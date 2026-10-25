#!/usr/bin/env python3
"""End-to-end verification suite for the Aegis Harness.

Run it through the harness so AEGIS_AGENT_TOKEN and the gateway URL are
injected:

    ./aegis-harness run --policy policy.rego --hitl-ttl 2s -- \
        python3 test_agent.py

The script exits non-zero if any security assertion fails.
"""

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

MCP_URL = os.environ.get("AEGIS_MCP_URL", "http://127.0.0.1:8787/v1/mcp")
GW_URL = os.environ.get("AEGIS_GATEWAY_URL", "http://127.0.0.1:8787")
ROOT_TOKEN = os.environ.get("AEGIS_AGENT_TOKEN", "")

FAILURES = []
CANARY = None


def check(name, condition, detail=""):
    if condition:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name} {detail}")


def call_mcp(tool_name, args, session="sess-alpha", token=ROOT_TOKEN):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Aegis-Session": session}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(MCP_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw}


def delegate(child, scopes, token=ROOT_TOKEN):
    req = urllib.request.Request(
        f"{GW_URL}/v1/delegate",
        data=json.dumps({"child_agent": child, "requested_scopes": scopes}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()}


def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


print("=== [TEST 0] Missing Credentials Fail Closed ===")
status, res = call_mcp("query_db", {"query": "SELECT * FROM users LIMIT 10"}, token=None)
check("anonymous request rejected", status == 401, f"status={status} body={res}")
check("no scopes leaked on anonymous request", "error" in res, str(res))

print("\n=== [TEST 1] Allowed Read SQL + PII Scrubbing + Per-Session Canary ===")
status, res = call_mcp("query_db", {"query": "SELECT * FROM users LIMIT 10"})
output = res.get("result", {}).get("output", "")
print(f"Status: {status}")
print(output)
check("allowed read returns 200", status == 200)
check("email redacted", "[REDACTED_EMAIL]" in output)
check("SSN redacted", "[REDACTED_SSN]" in output)
check("internal IP redacted", "[REDACTED_INTERNAL_IP]" in output)
match = re.search(r"context_trace_id:\s*([A-Za-z0-9\-]+)", output)
CANARY = match.group(1) if match else None
check("per-session canary injected", CANARY is not None)

print("\n=== [TEST 2] Zero-Trust Secret Injection + Egress Token Redaction ===")
status, res = call_mcp("http_request", {
    "url": "https://api.github.com/repos/org/repo",
    "auth_header": "token {{SECRET:GITHUB_TOKEN}}",
})
output = res.get("result", {}).get("output", "")
print(f"Status: {status}")
print(output)
check("allow-listed egress returns 200", status == 200)
check("secret placeholder was brokered", '"secret_injected":true' in output)
check("bearer token redacted from output", "Bearer [REDACTED_TOKEN]" in output)

print("\n=== [TEST 3] Sandboxed Code Execution Has No Host Secrets ===")
status, res = call_mcp("execute_code", {
    "code": "import os; print('Sandbox Env Keys:', list(os.environ.keys()))",
})
output = res.get("result", {}).get("output", "")
print(f"Status: {status}")
print(output)
check("sandboxed execution returns 200", status == 200)
check("agent token not inherited by sandbox", "AEGIS_AGENT_TOKEN" not in output)
check("host credentials not inherited by sandbox", "REAL_GITHUB_TOKEN" not in output)

print("\n=== [TEST 4] Multi-Agent Capability Down-Scoping ===")
status, del_res = delegate("sub-researcher", ["query_db"])
child_jwt = del_res.get("delegation_token", "")
check("parent can delegate query_db", status == 200 and bool(child_jwt), str(del_res))
check("only query_db granted", del_res.get("granted_scopes") == ["query_db"], str(del_res.get("granted_scopes")))

status, res = call_mcp("execute_code", {"code": "print('hacked')"}, token=child_jwt)
print(f"Child -> execute_code: Status: {status} | Error: {res.get('error', {}).get('message', res)}")
check("child cannot use execute_code", status == 403)

status, res = call_mcp("query_db", {"query": "SELECT 1 LIMIT 1"}, token=child_jwt)
check("child can use delegated query_db", status == 200, f"status={status} body={res}")

status, res = delegate("sub-sub-researcher", ["http_request"], token=child_jwt)
check("child cannot escalate to http_request", status == 403, f"status={status} body={res}")

print("\n=== [TEST 5] HITL Suspension & Fail-Closed TTL Expiration ===")
print("  (requires --hitl-ttl 2s; otherwise this test blocks until approval TTL)")
status, res = call_mcp("query_db", {"query": "DROP TABLE users;"})
msg = res.get("error", {}).get("message", "")
print(f"Destructive SQL -> Status: {status} | Error: {msg}")
check("destructive SQL denied on timeout", status == 403 and "timed out" in msg.lower(), str(res))

print("\n=== [TEST 6] Canary Exfiltration Tripwire & Instant Session Kill ===")
check("canary available from earlier output", CANARY is not None)
status, res = call_mcp("http_request", {
    "url": f"https://api.github.com/exfil?secret={CANARY}",
    "auth_header": "none",
})
print(f"Canary Tripwire -> Status: {status} | Response: {res}")
check("canary exfiltration blocked", status == 403 and "canary" in json.dumps(res).lower(), str(res))

status, res = call_mcp("query_db", {"query": "SELECT 1 LIMIT 1"})
print(f"Post-tripwire session -> Status: {status} | Response: {res}")
check("session remains terminated", status == 403 and "terminated" in json.dumps(res).lower(), str(res))

print("\n=== [TEST 7] alg=none JWT Is Rejected ===")
now = int(time.time())
forged = f"{b64url({'alg': 'none', 'typ': 'JWT'})}.{b64url({'sub': 'attacker', 'scopes': ['query_db'], 'iss': 'aegis-harness', 'aud': 'aegis-gateway', 'exp': now + 300})}."
status, res = call_mcp("query_db", {"query": "SELECT 1 LIMIT 1"}, token=forged)
print(f"Forged token -> Status: {status} | Response: {res}")
check("unsigned JWT rejected", status == 401, str(res))

print()
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    sys.exit(1)
print("All Aegis verification checks passed.")
