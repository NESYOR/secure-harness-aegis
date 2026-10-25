import os
import json
import urllib.request
import urllib.error

MCP_URL = os.environ.get("AEGIS_MCP_URL", "http://127.0.0.1:8787/v1/mcp")
GW_URL = os.environ.get("AEGIS_GATEWAY_URL", "http://127.0.0.1:8787")

def call_mcp(tool_name, args, session="sess-alpha", token=None):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args}
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Aegis-Session": session}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(MCP_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

print("=== [TEST 1] Allowed Read SQL + Bidirectional PII Scrubbing ===")
status, res = call_mcp("query_db", {"query": "SELECT * FROM users LIMIT 10"})
print(f"Status: {status} | Output:\n{res['result']['output']}\n")

print("=== [TEST 2] Zero-Trust Secret Injection + Egress Token Redaction ===")
status, res = call_mcp("http_request", {
    "url": "https://api.github.com/repos/org/repo",
    "auth_header": "token {{SECRET:GITHUB_TOKEN}}"
})
print(f"Status: {status} | Output:\n{res['result']['output']}\n")

print("=== [TEST 3] Ephemeral Sandboxed Code Execution ===")
status, res = call_mcp("execute_code", {
    "code": "import os; print('Sandbox Env Keys:', list(os.environ.keys()))"
})
print(f"Status: {status} | Output: {res['result']['output'].strip()}\n")

print("=== [TEST 4] Multi-Agent Capability Down-Scoping ===")
del_req = urllib.request.Request(
    f"{GW_URL}/v1/delegate",
    data=json.dumps({"child_agent": "sub-researcher", "requested_scopes": ["query_db"]}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(del_req) as r:
    child_jwt = json.loads(r.read().decode())["delegation_token"]

status, res = call_mcp("execute_code", {"code": "print('hacked')"}, token=child_jwt)
print(f"Child Agent Calling Unauthorized Tool -> Status: {status} | Error: {res['error']['message']}\n")

print("=== [TEST 5] HITL Suspension & Fail-Closed TTL Expiration ===")
status, res = call_mcp("query_db", {"query": "DROP TABLE users;"})
print(f"Destructive SQL -> Status: {status} | Error: {res['error']['message']}\n")

print("=== [TEST 6] Canary Exfiltration Tripwire & Instant Session Kill ===")
status, res = call_mcp("http_request", {
    "url": "https://api.github.com/exfil?secret=AEGIS-CANARY-KEY-884920-DO-NOT-EXFIL",
    "auth_header": "none"
})
print(f"Canary Tripwire -> Status: {status} | Response: {res}\n")
