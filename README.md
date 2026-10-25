# Aegis Harness

Aegis Harness is an out-of-process, zero-trust security sidecar for AI agents. It
mediates MCP `tools/call` requests, evaluates a declarative OPA/Rego policy,
injects brokered secrets only after authorization, scrubs sensitive data from
responses, and records every decision in an append-only, tamper-evident audit
ledger.

The design goal is **fail closed**: missing credentials, policy errors, audit
failures, and approval timeouts all result in denial rather than implicit trust.

## Architecture

```
                       ┌──────────────────────────────────────────────┐
  Agent process ──────▶│ Aegis sidecar (127.0.0.1:8787)                │
  (no host secrets)    │                                              │
                       │  1. Verify agent JWT (HS256, iss/aud/exp)    │
                       │  2. Per-session canary exfiltration tripwire │
                       │  3. OPA/Rego policy decision                 │
                       │  4. HITL suspension + authenticated approval │
                       │  5. Brokered secret injection                │
                       │  6. Output PII/token scrubbing + canary      │
                       │  7. Hash-chained, HMAC-authenticated audit   │
                       └───────────────┬──────────────────────────────┘
                                       │
                          ┌──────────────────────────────┐
                          │ Demo adapters (--demo)        │
                          │ or upstream MCP (--upstream)  │
                          └──────────────────────────────┘
```

The wrapped agent receives only `PATH`, `HOME`, a few non-sensitive locale
variables, `AEGIS_MCP_URL`, `AEGIS_GATEWAY_URL`, and a process-scoped root
`AEGIS_AGENT_TOKEN` (24-hour expiry by default). Host credentials are not
inherited. Child agents receive down-scoped delegation tokens minted by the
gateway (15-minute expiry).

## Quick start

```bash
# 1. Fetch dependencies and run the test suite
go mod tidy
go test ./...

# 2. Build a static binary
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o aegis-harness .

# 3. Run the end-to-end verification suite (--demo enables synthetic adapters)
./aegis-harness run --demo --policy policy.rego --hitl-ttl 2s -- python3 test_agent.py

# 4. Verify the audit ledger (read-only; never migrates or writes)
./aegis-harness verify-audit \
  --audit-db aegis_audit.db \
  --audit-key-file aegis_audit.db.key
```

The test suite covers anonymous-request rejection, bounded read-only SQL,
secret brokering, PII scrubbing, sandbox environment isolation, capability
down-scoping, HITL timeout failure, per-session canary detection, and
`alg=none` JWT rejection.

### Approving a suspended action

When a call is suspended, the gateway logs a request ID. Approve or deny it with
the admin token created at startup (default `aegis_audit.db.admin`, mode `0600`):

```bash
./aegis-harness approve --id hitl-<id> --approver alice
./aegis-harness approve --id hitl-<id> --approver alice --deny
```

The approval endpoint requires `X-Aegis-Admin-Token` (or a bearer admin token).
An agent JWT cannot approve its own action.

### Forwarding to a real MCP server

The synthetic adapters exist only for the verification suite. Point the sidecar
at a real MCP JSON-RPC endpoint instead:

```bash
export AEGIS_UPSTREAM_TOKEN="$(cat /run/secrets/upstream-token)"
./aegis-harness run \
  --policy policy.rego \
  --upstream https://mcp.internal.example/rpc \
  --root-scopes query_db,http_request
```

The gateway forwards only calls that pass policy and (when required) HITL. It
resolves `{{SECRET:NAME}}` placeholders, rejects redirects, caps response bodies
at 4 MiB, and scrubs upstream output before returning it to the agent. `--demo`
and `--upstream` are mutually exclusive; omitting both refuses to start.

## Configuration

| Flag | Default | Purpose |
| --- | --- | --- |
| `--policy` | `policy.rego` | Rego policy file |
| `--audit-db` | `aegis_audit.db` | SQLite WAL audit ledger |
| `--listen` | `127.0.0.1:8787` | Sidecar bind address |
| `--demo` | `false` | Enable synthetic demo adapters (verification only) |
| `--upstream` | _(none)_ | Forward authorized `tools/call` requests to an MCP JSON-RPC URL |
| `--upstream-token` | `$AEGIS_UPSTREAM_TOKEN` | Bearer token for the upstream MCP server |
| `--shadow` | `false` | Bypass HITL suspensions for profiling, then synthesize a draft policy; hard denies still apply |
| `--shadow-out` | `policy.synthesized.rego` | Synthesized policy path (written `0600`) |
| `--hitl-ttl` | `5m` | Fail-closed approval timeout |
| `--root-scopes` | `query_db,execute_code,http_request` | Scopes granted to the root agent |
| `--require-isolation` | `false` | Refuse `execute_code` unless docker/runsc/bwrap is available |
| `--audit-key-file` | `<audit-db>.key` | HMAC key for the audit ledger |
| `--admin-token-file` | `<audit-db>.admin` | HITL approval token |
| `--agent-token-file` | `<audit-db>.agent` | Root agent token file |
| `--ebpf` | `false` | Reserved; fails closed (see limitations) |

Environment variables:

| Variable | Purpose |
| --- | --- |
| `AEGIS_SECRET_GITHUB_TOKEN` | Real secret injected for `{{SECRET:GITHUB_TOKEN}}` |
| `AEGIS_SECRET_DB_PASSWORD` | Real secret injected for `{{SECRET:DB_PASSWORD}}` |
| `REAL_GITHUB_TOKEN`, `REAL_DB_PASSWORD` | Legacy aliases for the above |
| `AEGIS_AUDIT_HMAC_KEY` | Overrides the audit key file (use a KMS/secret manager in production) |
| `AEGIS_UPSTREAM_TOKEN` | Bearer token for the upstream MCP server |
| `AEGIS_ADMIN_TOKEN` | Overrides the HITL admin token file |

Send `SIGHUP` to reload the policy without dropping the sidecar. The previous
policy remains active if compilation fails.

## Security properties

- **Authentication is mandatory.** There is no anonymous default scope set.
  Tokens are HS256 JWTs with a process-local random key, issuer/audience
  validation, expiry, `nbf`/`iat`, and a unique `jti`.
- **Capability delegation is intersection-only.** A child cannot request a scope
  its parent lacks. Delegation depth is capped at three.
- **The policy is conservative.** Unknown tools are denied. Read-only SQL must
  be a single `SELECT`/`WITH` statement with a bounded `LIMIT` (maximum 1000).
  Mutating SQL and production deploys are suspended for human approval.
  Cloud metadata endpoints are denied for both code and HTTP tools.
- **Audit is tamper-evident.** Records are SHA-256 hash-chained; each row and the
  authenticated ledger head are HMAC-SHA256 protected. Deleting the tail is
  detected because the head count/hash no longer matches.
- **Audit failure is fail-closed.** A tool is not executed if the intent record
  cannot be written.
- **Canaries are per session.** Every response is tainted with a random
  per-session token. Any request containing a canary (including another
  session's canary) terminates the relevant session(s) immediately.
- **PII and credentials are scrubbed.** Emails, SSNs, private IPs, bearer tokens,
  GitHub/Slack/AWS/OpenAI-style keys, JWTs, and PEM private keys are redacted
  before output and before arguments reach the audit ledger.
- **HTTP ingress is bounded.** Request bodies are limited to 1 MiB, header size
  is limited, and timeouts are set on the server.

## Known limitations

These are deliberate boundaries, not silent guarantees:

1. **Demo adapters are not real tools.** `--demo` makes `query_db`,
   `http_request`, and `deploy_service` return synthetic results and must never
   be used in production. Use `--upstream` for real traffic; the forwarding path
   is transport-generic, so per-tool output validation still belongs in the
   upstream server.
2. **No eBPF enforcement yet.** Passing `--ebpf` fails closed instead of
   pretending a kernel filter was attached.
3. **Sandbox isolation depends on the host.** With docker/runsc or bubblewrap,
   code runs with network disabled, dropped capabilities, read-only filesystem,
   resource limits, and no host environment. Without them, the fallback is a
   process-level run with a clean environment and temporary working directory —
   it is *not* a security boundary. Use `--require-isolation` in production.
4. **The default audit key sits next to the database.** This is convenient for
   local development but a host-level attacker who can read both can forge
   records. Use `AEGIS_AUDIT_HMAC_KEY` backed by a KMS/HSM and export the ledger
   head to an external witness in production.
5. **Tokens are process-local.** Restarting the sidecar invalidates existing
   agent/delegation tokens. Multi-replica deployments need a shared key and
   revocation strategy.
6. **Policy is argument-approximate.** SQL keyword detection is conservative and
   can false-positive on keywords inside string literals. It is a guardrail, not
   a SQL parser. Use a real read-only database role as defense in depth.

## Next steps

Priority order for turning this prototype into a deployable control plane:

1. **Productionize upstream forwarding.** Add per-tool egress allowlists, mTLS,
   retry/idempotency controls, and upstream response schema validation. Keep the
   demo adapters permanently behind `--demo`.
2. **Production sandboxing.** Require gVisor/Firecracker or a hardened
   container runtime; add seccomp, user-namespace, and per-call network policy.
   Remove the unisolated fallback from production builds.
3. **Key and identity management.** Move JWT signing and audit HMAC keys to a
   KMS/HSM, add key rotation and revocation, and use mTLS or SPIFFE identities
   between agents and the sidecar.
4. **Audit anchoring.** Periodically publish a signed Merkle checkpoint or write
   the head hash to immutable storage (S3 Object Lock, transparency log) so
   truncation by a host-level attacker is detectable externally.
5. **Policy quality.** Add Rego unit tests for every rule, signed OPA bundles,
   data-driven allowlists, and argument-level constraints for high-risk tools.
   Consider a real SQL parser for read-only enforcement.
6. **HITL hardening.** Bind approvals to a hash of the exact arguments, add
   four-eyes approval, expiry/rotation for the admin token, and out-of-band
   approval through an IdP/Slack workflow.
7. **Operational controls.** Add Prometheus metrics, OpenTelemetry traces,
   structured JSON logs with request IDs, per-session concurrency/rate limits,
   and bounded session/canary storage to prevent memory exhaustion.
8. **Supply chain.** Add `govulncheck`, SBOM generation, reproducible builds,
   container image signing, and dependency update automation.
9. **Broader testing.** Add fuzzing for the MCP parser and policy inputs, race
   tests in CI, and end-to-end tests against real MCP clients/servers.
10. **Deployment packaging.** Provide a systemd unit, container image, and
    Kubernetes sidecar manifests with read-only root filesystems and network
    policies.

## Development

```bash
make test        # go test ./...
make vet         # go vet ./...
make e2e         # build + run the Python verification suite + verify audit chain
make build       # static binary
gofmt -w .       # format
```

Repository layout:

```
main.go                       CLI: run / approve / verify-audit
policy.rego                   Fail-closed Rego policy
test_agent.py                 End-to-end security verification
internal/auth/                JWT minting, validation, delegation
internal/proxy/               MCP gateway, HITL, canaries, scrubbing
internal/audit/               Hash-chained + HMAC audit ledger
internal/sandbox/             Python isolation adapters
internal/redact/              Credential/PII redaction
internal/ebpf/                Reserved kernel-enforcement hook
```
