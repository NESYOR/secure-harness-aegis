# Aegis Harness: Zero-Trust Security Sidecar for AI Agents

Aegis Harness is an out-of-process security proxy and CLI runner built in Go that mediates AI agent tool invocations via MCP (Model Context Protocol) and HTTP.

## Quick Start

```bash
# 1. Fetch dependencies and compile static binary
go mod tidy
CGO_ENABLED=0 go build -ldflags="-s -w" -o aegis-harness .

# 2. Run the end-to-end verification suite
./aegis-harness run --policy policy.rego --hitl-ttl 2s -- python3 test_agent.py

# 3. Verify the cryptographic hash-chained SQLite WAL audit ledger
./aegis-harness verify-audit --audit-db aegis_audit.db
```
