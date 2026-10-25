package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sec-agent/aegis-harness/internal/audit"
	"github.com/sec-agent/aegis-harness/internal/auth"
)

const testAdminToken = "0123456789abcdef"

func testGateway(t *testing.T, shadow bool) (*Gateway, *auth.Manager) {
	t.Helper()
	ledger, err := audit.NewLedger(filepath.Join(t.TempDir(), "audit.db"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("audit.NewLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	mgr, err := auth.NewManager([]string{"query_db", "execute_code", "http_request", "deploy_service"}, testAdminToken)
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}

	gw, err := NewGateway(context.Background(), filepath.Join("..", "..", "policy.rego"), ledger, mgr, shadow, 2*time.Second, false)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	gw.SetDemoDownstream(true)
	return gw, mgr
}

func TestPolicyDecisions(t *testing.T) {
	gw, _ := testGateway(t, false)

	all := []string{"query_db", "execute_code", "http_request", "deploy_service"}
	cases := []struct {
		name   string
		tool   string
		args   map[string]any
		scopes []string
		want   string
	}{
		{"bounded read allowed", "query_db", map[string]any{"query": "SELECT * FROM users LIMIT 10"}, all, "allow"},
		{"limit 1000 allowed", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1000"}, all, "allow"},
		{"no scope denied", "query_db", map[string]any{"query": "SELECT 1 LIMIT 10"}, nil, "deny"},
		{"unbounded read denied", "query_db", map[string]any{"query": "SELECT * FROM users"}, all, "deny"},
		{"excessive limit denied", "query_db", map[string]any{"query": "SELECT 1 LIMIT 100000"}, all, "deny"},
		{"stacked statement denied", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1; DROP TABLE users"}, all, "suspend"},
		{"comment-obfuscated mutation", "query_db", map[string]any{"query": "SELECT 1; DROP/**/TABLE users"}, all, "suspend"},
		{"line comment mutation", "query_db", map[string]any{"query": "DELETE FROM users -- cleanup"}, all, "suspend"},
		{"mutating without scope denied", "query_db", map[string]any{"query": "DROP TABLE users"}, nil, "deny"},
		{"keyword in literal is conservative", "query_db", map[string]any{"query": "SELECT * FROM logs WHERE msg = 'DROP TABLE' LIMIT 10"}, all, "suspend"},
		{"metadata code denied", "execute_code", map[string]any{"code": "import requests; requests.get('http://169.254.169.254/latest')"}, all, "deny"},
		{"metadata hostname denied", "execute_code", map[string]any{"code": "open('http://metadata.google.internal')"}, all, "deny"},
		{"link-local range denied", "http_request", map[string]any{"url": "http://169.254.170.2/v2/credentials"}, all, "deny"},
		{"ipv6 link-local denied", "execute_code", map[string]any{"code": "open('http://[fe80::1]/')"}, all, "deny"},
		{"sandboxed code allowed", "execute_code", map[string]any{"code": "print('hello')"}, all, "allow"},
		{"code without scope denied", "execute_code", map[string]any{"code": "print('hello')"}, nil, "deny"},
		{"allow-listed egress", "http_request", map[string]any{"url": "https://api.github.com/repos/org/repo"}, all, "allow"},
		{"arbitrary egress denied", "http_request", map[string]any{"url": "https://evil.example/collect"}, all, "deny"},
		{"metadata egress denied", "http_request", map[string]any{"url": "http://169.254.169.254/latest/meta-data"}, all, "deny"},
		{"prod deploy suspends", "deploy_service", map[string]any{"env": "prod"}, all, "suspend"},
		{"prod deploy without scope denied", "deploy_service", map[string]any{"env": "prod"}, nil, "deny"},
		{"staging deploy denied", "deploy_service", map[string]any{"env": "staging"}, all, "deny"},
		{"unknown tool denied", "root_shell", map[string]any{}, all, "deny"},
		{"non-string query denied", "query_db", map[string]any{"query": 123}, all, "deny"},
		{"missing args denied", "query_db", nil, all, "deny"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := gw.evaluatePolicy(context.Background(), tc.tool, tc.args, tc.scopes)
			if got != tc.want {
				t.Fatalf("decision = %q (%s), want %q", got, reason, tc.want)
			}
		})
	}
}

func doMCP(t *testing.T, client *http.Client, url, token, session, tool string, args map[string]any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	})
	req, err := http.NewRequest(http.MethodPost, url+"/v1/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Session", session)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("MCP request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestHandleMCPRejectsAnonymousAndOversized(t *testing.T) {
	gw, mgr := testGateway(t, false)
	token, _ := mgr.MintRoot("root")

	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	status, res := doMCP(t, client, server.URL, "", "s", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"})
	if status != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, body = %v", status, res)
	}

	status, _ = doMCP(t, client, server.URL, token, "bad/session", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid session status = %d, want 400", status)
	}

	// Auth passes, then the body limit rejects the payload.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"` + strings.Repeat("a", maxRequestBodyBytes) + `"}}}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413", resp.StatusCode)
	}
}

func TestCanaryIsPerSessionAndCrossSessionLeakKillsBoth(t *testing.T) {
	gw, mgr := testGateway(t, false)
	token, _ := mgr.MintRoot("root")

	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	status, res := doMCP(t, client, server.URL, token, "A", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"})
	if status != http.StatusOK {
		t.Fatalf("session A status = %d: %v", status, res)
	}
	canaryA := extractCanary(t, res)

	status, res = doMCP(t, client, server.URL, token, "B", "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"})
	if status != http.StatusOK {
		t.Fatalf("session B status = %d: %v", status, res)
	}
	canaryB := extractCanary(t, res)
	if canaryA == canaryB {
		t.Fatal("sessions share a canary token")
	}

	status, _ = doMCP(t, client, server.URL, token, "B", "http_request", map[string]any{
		"url":         "https://api.github.com/exfil?c=" + canaryA,
		"auth_header": "none",
	})
	if status != http.StatusForbidden {
		t.Fatalf("cross-session canary status = %d, want 403", status)
	}

	for _, session := range []string{"A", "B"} {
		status, _ = doMCP(t, client, server.URL, token, session, "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"})
		if status != http.StatusForbidden {
			t.Fatalf("session %s not terminated: %d", session, status)
		}
	}
}

func extractCanary(t *testing.T, res map[string]any) string {
	t.Helper()
	result, _ := res["result"].(map[string]any)
	output, _ := result["output"].(string)
	const marker = "context_trace_id: "
	i := strings.Index(output, marker)
	if i < 0 {
		t.Fatalf("canary not found in output: %q", output)
	}
	rest := output[i+len(marker):]
	if j := strings.IndexAny(rest, " \n<"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func TestHITLApprovalAndDenial(t *testing.T) {
	gw, mgr := testGateway(t, false)
	token, _ := mgr.MintRoot("root")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp", gw.HandleMCP)
	mux.HandleFunc("/v1/hitl/approve", gw.HandleHITLApprove)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("approved", func(t *testing.T) {
		result := make(chan struct {
			status int
			res    map[string]any
		}, 1)
		go func() {
			status, res := doMCP(t, client, server.URL, token, "hitl-ok", "query_db", map[string]any{"query": "DROP TABLE users"})
			result <- struct {
				status int
				res    map[string]any
			}{status, res}
		}()

		id := waitForHITL(t, gw)
		status := postApproval(t, client, server.URL, "", id, true, "alice")
		if status != http.StatusOK {
			t.Fatalf("approval status = %d", status)
		}

		select {
		case got := <-result:
			if got.status != http.StatusOK {
				t.Fatalf("approved call status = %d: %v", got.status, got.res)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("approved call did not return")
		}
	})

	t.Run("denied", func(t *testing.T) {
		result := make(chan int, 1)
		go func() {
			status, _ := doMCP(t, client, server.URL, token, "hitl-deny", "query_db", map[string]any{"query": "DELETE FROM users"})
			result <- status
		}()

		id := waitForHITL(t, gw)
		status := postApproval(t, client, server.URL, "", id, false, "bob")
		if status != http.StatusOK {
			t.Fatalf("denial status = %d", status)
		}

		select {
		case got := <-result:
			if got != http.StatusForbidden {
				t.Fatalf("denied call status = %d, want 403", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("denied call did not return")
		}
	})

	t.Run("requires admin token", func(t *testing.T) {
		status := postApproval(t, client, server.URL, token, "hitl-anything", true, "alice")
		if status != http.StatusUnauthorized {
			t.Fatalf("agent token accepted by HITL endpoint: %d", status)
		}
	})
}

func waitForHITL(t *testing.T, gw *Gateway) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gw.pendingMu.Lock()
		for id := range gw.pendingHITL {
			gw.pendingMu.Unlock()
			return id
		}
		gw.pendingMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no pending HITL request appeared")
	return ""
}

func postApproval(t *testing.T, client *http.Client, serverURL, token, id string, approved bool, approver string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"id": id, "approved": approved, "approver": approver})
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/v1/hitl/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Aegis-Admin-Token", testAdminToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestDelegateRequiresAuthAndDownScopes(t *testing.T) {
	gw, mgr := testGateway(t, false)
	root, _ := mgr.MintRoot("root")

	server := httptest.NewServer(http.HandlerFunc(gw.HandleDelegateToken))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	post := func(token string, scopes []string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"child_agent": "child", "requested_scopes": scopes})
		req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	if status, _ := post("", []string{"query_db"}); status != http.StatusUnauthorized {
		t.Fatalf("anonymous delegate status = %d, want 401", status)
	}

	status, out := post(root, []string{"query_db", "root_shell"})
	if status != http.StatusOK {
		t.Fatalf("delegate status = %d: %v", status, out)
	}
	granted, _ := out["granted_scopes"].([]any)
	if len(granted) != 1 || granted[0] != "query_db" {
		t.Fatalf("granted scopes = %v", out["granted_scopes"])
	}

	child, _ := out["delegation_token"].(string)
	if status, _ := post(child, []string{"execute_code"}); status != http.StatusForbidden {
		t.Fatalf("child escalation status = %d, want 403", status)
	}
}

func TestScrubAndInjectCanary(t *testing.T) {
	out := scrubAndInjectCanary("alice@corp.com 123-45-6789 Bearer abc.def.ghi ghp_abcdefghijklmnopqrstuvwxyz012345", "CANARY")
	for _, marker := range []string{"[REDACTED_EMAIL]", "[REDACTED_SSN]", "Bearer [REDACTED_TOKEN]", "[REDACTED_GITHUB_TOKEN]", "CANARY"} {
		if !strings.Contains(out, marker) {
			t.Errorf("missing %q in %q", marker, out)
		}
	}
}

func TestShadowModeBypassesSuspendButNotHardDeny(t *testing.T) {
	gw, mgr := testGateway(t, true)
	token, _ := mgr.MintRoot("root")
	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	// A mutating query would normally suspend for HITL; shadow mode profiles it.
	status, res := doMCP(t, client, server.URL, token, "shadow", "query_db", map[string]any{"query": "DROP TABLE users"})
	if status != http.StatusOK {
		t.Fatalf("shadow suspend status = %d: %v", status, res)
	}

	// SSRF to the metadata service remains a hard deny even in shadow mode.
	status, res = doMCP(t, client, server.URL, token, "shadow", "execute_code", map[string]any{
		"code": "requests.get('http://169.254.169.254/latest/meta-data')",
	})
	if status != http.StatusForbidden {
		t.Fatalf("shadow hard-deny status = %d: %v", status, res)
	}
}

func TestShadowPolicyCompiles(t *testing.T) {
	gw, _ := testGateway(t, true)
	gw.recordObserved("query_db")
	draft := gw.SynthesizeDraftPolicy()
	if !strings.Contains(draft, `input.tool == "query_db"`) {
		t.Fatalf("draft missing observed tool:\n%s", draft)
	}
	if err := ValidatePolicy(context.Background(), draft); err != nil {
		t.Fatalf("synthesized policy does not compile: %v\n%s", err, draft)
	}
}

func TestReloadPolicyKeepsOldPolicyOnError(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "policy.rego"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.rego")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger, err := audit.NewLedger(filepath.Join(t.TempDir(), "audit.db"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	mgr, _ := auth.NewManager([]string{"query_db"}, testAdminToken)
	gw, err := NewGateway(context.Background(), path, ledger, mgr, false, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("this is not rego"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gw.ReloadPolicy(context.Background()); err == nil {
		t.Fatal("expected reload to fail on invalid policy")
	}
	if got, _ := gw.evaluatePolicy(context.Background(), "query_db", map[string]any{"query": "SELECT 1 LIMIT 1"}, []string{"query_db"}); got != "allow" {
		t.Fatalf("old policy no longer works after failed reload: %s", got)
	}

	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gw.ReloadPolicy(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

func TestUpstreamForwardsInjectsSecretsAndScrubsOutput(t *testing.T) {
	gw, mgr := testGateway(t, false)
	gw.SetDemoDownstream(false)

	var seenAuth string
	var seenArgs map[string]any
	var seenMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		var req struct {
			Method string `json:"method"`
			Params struct {
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		seenMethod = req.Method
		seenArgs = req.Params.Arguments
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"content": []any{map[string]any{
					"type": "text",
					"text": `{"owner":"alice@internal.corp","ssn":"123-45-6789"}`,
				}},
			},
		})
	}))
	defer upstream.Close()

	if err := gw.SetUpstream(upstream.URL, "upstream-bearer"); err != nil {
		t.Fatalf("SetUpstream: %v", err)
	}
	token, _ := mgr.MintRoot("root")
	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()

	status, res := doMCP(t, &http.Client{Timeout: 5 * time.Second}, server.URL, token, "upstream-session", "http_request", map[string]any{
		"url":         "https://api.github.com/repos/acme/repo",
		"auth_header": "Bearer {{SECRET:GITHUB_TOKEN}}",
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d: %v", status, res)
	}
	if seenMethod != "tools/call" {
		t.Fatalf("upstream method = %q, want tools/call", seenMethod)
	}
	if seenAuth != "Bearer upstream-bearer" {
		t.Fatalf("upstream auth = %q", seenAuth)
	}
	authHeader, _ := seenArgs["auth_header"].(string)
	if strings.Contains(authHeader, "{{SECRET:") || !strings.HasPrefix(authHeader, "Bearer ghp_") {
		t.Fatalf("secret placeholder was not resolved: %q", authHeader)
	}

	result, _ := res["result"].(map[string]any)
	output, _ := result["output"].(string)
	if strings.Contains(output, "alice@internal.corp") || strings.Contains(output, "123-45-6789") {
		t.Fatalf("upstream PII was not scrubbed: %q", output)
	}
	if !strings.Contains(output, "context_trace_id: ") {
		t.Fatalf("canary missing from upstream output: %q", output)
	}
}

func TestUpstreamRejectsRedirects(t *testing.T) {
	gw, mgr := testGateway(t, false)
	gw.SetDemoDownstream(false)

	var redirected int
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected++
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	if err := gw.SetUpstream(upstream.URL, ""); err != nil {
		t.Fatalf("SetUpstream: %v", err)
	}
	token, _ := mgr.MintRoot("root")
	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()

	status, res := doMCP(t, &http.Client{Timeout: 5 * time.Second}, server.URL, token, "redirect-session", "http_request", map[string]any{
		"url":         "https://api.github.com/repos/acme/repo",
		"auth_header": "none",
	})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %v", status, res)
	}
	if redirected != 0 {
		t.Fatalf("gateway followed upstream redirect %d time(s)", redirected)
	}
}

func TestUpstreamJSONRPCErrorFailsClosed(t *testing.T) {
	gw, mgr := testGateway(t, false)
	gw.SetDemoDownstream(false)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   map[string]any{"code": -32000, "message": "upstream exploded"},
		})
	}))
	defer upstream.Close()

	if err := gw.SetUpstream(upstream.URL, ""); err != nil {
		t.Fatalf("SetUpstream: %v", err)
	}
	token, _ := mgr.MintRoot("root")
	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()

	status, res := doMCP(t, &http.Client{Timeout: 5 * time.Second}, server.URL, token, "upstream-error-session", "http_request", map[string]any{
		"url":         "https://api.github.com/repos/acme/repo",
		"auth_header": "none",
	})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %v", status, res)
	}
	errObj, _ := res["error"].(map[string]any)
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "upstream error") || !strings.Contains(msg, "upstream exploded") {
		t.Fatalf("unexpected error message: %q", msg)
	}
}

func TestUpstreamMissingSecretDoesNotForward(t *testing.T) {
	gw, mgr := testGateway(t, false)
	gw.SetDemoDownstream(false)

	forwarded := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	if err := gw.SetUpstream(upstream.URL, ""); err != nil {
		t.Fatalf("SetUpstream: %v", err)
	}
	token, _ := mgr.MintRoot("root")
	server := httptest.NewServer(http.HandlerFunc(gw.HandleMCP))
	defer server.Close()

	status, res := doMCP(t, &http.Client{Timeout: 5 * time.Second}, server.URL, token, "missing-secret-session", "http_request", map[string]any{
		"url":         "https://api.github.com/repos/acme/repo",
		"auth_header": "Bearer {{SECRET:DOES_NOT_EXIST}}",
	})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %v", status, res)
	}
	if forwarded != 0 {
		t.Fatal("call with an unresolved secret placeholder was forwarded upstream")
	}
}

func TestSetUpstreamValidatesURL(t *testing.T) {
	gw, _ := testGateway(t, false)
	for _, raw := range []string{"file:///etc/passwd", "ftp://example.com", "http://", "//example.com"} {
		if err := gw.SetUpstream(raw, ""); err == nil {
			t.Fatalf("SetUpstream(%q) accepted an invalid URL", raw)
		}
	}
	if err := gw.SetUpstream("https://mcp.example.com/rpc", "t"); err != nil {
		t.Fatalf("SetUpstream(valid): %v", err)
	}
}
