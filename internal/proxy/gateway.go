package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sec-agent/aegis-harness/internal/audit"
	"github.com/sec-agent/aegis-harness/internal/sandbox"
)

const CanarySecret = "AEGIS-CANARY-KEY-884920-DO-NOT-EXFIL"

type Gateway struct {
	opaQuery     rego.PreparedEvalQuery
	ledger       *audit.Ledger
	sandbox      *sandbox.SandboxRunner
	shadowMode   bool
	hitlTTL      time.Duration
	jwtSecret    []byte
	secretVault  map[string]string
	pendingMu    sync.Mutex
	pendingHITL  map[string]chan HITLVerdict
	observedMu   sync.Mutex
	observedRuns map[string]bool
	sessionAbort sync.Map
}

type HITLVerdict struct {
	Approved bool
	Approver string
}

type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

var (
	emailRegex  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	ssnRegex    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	bearerRegex = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`)
	privIPRegex = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b`)
)

func NewGateway(ctx context.Context, policyPath string, ledger *audit.Ledger, shadow bool, hitlTTL time.Duration) (*Gateway, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading policy file: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.aegis.authz"),
		rego.Module(policyPath, string(policyBytes)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed compiling Rego policy: %w", err)
	}

	vault := map[string]string{
		"GITHUB_TOKEN": os.Getenv("REAL_GITHUB_TOKEN"),
		"DB_PASSWORD":  os.Getenv("REAL_DB_PASSWORD"),
	}
	if vault["GITHUB_TOKEN"] == "" {
		vault["GITHUB_TOKEN"] = "ghp_REAL_PRODUCTION_CREDENTIAL_89123"
	}

	return &Gateway{
		opaQuery:     query,
		ledger:       ledger,
		sandbox:      sandbox.NewRunner(10 * time.Second),
		shadowMode:   shadow,
		hitlTTL:      hitlTTL,
		jwtSecret:    []byte("aegis-ephemeral-hmac-signing-key-2026"),
		secretVault:  vault,
		pendingHITL:  make(map[string]chan HITLVerdict),
		observedRuns: make(map[string]bool),
	}, nil
}

// HandleMCP intercepts JSON-RPC 2.0 `tools/call` invocations
func (g *Gateway) HandleMCP(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Aegis-Session")
	if sessionID == "" {
		sessionID = "default-session"
	}

	// 1. Check if session was previously killed by a Canary tripwire
	if _, terminated := g.sessionAbort.Load(sessionID); terminated {
		http.Error(w, `{"error":"SESSION_TERMINATED_BY_CANARY_TRIPWIRE"}`, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed reading body"}`, http.StatusBadRequest)
		return
	}

	// 2. Exfiltration Tripwire Check: Does the outbound request contain our Canary Token?
	if strings.Contains(string(body), CanarySecret) {
		g.sessionAbort.Store(sessionID, true)
		_, _ = g.ledger.Append(sessionID, "CANARY_TRIPWIRE", string(body), "ABORT_EXFILTRATION", "system")
		log.Printf("[ALERT] CANARY TRIPWIRE TRIGGERED in session %s! Terminating session immediately.", sessionID)
		http.Error(w, `{"error":"CRITICAL: Exfiltration of canary token detected. Session terminated."}`, http.StatusForbidden)
		return
	}

	var mcpReq MCPRequest
	if err := json.Unmarshal(body, &mcpReq); err != nil || mcpReq.Method != "tools/call" {
		http.Error(w, `{"error":"invalid MCP tools/call request"}`, http.StatusBadRequest)
		return
	}

	var callParams ToolCallParams
	if err := json.Unmarshal(mcpReq.Params, &callParams); err != nil {
		http.Error(w, `{"error":"invalid tool params"}`, http.StatusBadRequest)
		return
	}

	// 3. Verify Delegated Multi-Agent Scopes
	scopes := g.extractScopes(r.Header.Get("Authorization"))
	argsBytes, _ := json.Marshal(callParams.Arguments)

	// Record observed tool for Shadow Mode profiling
	g.observedMu.Lock()
	g.observedRuns[callParams.Name] = true
	g.observedMu.Unlock()

	// 4. Synchronous Deterministic Policy Evaluation (OPA/Rego)
	decision, reason := g.evaluatePolicy(r.Context(), callParams.Name, callParams.Arguments, scopes)

	if g.shadowMode && decision != "allow" {
		log.Printf("[SHADOW-MODE] Would have enforced %s on tool %s (%s), permitting for profiling", decision, callParams.Name, reason)
		decision = "allow"
	}

	// 5. Handle HITL Stateful Suspension with Bounded TTL
	approver := "policy-engine"
	if decision == "suspend" {
		reqID := fmt.Sprintf("hitl-%d", time.Now().UnixNano())
		ch := make(chan HITLVerdict, 1)
		g.pendingMu.Lock()
		g.pendingHITL[reqID] = ch
		g.pendingMu.Unlock()

		log.Printf("[HITL SUSPENDED] Tool=%s Args=%s | Approve via: aegis-harness approve --id %s", callParams.Name, string(argsBytes), reqID)

		select {
		case verdict := <-ch:
			if !verdict.Approved {
				_, _ = g.ledger.Append(sessionID, callParams.Name, string(argsBytes), "DENIED_BY_HUMAN", verdict.Approver)
				writeJSONRPCError(w, mcpReq.ID, -32001, "Action rejected by human reviewer")
				return
			}
			decision = "allow"
			approver = verdict.Approver
		case <-time.After(g.hitlTTL):
			g.pendingMu.Lock()
			delete(g.pendingHITL, reqID)
			g.pendingMu.Unlock()
			_, _ = g.ledger.Append(sessionID, callParams.Name, string(argsBytes), "DENIED_HITL_TTL_EXPIRED", "system-ttl")
			writeJSONRPCError(w, mcpReq.ID, -32002, fmt.Sprintf("Human approval timed out after %v (fail-closed)", g.hitlTTL))
			return
		}
	}

	if decision != "allow" {
		_, _ = g.ledger.Append(sessionID, callParams.Name, string(argsBytes), "DENY", approver)
		writeJSONRPCError(w, mcpReq.ID, -32000, fmt.Sprintf("Policy Denied: %s", reason))
		return
	}

	// 6. Execute Approved Tool (with Zero-Trust Credential Brokering & Sandboxing)
	rawOutput, execErr := g.executeToolDownstream(r.Context(), callParams)
	if execErr != nil {
		_, _ = g.ledger.Append(sessionID, callParams.Name, string(argsBytes), "EXEC_ERROR", approver)
		writeJSONRPCError(w, mcpReq.ID, -32003, execErr.Error())
		return
	}

	// 7. Scrub Output PII/Secrets & Inject Active Canary Token
	cleanOutput := g.scrubAndInjectCanary(rawOutput)
	hash, _ := g.ledger.Append(sessionID, callParams.Name, string(argsBytes), "ALLOW", approver)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      mcpReq.ID,
		"result": map[string]any{
			"output":     cleanOutput,
			"audit_hash": hash,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) evaluatePolicy(ctx context.Context, tool string, args map[string]any, scopes []string) (string, string) {
	evalCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	input := map[string]any{
		"tool":             tool,
		"args":             args,
		"delegated_scopes": scopes,
	}

	rs, err := g.opaQuery.Eval(evalCtx, rego.EvalInput(input))
	if err != nil || len(rs) == 0 {
		// Fail-closed guarantee on any evaluation error or timeout
		return "deny", "fail-closed: policy evaluation error or timeout"
	}

	bindings, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return "deny", "fail-closed: malformed policy output"
	}

	dec, _ := bindings["decision"].(string)
	rea, _ := bindings["reason"].(string)
	if dec == "" {
		return "deny", "fail-closed: empty decision"
	}
	return dec, rea
}

func (g *Gateway) executeToolDownstream(ctx context.Context, call ToolCallParams) (string, error) {
	switch call.Name {
	case "execute_code":
		code, _ := call.Arguments["code"].(string)
		return g.sandbox.ExecutePython(ctx, code)

	case "query_db":
		q, _ := call.Arguments["query"].(string)
		return fmt.Sprintf(`[{"id":1,"user":"alice@internal.corp","ssn":"123-45-6789","internal_ip":"10.24.1.99","query_executed":%q}]`, q), nil

	case "http_request":
		url, _ := call.Arguments["url"].(string)
		authHeader, _ := call.Arguments["auth_header"].(string)
		// Zero-trust secret injection: replace placeholder with real secret downstream
		for k, secretVal := range g.secretVault {
			placeholder := fmt.Sprintf("{{SECRET:%s}}", k)
			authHeader = strings.ReplaceAll(authHeader, placeholder, secretVal)
		}
		return fmt.Sprintf(`{"status":200,"url":%q,"injected_secret_verified":%v,"leak_check":"Bearer eyJhbGciOiJIUzI1NiJ9.secret"}`,
			url, strings.Contains(authHeader, "ghp_REAL_PRODUCTION_CREDENTIAL")), nil

	default:
		return `{"status":"executed"}`, nil
	}
}

func (g *Gateway) scrubAndInjectCanary(payload string) string {
	scrubbed := emailRegex.ReplaceAllString(payload, "[REDACTED_EMAIL]")
	scrubbed = ssnRegex.ReplaceAllString(scrubbed, "[REDACTED_SSN]")
	scrubbed = bearerRegex.ReplaceAllString(scrubbed, "Bearer [REDACTED_TOKEN]")
	scrubbed = privIPRegex.ReplaceAllString(scrubbed, "[REDACTED_INTERNAL_IP]")
	// Embed synthetic canary into context metadata
	return fmt.Sprintf("%s\n<!-- context_trace_id: %s -->", scrubbed, CanarySecret)
}

// HandleHITLApprove resolves a suspended tool invocation
func (g *Gateway) HandleHITLApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID       string `json:"id"`
		Approved bool   `json:"approved"`
		Approver string `json:"approver"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	g.pendingMu.Lock()
	ch, exists := g.pendingHITL[body.ID]
	if exists {
		delete(g.pendingHITL, body.ID)
	}
	g.pendingMu.Unlock()

	if !exists {
		http.Error(w, `{"error":"suspension ID not found or already expired"}`, http.StatusNotFound)
		return
	}

	ch <- HITLVerdict{Approved: body.Approved, Approver: body.Approver}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"verdict_delivered"}`))
}

// HandleDelegateToken mints a down-scoped JWT for sub-agents (intersection of parent & requested scopes)
func (g *Gateway) HandleDelegateToken(w http.ResponseWriter, r *http.Request) {
	parentScopes := g.extractScopes(r.Header.Get("Authorization"))
	var req struct {
		ChildAgent      string   `json:"child_agent"`
		RequestedScopes []string `json:"requested_scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	parentSet := make(map[string]bool)
	for _, s := range parentScopes {
		parentSet[s] = true
	}

	// Enforce strict capability intersection (child cannot escalate privileges)
	var granted []string
	for _, s := range req.RequestedScopes {
		if parentSet[s] {
			granted = append(granted, s)
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    req.ChildAgent,
		"scopes": granted,
		"exp":    time.Now().Add(30 * time.Minute).Unix(),
	})
	signed, _ := token.SignedString(g.jwtSecret)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"delegation_token": signed,
		"granted_scopes":   granted,
	})
}

func (g *Gateway) extractScopes(authHeader string) []string {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return []string{"query_db", "execute_code", "http_request", "deploy_service"}
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) { return g.jwtSecret, nil })
	if err != nil || !tok.Valid {
		return []string{}
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return []string{}
	}
	rawScopes, ok := claims["scopes"].([]any)
	if !ok {
		return []string{}
	}
	var out []string
	for _, item := range rawScopes {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (g *Gateway) SynthesizeDraftPolicy() string {
	g.observedMu.Lock()
	defer g.observedMu.Unlock()

	var sb strings.Builder
	sb.WriteString("# Auto-synthesized Least-Privilege Rego Policy from Shadow Mode Run\npackage aegis.authz\nimport rego.v1\ndefault decision := \"deny\"\n\n")
	for tool := range g.observedRuns {
		sb.WriteString(fmt.Sprintf("decision := \"allow\" if {\n\tinput.tool == %q\n\t%q in input.delegated_scopes\n}\n\n", tool, tool))
	}
	return sb.String()
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}
