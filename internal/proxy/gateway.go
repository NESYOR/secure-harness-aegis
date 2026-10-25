package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/sec-agent/aegis-harness/internal/audit"
	"github.com/sec-agent/aegis-harness/internal/auth"
	"github.com/sec-agent/aegis-harness/internal/redact"
	"github.com/sec-agent/aegis-harness/internal/sandbox"
)

const (
	maxRequestBodyBytes = 1 << 20
	maxAuditArgBytes    = 8192
	maxSessionIDBytes   = 128
)

var (
	errHITLTimeout    = errors.New("human approval timed out")
	errHITLClientGone = errors.New("client disconnected while awaiting approval")
	errUnknownTool    = errors.New("unknown tool")
)

type Gateway struct {
	policyPath string
	policyMu   sync.RWMutex
	opaQuery   rego.PreparedEvalQuery

	ledger  *audit.Ledger
	auth    *auth.Manager
	sandbox *sandbox.SandboxRunner

	shadowMode bool
	hitlTTL    time.Duration

	secretVault    map[string]string
	demoDownstream bool
	upstreamURL    string
	upstreamToken  string
	httpClient     *http.Client

	pendingMu   sync.Mutex
	pendingHITL map[string]*pendingApproval

	observedMu   sync.Mutex
	observedRuns map[string]bool

	canaries     sync.Map // session ID -> per-session canary token
	sessionAbort sync.Map // session ID -> true after a tripwire
}

type pendingApproval struct {
	ch        chan HITLVerdict
	sessionID string
	tool      string
	createdAt time.Time
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

func NewGateway(ctx context.Context, policyPath string, ledger *audit.Ledger, authMgr *auth.Manager, shadow bool, hitlTTL time.Duration, requireIsolation bool) (*Gateway, error) {
	if ledger == nil {
		return nil, errors.New("audit ledger is required")
	}
	if authMgr == nil {
		return nil, errors.New("auth manager is required")
	}
	if hitlTTL <= 0 {
		hitlTTL = 5 * time.Minute
	}

	query, err := compilePolicy(ctx, policyPath)
	if err != nil {
		return nil, err
	}

	return &Gateway{
		policyPath:   policyPath,
		opaQuery:     query,
		ledger:       ledger,
		auth:         authMgr,
		sandbox:      sandbox.NewRunner(10*time.Second, requireIsolation),
		shadowMode:   shadow,
		hitlTTL:      hitlTTL,
		secretVault:  buildSecretVault(),
		pendingHITL:  make(map[string]*pendingApproval),
		observedRuns: make(map[string]bool),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Never follow redirects: an upstream must not be able to
				// redirect brokered calls to an unintended destination.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// SetDemoDownstream enables the synthetic demo adapters. Production
// deployments should configure a real upstream instead.
func (g *Gateway) SetDemoDownstream(enabled bool) { g.demoDownstream = enabled }

// SetUpstream configures forwarding of authorized tool calls to a real MCP
// JSON-RPC endpoint. Redirects are rejected and responses are size-limited.
func (g *Gateway) SetUpstream(rawURL, token string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("upstream URL must use http or https")
	}
	if parsed.Host == "" {
		return errors.New("upstream URL must include a host")
	}
	g.upstreamURL = rawURL
	g.upstreamToken = token
	return nil
}

// DownstreamReady reports whether a demo or real downstream is configured.
func (g *Gateway) DownstreamReady() bool { return g.demoDownstream || g.upstreamURL != "" }

func compilePolicy(ctx context.Context, policyPath string) (rego.PreparedEvalQuery, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("failed reading policy file: %w", err)
	}
	query, err := rego.New(
		rego.Query("data.aegis.authz"),
		rego.Module(policyPath, string(policyBytes)),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("failed compiling Rego policy: %w", err)
	}
	return query, nil
}

// ValidatePolicy compiles a Rego source string without activating it.
func ValidatePolicy(ctx context.Context, src string) error {
	_, err := rego.New(
		rego.Query("data.aegis.authz"),
		rego.Module("synthesized.rego", src),
	).PrepareForEval(ctx)
	return err
}

// ReloadPolicy atomically swaps in a freshly compiled policy file. It is used
// by SIGHUP so operators can update policy without dropping in-flight calls.
func (g *Gateway) ReloadPolicy(ctx context.Context) error {
	query, err := compilePolicy(ctx, g.policyPath)
	if err != nil {
		return err
	}
	g.policyMu.Lock()
	g.opaQuery = query
	g.policyMu.Unlock()
	return nil
}

// Isolation reports the sandbox mode in use.
func (g *Gateway) Isolation() sandbox.Mode { return g.sandbox.Isolation() }

// HandleMCP intercepts JSON-RPC 2.0 `tools/call` invocations.
func (g *Gateway) HandleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONRPCError(w, nil, -32600, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeJSONRPCError(w, nil, -32600, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	principal, err := g.auth.Authenticate(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONRPCError(w, nil, -32004, "unauthorized: missing or invalid agent token", http.StatusUnauthorized)
		return
	}

	sessionID := principal.Subject
	if requested := strings.TrimSpace(r.Header.Get("X-Aegis-Session")); requested != "" {
		if len(requested) > maxSessionIDBytes || !auth.ValidIdentity(requested) {
			writeJSONRPCError(w, nil, -32602, "X-Aegis-Session must match [A-Za-z0-9._-]{1,128}", http.StatusBadRequest)
			return
		}
		sessionID += "/" + requested
	}

	if _, terminated := g.sessionAbort.Load(sessionID); terminated {
		writeJSONRPCError(w, nil, -32010, "session terminated by canary tripwire", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONRPCError(w, nil, -32013, "request body exceeds 1 MiB limit", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONRPCError(w, nil, -32700, "failed reading request body", http.StatusBadRequest)
		return
	}

	canary, err := g.canaryFor(sessionID)
	if err != nil {
		writeJSONRPCError(w, nil, -32005, "failed to initialize session canary", http.StatusInternalServerError)
		return
	}
	if owner, _, found := g.findCanary(string(body)); found {
		g.sessionAbort.Store(sessionID, true)
		if owner != "" && owner != sessionID {
			// The canary belongs to another session. Kill the exfiltrating
			// session and the session whose data leaked.
			g.sessionAbort.Store(owner, true)
		}
		_, auditErr := g.ledger.Append(sessionID, "CANARY_TRIPWIRE", truncate(g.redactCanaries(string(body)), maxAuditArgBytes), "ABORT_EXFILTRATION", "system")
		if auditErr != nil {
			log.Printf("[Aegis] CRITICAL: failed to audit canary tripwire: %v", auditErr)
		}
		log.Printf("[ALERT] CANARY TRIPWIRE TRIGGERED in session %s! Terminating session immediately.", sessionID)
		writeJSONRPCError(w, nil, -32010, "critical: canary token exfiltration detected; session terminated", http.StatusForbidden)
		return
	}

	var mcpReq MCPRequest
	if err := json.Unmarshal(body, &mcpReq); err != nil {
		writeJSONRPCError(w, nil, -32700, "invalid JSON-RPC payload", http.StatusBadRequest)
		return
	}
	if mcpReq.JSONRPC != "2.0" || mcpReq.Method != "tools/call" {
		writeJSONRPCError(w, mcpReq.ID, -32600, "only MCP tools/call is supported", http.StatusBadRequest)
		return
	}

	var callParams ToolCallParams
	if err := json.Unmarshal(mcpReq.Params, &callParams); err != nil || strings.TrimSpace(callParams.Name) == "" {
		writeJSONRPCError(w, mcpReq.ID, -32602, "invalid tool params", http.StatusBadRequest)
		return
	}
	if callParams.Arguments == nil {
		callParams.Arguments = map[string]any{}
	}

	auditArgs := truncate(redact.JSON(callParams.Arguments), maxAuditArgBytes)
	decision, reason := g.evaluatePolicy(r.Context(), callParams.Name, callParams.Arguments, principal.Scopes)
	auditDecision := "ALLOW"
	if g.shadowMode && decision == "suspend" {
		// Shadow mode bypasses HITL so operators can profile real traffic, but
		// it never weakens unconditional denies (for example SSRF to cloud
		// metadata).
		log.Printf("[SHADOW-MODE] would have suspended tool %s (%s); permitting for profiling", callParams.Name, reason)
		decision = "allow"
		auditDecision = "ALLOW_SHADOW"
	}

	approver := "policy-engine"
	if decision == "suspend" {
		// Audit the suspension before blocking. If the ledger is unavailable,
		// fail closed rather than creating an unauditable approval request.
		if _, err := g.ledger.Append(sessionID, callParams.Name, auditArgs, "SUSPEND", "policy-engine"); err != nil {
			writeJSONRPCError(w, mcpReq.ID, -32005, "audit ledger unavailable; failing closed", http.StatusInternalServerError)
			return
		}

		verdict, err := g.waitForApproval(r.Context(), sessionID, callParams.Name, auditArgs)
		switch {
		case errors.Is(err, errHITLTimeout):
			writeJSONRPCError(w, mcpReq.ID, -32002, fmt.Sprintf("human approval timed out after %v (fail-closed)", g.hitlTTL), http.StatusForbidden)
			return
		case errors.Is(err, errHITLClientGone):
			return
		case err != nil:
			writeJSONRPCError(w, mcpReq.ID, -32005, "approval failed", http.StatusInternalServerError)
			return
		}
		if !verdict.Approved {
			if _, auditErr := g.ledger.Append(sessionID, callParams.Name, auditArgs, "DENIED_BY_HUMAN", verdict.Approver); auditErr != nil {
				log.Printf("[Aegis] CRITICAL: failed to audit human denial: %v", auditErr)
			}
			writeJSONRPCError(w, mcpReq.ID, -32001, "action rejected by human reviewer", http.StatusForbidden)
			return
		}
		decision = "allow"
		approver = verdict.Approver
		auditDecision = "ALLOW_HITL"
	}

	if decision != "allow" {
		_, auditErr := g.ledger.Append(sessionID, callParams.Name, auditArgs, "DENY", approver)
		if auditErr != nil {
			log.Printf("[Aegis] CRITICAL: failed to audit denied call: %v", auditErr)
		}
		writeJSONRPCError(w, mcpReq.ID, -32000, fmt.Sprintf("policy denied: %s", reason), http.StatusForbidden)
		return
	}

	// Audit intent before executing. A crash or hang after this point still
	// leaves an attributable record of the authorized action.
	if _, err := g.ledger.Append(sessionID, callParams.Name, auditArgs, auditDecision+"_INTENT", approver); err != nil {
		writeJSONRPCError(w, mcpReq.ID, -32005, "audit ledger unavailable; failing closed", http.StatusInternalServerError)
		return
	}

	rawOutput, execErr := g.executeToolDownstream(r.Context(), callParams)
	if execErr != nil {
		_, auditErr := g.ledger.Append(sessionID, callParams.Name, truncate(redact.Text(execErr.Error()), maxAuditArgBytes), "EXEC_ERROR", approver)
		if auditErr != nil {
			log.Printf("[Aegis] CRITICAL: failed to audit execution error: %v", auditErr)
		}
		writeJSONRPCError(w, mcpReq.ID, -32003, "tool execution failed: "+redact.Text(execErr.Error()), http.StatusBadGateway)
		return
	}

	cleanOutput := scrubAndInjectCanary(rawOutput, canary)
	hash, err := g.ledger.Append(sessionID, callParams.Name, auditArgs, auditDecision, approver)
	if err != nil {
		// The tool already ran; report the failure but never hide it.
		log.Printf("[Aegis] CRITICAL: executed tool but failed to audit result: %v", err)
		writeJSONRPCError(w, mcpReq.ID, -32005, "tool executed but audit append failed", http.StatusInternalServerError)
		return
	}

	g.recordObserved(callParams.Name)

	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      mcpReq.ID,
		"result": map[string]any{
			"output":     cleanOutput,
			"audit_hash": hash,
		},
	})
}

func (g *Gateway) evaluatePolicy(ctx context.Context, tool string, args map[string]any, scopes []string) (string, string) {
	evalCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	input := map[string]any{
		"tool":             tool,
		"args":             args,
		"delegated_scopes": scopes,
	}

	g.policyMu.RLock()
	defer g.policyMu.RUnlock()
	rs, err := g.opaQuery.Eval(evalCtx, rego.EvalInput(input))
	if err != nil || len(rs) == 0 {
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

func (g *Gateway) waitForApproval(ctx context.Context, sessionID, tool, auditArgs string) (HITLVerdict, error) {
	reqID, err := randomRequestID()
	if err != nil {
		return HITLVerdict{}, err
	}
	ch := make(chan HITLVerdict, 1)
	p := &pendingApproval{ch: ch, sessionID: sessionID, tool: tool, createdAt: time.Now()}

	g.pendingMu.Lock()
	g.pendingHITL[reqID] = p
	g.pendingMu.Unlock()

	defer func() {
		g.pendingMu.Lock()
		delete(g.pendingHITL, reqID)
		g.pendingMu.Unlock()
	}()

	log.Printf("[HITL SUSPENDED] tool=%s session=%s id=%s | approve via: aegis-harness approve --id %s", tool, sessionID, reqID, reqID)

	timer := time.NewTimer(g.hitlTTL)
	defer timer.Stop()

	select {
	case verdict := <-ch:
		return verdict, nil
	case <-timer.C:
		_, auditErr := g.ledger.Append(sessionID, tool, auditArgs, "DENIED_HITL_TTL_EXPIRED", "system-ttl")
		if auditErr != nil {
			log.Printf("[Aegis] CRITICAL: failed to audit HITL timeout: %v", auditErr)
		}
		return HITLVerdict{}, errHITLTimeout
	case <-ctx.Done():
		_, auditErr := g.ledger.Append(sessionID, tool, auditArgs, "ABORTED_CLIENT_DISCONNECT", "system")
		if auditErr != nil {
			log.Printf("[Aegis] CRITICAL: failed to audit HITL disconnect: %v", auditErr)
		}
		return HITLVerdict{}, errHITLClientGone
	}
}

func (g *Gateway) executeToolDownstream(ctx context.Context, call ToolCallParams) (string, error) {
	if g.upstreamURL != "" {
		return g.forwardUpstream(ctx, call)
	}
	if !g.demoDownstream {
		return "", errors.New("no downstream adapter configured")
	}
	return g.executeDemoTool(ctx, call)
}

func (g *Gateway) executeDemoTool(ctx context.Context, call ToolCallParams) (string, error) {
	switch call.Name {
	case "execute_code":
		code, _ := call.Arguments["code"].(string)
		if strings.TrimSpace(code) == "" {
			return "", errors.New("code argument is required")
		}
		return g.sandbox.ExecutePython(ctx, code)

	case "query_db":
		q, _ := call.Arguments["query"].(string)
		// Demo downstream adapter. Replace with a real read-only database
		// connector in production; it intentionally returns synthetic PII so
		// output scrubbing can be verified end-to-end.
		return fmt.Sprintf(`[{"id":1,"user":"alice@internal.corp","ssn":"123-45-6789","internal_ip":"10.24.1.99","query_executed":%q}]`, q), nil

	case "http_request":
		url, _ := call.Arguments["url"].(string)
		authHeader, _ := call.Arguments["auth_header"].(string)
		injected, missing := redact.ReplaceSecrets(authHeader, g.secretVault)
		if len(missing) > 0 {
			return "", fmt.Errorf("secret(s) not configured: %s", strings.Join(missing, ", "))
		}
		// Demo downstream adapter. No outbound request is made; in production
		// this is where the brokered request would be sent with a strict
		// timeout and response-size limit.
		return fmt.Sprintf(`{"status":200,"url":%q,"secret_injected":%v,"leak_check":"Bearer eyJhbGciOiJIUzI1NiJ9.secret"}`,
			url, injected != authHeader), nil

	case "deploy_service":
		env, _ := call.Arguments["env"].(string)
		return fmt.Sprintf(`{"status":"deployed","env":%q,"demo":true}`, env), nil

	default:
		return "", fmt.Errorf("%w: %s", errUnknownTool, call.Name)
	}
}

func (g *Gateway) forwardUpstream(ctx context.Context, call ToolCallParams) (string, error) {
	args, missing := g.injectSecrets(call.Arguments)
	if len(missing) > 0 {
		return "", fmt.Errorf("secret(s) not configured: %s", strings.Join(missing, ", "))
	}

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      call.Name,
			"arguments": args,
		},
	})
	if err != nil {
		return "", fmt.Errorf("encoding upstream request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.upstreamURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("building upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.upstreamToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.upstreamToken)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading upstream response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("invalid upstream JSON-RPC response: %w", err)
	}
	if envelope.Error != nil {
		return "", fmt.Errorf("upstream error: %s", envelope.Error.Message)
	}
	if len(envelope.Result) == 0 {
		return "", errors.New("upstream response has no result")
	}

	var result map[string]any
	if err := json.Unmarshal(envelope.Result, &result); err == nil {
		if output, ok := result["output"].(string); ok {
			return output, nil
		}
		if content, ok := result["content"].([]any); ok {
			var parts []string
			for _, item := range content {
				if block, ok := item.(map[string]any); ok {
					if text, ok := block["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "\n"), nil
			}
		}
	}
	return string(envelope.Result), nil
}

// injectSecrets recursively substitutes {{SECRET:NAME}} placeholders in all
// string arguments using an isolated copy of the request.
func (g *Gateway) injectSecrets(v any) (any, []string) {
	var missing []string
	var walk func(any) any
	walk = func(value any) any {
		switch x := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, val := range x {
				out[k] = walk(val)
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, val := range x {
				out[i] = walk(val)
			}
			return out
		case string:
			replaced, notFound := redact.ReplaceSecrets(x, g.secretVault)
			missing = append(missing, notFound...)
			return replaced
		default:
			return v
		}
	}
	return walk(v), missing
}

func scrubAndInjectCanary(payload, canary string) string {
	scrubbed := redact.Text(payload)
	return fmt.Sprintf("%s\n<!-- context_trace_id: %s -->", scrubbed, canary)
}

// HandleHITLApprove resolves a suspended tool invocation. It requires the
// process-local admin token; an agent JWT is not sufficient.
func (g *Gateway) HandleHITLApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	if !g.auth.IsAdminRequest(r) {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var body struct {
		ID       string `json:"id"`
		Approved bool   `json:"approved"`
		Approver string `json:"approver"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if strings.TrimSpace(body.ID) == "" {
		writeJSONError(w, http.StatusBadRequest, "id is required")
		return
	}
	if body.Approver == "" {
		body.Approver = "unknown-approver"
	}
	if len(body.Approver) > 128 {
		writeJSONError(w, http.StatusBadRequest, "approver is too long")
		return
	}

	g.pendingMu.Lock()
	p, exists := g.pendingHITL[body.ID]
	if exists {
		delete(g.pendingHITL, body.ID)
	}
	g.pendingMu.Unlock()

	if !exists {
		writeJSONError(w, http.StatusNotFound, "suspension id not found or already expired")
		return
	}

	select {
	case p.ch <- HITLVerdict{Approved: body.Approved, Approver: body.Approver}:
	default:
		writeJSONError(w, http.StatusConflict, "suspension already resolved")
		return
	}
	log.Printf("[HITL] id=%s session=%s approved=%v approver=%s", body.ID, p.sessionID, body.Approved, body.Approver)
	writeJSON(w, http.StatusOK, map[string]string{"status": "verdict_delivered"})
}

// HandleDelegateToken mints a down-scoped JWT for sub-agents. The child
// receives the intersection of the parent's scopes and its request.
func (g *Gateway) HandleDelegateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}

	parent, err := g.auth.Authenticate(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid agent token")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		ChildAgent      string   `json:"child_agent"`
		RequestedScopes []string `json:"requested_scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.ChildAgent) == "" || len(req.RequestedScopes) == 0 {
		writeJSONError(w, http.StatusBadRequest, "child_agent and requested_scopes are required")
		return
	}

	token, granted, err := g.auth.MintDelegation(parent, req.ChildAgent, req.RequestedScopes)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "delegation denied: "+err.Error())
		return
	}

	auditArgs := truncate(redact.JSON(map[string]any{
		"child_agent":      req.ChildAgent,
		"requested_scopes": req.RequestedScopes,
		"granted_scopes":   granted,
	}), maxAuditArgBytes)
	if _, err := g.ledger.Append(parent.Subject, "delegate", auditArgs, "ALLOW_DELEGATION", parent.Subject); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit ledger unavailable; failing closed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"delegation_token": token,
		"granted_scopes":   granted,
	})
}

func (g *Gateway) recordObserved(tool string) {
	g.observedMu.Lock()
	g.observedRuns[tool] = true
	g.observedMu.Unlock()
}

// SynthesizeDraftPolicy produces a least-privilege baseline from tools that
// were actually allowed during a shadow run.
func (g *Gateway) SynthesizeDraftPolicy() string {
	g.observedMu.Lock()
	defer g.observedMu.Unlock()

	tools := make([]string, 0, len(g.observedRuns))
	for tool := range g.observedRuns {
		tools = append(tools, tool)
	}
	sort.Strings(tools)

	var sb strings.Builder
	sb.WriteString("# Auto-synthesized least-privilege Rego policy from a shadow-mode run.\n")
	sb.WriteString("# Review before use: it allows each observed tool for callers holding the\n")
	sb.WriteString("# matching scope, but does not encode argument-level constraints.\n")
	sb.WriteString("package aegis.authz\n\nimport rego.v1\n\ndefault decision := \"deny\"\ndefault reason := \"implicitly denied by synthesized policy\"\n\n")
	for _, tool := range tools {
		fmt.Fprintf(&sb, "decision := \"allow\" if {\n\tinput.tool == %q\n\t%q in object.get(input, \"delegated_scopes\", [])\n}\n\n", tool, tool)
	}
	sb.WriteString("reason := \"permitted by synthesized shadow policy\" if {\n\tdecision == \"allow\"\n}\n")
	return sb.String()
}

func (g *Gateway) canaryFor(sessionID string) (string, error) {
	if v, ok := g.canaries.Load(sessionID); ok {
		return v.(string), nil
	}
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "AEGIS-CANARY-" + hex.EncodeToString(b)
	actual, _ := g.canaries.LoadOrStore(sessionID, token)
	return actual.(string), nil
}

// findCanary returns the owner and token of the first active canary found in a
// request body. Scanning every session lets us catch cross-session leakage.
func (g *Gateway) findCanary(body string) (owner, token string, found bool) {
	g.canaries.Range(func(k, v any) bool {
		t := v.(string)
		if t != "" && strings.Contains(body, t) {
			owner, token, found = k.(string), t, true
			return false
		}
		return true
	})
	return owner, token, found
}

func (g *Gateway) redactCanaries(s string) string {
	g.canaries.Range(func(_, v any) bool {
		s = strings.ReplaceAll(s, v.(string), "[REDACTED_CANARY]")
		return true
	})
	return s
}

func buildSecretVault() map[string]string {
	vault := make(map[string]string)
	for _, name := range []string{"GITHUB_TOKEN", "DB_PASSWORD"} {
		for _, envName := range []string{"AEGIS_SECRET_" + name, "REAL_" + name} {
			if v := os.Getenv(envName); v != "" {
				vault[name] = v
				break
			}
		}
	}
	if vault["GITHUB_TOKEN"] == "" {
		if raw, err := randomHex(24); err == nil {
			vault["GITHUB_TOKEN"] = "ghp_ephemeral_" + raw
			log.Printf("[Aegis] AEGIS_SECRET_GITHUB_TOKEN is not set; using an ephemeral demo secret")
		}
	}
	return vault
}

func randomRequestID() (string, error) {
	raw, err := randomHex(12)
	if err != nil {
		return "", err
	}
	return "hitl-" + raw, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, msg string, status int) {
	writeJSON(w, status, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}
