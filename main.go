package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sec-agent/aegis-harness/internal/audit"
	"github.com/sec-agent/aegis-harness/internal/auth"
	"github.com/sec-agent/aegis-harness/internal/ebpf"
	"github.com/sec-agent/aegis-harness/internal/proxy"
	"github.com/sec-agent/aegis-harness/internal/sandbox"
)

const version = "0.2.0"

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if len(os.Args) < 2 {
		usage()
		return 1
	}

	switch os.Args[1] {
	case "run":
		return runCmd(os.Args[2:])
	case "approve":
		return approveCmd(os.Args[2:])
	case "verify-audit":
		return verifyCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("aegis-harness %s\n", version)
		return 0
	default:
		usage()
		return 1
	}
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.rego", "Path to declarative Rego policy")
	auditPath := fs.String("audit-db", "aegis_audit.db", "Path to append-only SQLite WAL ledger")
	listenAddr := fs.String("listen", "127.0.0.1:8787", "Local proxy address")
	shadowMode := fs.Bool("shadow", false, "Enable Shadow/Profiling mode and synthesize draft policy")
	enableEBPF := fs.Bool("ebpf", false, "Attach optional Linux eBPF cgroup socket filter (experimental)")
	hitlTTL := fs.Duration("hitl-ttl", 5*time.Minute, "Bounded TTL for suspended HITL tool calls")
	requireIsolation := fs.Bool("require-isolation", false, "Refuse to run tools unless a real sandbox runtime is available")
	rootScopes := fs.String("root-scopes", "query_db,execute_code,http_request", "Comma-separated scopes granted to the root agent")
	shadowOut := fs.String("shadow-out", "policy.synthesized.rego", "Output path for shadow-mode policy synthesis")
	demoDownstream := fs.Bool("demo", false, "Use synthetic demo tool adapters (never enable in production)")
	upstreamURL := fs.String("upstream", "", "Forward authorized tools/call requests to an upstream MCP JSON-RPC URL")
	upstreamToken := fs.String("upstream-token", os.Getenv("AEGIS_UPSTREAM_TOKEN"), "Bearer token for the upstream MCP server (prefer AEGIS_UPSTREAM_TOKEN)")
	auditKeyPath := fs.String("audit-key-file", "", "Audit HMAC key file (default: <audit-db>.key)")
	adminTokenPath := fs.String("admin-token-file", "", "HITL admin token file (default: <audit-db>.admin)")
	agentTokenPath := fs.String("agent-token-file", "", "Root agent token file (default: <audit-db>.agent)")
	_ = fs.Parse(args)

	if *hitlTTL <= 0 {
		log.Printf("[Aegis] --hitl-ttl must be greater than zero")
		return 1
	}
	if *auditKeyPath == "" {
		*auditKeyPath = *auditPath + ".key"
	}
	if *adminTokenPath == "" {
		*adminTokenPath = *auditPath + ".admin"
	}
	if *agentTokenPath == "" {
		*agentTokenPath = *auditPath + ".agent"
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	key, err := audit.LoadOrCreateKey(*auditKeyPath)
	if err != nil {
		log.Printf("[Aegis] Failed loading audit key: %v", err)
		return 1
	}
	ledger, err := audit.NewLedger(*auditPath, key)
	if err != nil {
		log.Printf("[Aegis] Failed initializing tamper-evident ledger: %v", err)
		return 1
	}
	defer ledger.Close()

	adminToken := os.Getenv("AEGIS_ADMIN_TOKEN")
	adminLoaded := adminToken != ""
	if adminToken == "" {
		if existing := readSecretFile(*adminTokenPath); existing != "" {
			adminToken = existing
			adminLoaded = true
		}
	}
	authMgr, err := auth.NewManager(splitScopes(*rootScopes), adminToken)
	if err != nil {
		log.Printf("[Aegis] Failed initializing token authority: %v", err)
		return 1
	}
	if !adminLoaded {
		if err := writeSecretFile(*adminTokenPath, authMgr.AdminToken()); err != nil {
			log.Printf("[Aegis] Failed writing admin token file: %v", err)
			return 1
		}
	}

	rootToken, err := authMgr.MintRoot("root-agent")
	if err != nil {
		log.Printf("[Aegis] Failed minting root agent token: %v", err)
		return 1
	}
	if err := writeSecretFile(*agentTokenPath, rootToken); err != nil {
		log.Printf("[Aegis] Warning: failed writing agent token file: %v", err)
	}

	ebpfHook, err := ebpf.AttachEgressFilter(*enableEBPF, "/sys/fs/cgroup")
	if err != nil {
		log.Printf("[Aegis] Failed initializing eBPF filter: %v", err)
		return 1
	}
	defer ebpfHook.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gw, err := proxy.NewGateway(ctx, *policyPath, ledger, authMgr, *shadowMode, *hitlTTL, *requireIsolation)
	if err != nil {
		log.Printf("[Aegis] Failed initializing Aegis Gateway: %v", err)
		return 1
	}
	if *requireIsolation && gw.Isolation() == sandbox.ModeNone {
		log.Printf("[Aegis] --require-isolation is set but no supported sandbox runtime (docker/runsc/bwrap) was found")
		return 1
	}
	if *demoDownstream && *upstreamURL != "" {
		log.Printf("[Aegis] Choose either --demo or --upstream, not both")
		return 1
	}
	if *demoDownstream {
		gw.SetDemoDownstream(true)
		log.Printf("[Aegis] WARNING: synthetic demo downstream enabled; tool results are not real")
	} else if *upstreamURL != "" {
		if err := gw.SetUpstream(*upstreamURL, *upstreamToken); err != nil {
			log.Printf("[Aegis] Invalid upstream configuration: %v", err)
			return 1
		}
		log.Printf("[Aegis] Forwarding authorized tool calls to %s", *upstreamURL)
	} else {
		log.Printf("[Aegis] No downstream configured; pass --demo for the verification suite or --upstream for a real MCP server")
		return 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp", gw.HandleMCP)
	mux.HandleFunc("/v1/hitl/approve", gw.HandleHITLApprove)
	mux.HandleFunc("/v1/delegate", gw.HandleDelegateToken)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	writeTimeout := *hitlTTL + 30*time.Second
	if writeTimeout < 60*time.Second {
		writeTimeout = 60 * time.Second
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Printf("[Aegis] Failed binding %s: %v", *listenAddr, err)
		return 1
	}

	serverErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serverErr <- err
	}()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-hup:
				if err := gw.ReloadPolicy(ctx); err != nil {
					log.Printf("[Aegis] Policy reload failed (keeping previous policy): %v", err)
				} else {
					log.Printf("[Aegis] Policy reloaded from %s", *policyPath)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Printf("[Aegis] Sidecar listening on http://%s (shadow=%v, hitl-ttl=%v, isolation=%s)", ln.Addr(), *shadowMode, *hitlTTL, gw.Isolation())
	if gw.Isolation() == sandbox.ModeNone {
		log.Printf("[Aegis] WARNING: no sandbox runtime detected; execute_code runs as an unisolated process. Use --require-isolation in production.")
	}
	log.Printf("[Aegis] Policy=%s AuditDB=%s Key=%s", *policyPath, *auditPath, *auditKeyPath)
	log.Printf("[Aegis] HITL admin token file: %s", *adminTokenPath)

	var agentErr error
	if len(cmdArgs) == 0 {
		log.Printf("[Aegis] Running in standalone daemon mode. Press Ctrl+C to stop.")
		select {
		case <-ctx.Done():
		case err := <-serverErr:
			if err != nil {
				log.Printf("[Aegis] Proxy server failed: %v", err)
				agentErr = err
			}
		}
	} else {
		agentCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		agentCmd.Stdout = os.Stdout
		agentCmd.Stderr = os.Stderr
		agentCmd.Stdin = os.Stdin
		agentCmd.Env = agentEnvironment(ln.Addr().String(), rootToken)

		if err := agentCmd.Start(); err != nil {
			log.Printf("[Aegis] Failed starting agent: %v", err)
			agentErr = err
		} else {
			done := make(chan error, 1)
			go func() { done <- agentCmd.Wait() }()

			select {
			case agentErr = <-done:
			case <-ctx.Done():
				log.Printf("[Aegis] Shutdown signal received; stopping agent")
				_ = agentCmd.Process.Signal(os.Interrupt)
				select {
				case agentErr = <-done:
				case <-time.After(5 * time.Second):
					_ = agentCmd.Process.Kill()
					agentErr = <-done
				}
			case err := <-serverErr:
				if err != nil {
					log.Printf("[Aegis] Proxy server failed: %v", err)
					agentErr = err
				}
				_ = agentCmd.Process.Kill()
				<-done
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Aegis] Graceful shutdown failed: %v", err)
	}

	if *shadowMode {
		draft := gw.SynthesizeDraftPolicy()
		if err := proxy.ValidatePolicy(context.Background(), draft); err != nil {
			log.Printf("[Shadow Mode] Synthesized policy failed validation; refusing to write: %v", err)
		} else if err := os.WriteFile(*shadowOut, []byte(draft), 0o600); err != nil {
			log.Printf("[Shadow Mode] Failed writing %s: %v", *shadowOut, err)
		} else {
			log.Printf("[Shadow Mode] Synthesized least-privilege baseline policy -> %s", *shadowOut)
		}
	}

	if agentErr != nil {
		log.Printf("[Aegis] Agent exited with error: %v", agentErr)
		return 1
	}
	return 0
}

func approveCmd(args []string) int {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	id := fs.String("id", "", "Suspended HITL request ID")
	approver := fs.String("approver", "secops-admin", "Approver identity")
	deny := fs.Bool("deny", false, "Reject instead of approve")
	addr := fs.String("addr", "http://127.0.0.1:8787", "Gateway address")
	adminToken := fs.String("admin-token", "", "HITL admin token (or AEGIS_ADMIN_TOKEN)")
	adminTokenPath := fs.String("admin-token-file", "aegis_audit.db.admin", "Path to admin token file")
	_ = fs.Parse(args)

	if *id == "" {
		log.Printf("[Aegis] --id is required")
		return 1
	}
	if *approver == "" {
		log.Printf("[Aegis] --approver must not be empty")
		return 1
	}

	token := *adminToken
	if token == "" {
		token = os.Getenv("AEGIS_ADMIN_TOKEN")
	}
	if token == "" {
		token = readSecretFile(*adminTokenPath)
	}
	if token == "" {
		log.Printf("[Aegis] Admin token not found. Pass --admin-token, set AEGIS_ADMIN_TOKEN, or use --admin-token-file.")
		return 1
	}

	payload, _ := json.Marshal(map[string]any{
		"id":       *id,
		"approved": !*deny,
		"approver": *approver,
	})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*addr, "/")+"/v1/hitl/approve", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[Aegis] Failed building request: %v", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Admin-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Aegis] Failed contacting gateway: %v", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("HITL verdict submitted (HTTP %d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 1
	}
	return 0
}

func verifyCmd(args []string) int {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	auditPath := fs.String("audit-db", "aegis_audit.db", "Path to SQLite WAL audit ledger")
	keyPath := fs.String("audit-key-file", "aegis_audit.db.key", "Audit HMAC key file")
	_ = fs.Parse(args)

	if _, err := os.Stat(*auditPath); err != nil {
		log.Printf("[Aegis] Audit database not found: %v", err)
		return 1
	}

	key, keyErr := audit.LoadKey(*keyPath)
	authenticated := keyErr == nil
	if keyErr != nil {
		log.Printf("[Aegis] Warning: audit key unavailable (%v); MAC verification disabled", keyErr)
		key = nil
	}

	ledger, err := audit.NewReadOnlyLedger(*auditPath, key)
	if err != nil {
		log.Printf("[TAMPER DETECTED] %v", err)
		return 1
	}
	defer ledger.Close()

	count, err := ledger.VerifyChain()
	if err != nil {
		log.Printf("[TAMPER DETECTED] %v", err)
		return 1
	}
	if authenticated {
		fmt.Printf("[OK] Verified %d hash-chained, MAC-authenticated audit records. Zero tampering detected.\n", count)
	} else {
		fmt.Printf("[OK] Verified %d hash-chained audit records (MAC unavailable). Zero tampering detected.\n", count)
	}
	return 0
}

func agentEnvironment(addr, token string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"AEGIS_MCP_URL=http://" + addr + "/v1/mcp",
		"AEGIS_GATEWAY_URL=http://" + addr,
		"AEGIS_AGENT_TOKEN=" + token,
	}
	for _, key := range []string{"LANG", "LC_ALL", "TERM", "TZ", "TMPDIR", "SHELL"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	return env
}

func splitScopes(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readSecretFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	_ = os.Chmod(path, 0o600)
	token := strings.TrimSpace(string(b))
	if len(token) < 16 {
		return ""
	}
	return token
}

func writeSecretFile(path, value string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func usage() {
	fmt.Println(`Aegis Harness - zero-trust security sidecar for AI agents

Usage:
  aegis-harness run [flags] [-- <agent-command>]
  aegis-harness approve --id <hitl-id> [--approver <name>] [--deny]
  aegis-harness verify-audit [--audit-db aegis_audit.db] [--audit-key-file <path>]
  aegis-harness version

Run flags:
  --policy <path>            Rego policy file (default policy.rego)
  --audit-db <path>          SQLite WAL audit ledger (default aegis_audit.db)
  --listen <addr>            Local proxy address (default 127.0.0.1:8787)
  --shadow                   Shadow/profiling mode; synthesizes a draft policy
  --shadow-out <path>        Synthesized policy output (default policy.synthesized.rego)
  --hitl-ttl <duration>      HITL approval timeout (default 5m)
  --root-scopes <list>       Root agent scopes (default query_db,execute_code,http_request)
  --demo                     Use synthetic demo adapters (verification suite)
  --upstream <url>           Forward authorized tools/call to a real MCP server
  --upstream-token <token>   Upstream bearer token (prefer AEGIS_UPSTREAM_TOKEN)
  --require-isolation        Fail tools unless docker/runsc/bwrap is available
  --audit-key-file <path>    Audit HMAC key (default <audit-db>.key)
  --admin-token-file <path>  HITL admin token (default <audit-db>.admin)
  --agent-token-file <path>  Root agent token (default <audit-db>.agent)
  --ebpf                     Reserved; fails closed because enforcement is not implemented`)
}
