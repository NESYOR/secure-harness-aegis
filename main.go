package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/sec-agent/aegis-harness/internal/audit"
	"github.com/sec-agent/aegis-harness/internal/ebpf"
	"github.com/sec-agent/aegis-harness/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "approve":
		approveCmd(os.Args[2:])
	case "verify-audit":
		verifyCmd(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.rego", "Path to declarative Rego policy")
	auditPath := fs.String("audit-db", "aegis_audit.db", "Path to append-only SQLite WAL ledger")
	listenAddr := fs.String("listen", "127.0.0.1:8787", "Local proxy address")
	shadowMode := fs.Bool("shadow", false, "Enable Shadow/Profiling mode and synthesize draft policy")
	enableEBPF := fs.Bool("ebpf", false, "Attach optional Linux eBPF cgroup socket filter")
	hitlTTL := fs.Duration("hitl-ttl", 5*time.Minute, "Bounded TTL for suspended HITL tool calls")
	_ = fs.Parse(args)

	cmdArgs := fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	ledger, err := audit.NewLedger(*auditPath)
	if err != nil {
		log.Fatalf("Failed initializing tamper-evident ledger: %v", err)
	}
	defer ledger.Close()

	ebpfHook, err := ebpf.AttachEgressFilter(*enableEBPF, "/sys/fs/cgroup")
	if err != nil {
		log.Fatalf("Failed initializing eBPF filter: %v", err)
	}
	defer ebpfHook.Close()

	ctx := context.Background()
	gw, err := proxy.NewGateway(ctx, *policyPath, ledger, *shadowMode, *hitlTTL)
	if err != nil {
		log.Fatalf("Failed initializing Aegis Gateway: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mcp", gw.HandleMCP)
	mux.HandleFunc("/v1/hitl/approve", gw.HandleHITLApprove)
	mux.HandleFunc("/v1/delegate", gw.HandleDelegateToken)

	srv := &http.Server{Addr: *listenAddr, Handler: mux}
	go func() {
		log.Printf("[Aegis] Sidecar listening on http://%s (Shadow=%v, HITL-TTL=%v)", *listenAddr, *shadowMode, *hitlTTL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()
	time.Sleep(150 * time.Millisecond)

	if len(cmdArgs) == 0 {
		log.Printf("[Aegis] Running in standalone daemon mode. Press Ctrl+C to stop.")
		select {}
	}

	// Execute wrapped agent subprocess with injected proxy environment
	agentCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr
	agentCmd.Stdin = os.Stdin
	// Strip sensitive host credentials from the agent's environment
	agentCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"AEGIS_MCP_URL=http://" + *listenAddr + "/v1/mcp",
		"AEGIS_GATEWAY_URL=http://" + *listenAddr,
	}

	err = agentCmd.Run()
	_ = srv.Shutdown(ctx)

	if *shadowMode {
		draft := gw.SynthesizeDraftPolicy()
		_ = os.WriteFile("policy.synthesized.rego", []byte(draft), 0644)
		log.Printf("[Shadow Mode] Synthesized least-privilege baseline policy -> policy.synthesized.rego")
	}

	if err != nil {
		os.Exit(1)
	}
}

func approveCmd(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	id := fs.String("id", "", "Suspended HITL request ID")
	approver := fs.String("approver", "secops-admin", "Approver identity")
	deny := fs.Bool("deny", false, "Reject instead of approve")
	addr := fs.String("addr", "http://127.0.0.1:8787", "Gateway address")
	_ = fs.Parse(args)

	if *id == "" {
		log.Fatal("--id is required")
	}

	payload, _ := json.Marshal(map[string]any{
		"id":       *id,
		"approved": !*deny,
		"approver": *approver,
	})
	resp, err := http.Post(*addr+"/v1/hitl/approve", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("Failed contacting gateway: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("HITL Verdict submitted (HTTP %d)\n", resp.StatusCode)
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	auditPath := fs.String("audit-db", "aegis_audit.db", "Path to SQLite WAL audit ledger")
	_ = fs.Parse(args)

	ledger, err := audit.NewLedger(*auditPath)
	if err != nil {
		log.Fatalf("Error opening ledger: %v", err)
	}
	defer ledger.Close()

	count, err := ledger.VerifyChain()
	if err != nil {
		log.Fatalf("[TAMPER DETECTED] %v", err)
	}
	fmt.Printf("[OK] Verified %d hash-chained cryptographic audit records. Zero tampering detected.\n", count)
}

func usage() {
	fmt.Println(`Usage:
  aegis-harness run [--policy policy.rego] [--shadow] [--ebpf] -- <agent-command>
  aegis-harness approve --id <hitl-id> [--approver <name>] [--deny]
  aegis-harness verify-audit [--audit-db aegis_audit.db]`)
}
