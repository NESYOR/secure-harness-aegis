package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCappedBuffer(t *testing.T) {
	var b cappedBuffer
	b.max = 5
	if _, err := b.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if !b.truncated {
		t.Fatal("expected truncation")
	}
	if b.String() != "hello" {
		t.Fatalf("buffer = %q", b.String())
	}
}

func TestRequireIsolationFailsClosed(t *testing.T) {
	s := &SandboxRunner{Mode: ModeNone, Timeout: time.Second, RequireIsolation: true}
	if _, err := s.ExecutePython(context.Background(), "print(1)"); err == nil {
		t.Fatal("expected isolation requirement to fail")
	}
}

func TestExecutePythonFallback(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	s := &SandboxRunner{Mode: ModeNone, Timeout: 5 * time.Second}
	out, err := s.ExecutePython(context.Background(), "print(2 + 2)")
	if err != nil {
		t.Fatalf("ExecutePython: %v (output %q)", err, out)
	}
	if strings.TrimSpace(out) != "4" {
		t.Fatalf("output = %q", out)
	}
}

func TestExecutePythonBoundedOutput(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	s := &SandboxRunner{Mode: ModeNone, Timeout: 5 * time.Second}
	out, err := s.ExecutePython(context.Background(), "print('x' * (2 * 1024 * 1024))")
	if err != nil {
		t.Fatalf("ExecutePython: %v", err)
	}
	if !strings.Contains(out, "output truncated") {
		t.Fatalf("expected truncation marker, got %d bytes", len(out))
	}
}

func TestEmptyCodeRejected(t *testing.T) {
	s := &SandboxRunner{Mode: ModeNone, Timeout: time.Second}
	if _, err := s.ExecutePython(context.Background(), "   "); err == nil {
		t.Fatal("expected empty code error")
	}
}
