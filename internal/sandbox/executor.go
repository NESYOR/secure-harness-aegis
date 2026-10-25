package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Mode describes the strongest isolation primitives available on the host.
type Mode string

const (
	ModeGVisor     Mode = "gvisor"
	ModeDocker     Mode = "docker"
	ModeBubblewrap Mode = "bubblewrap"
	ModeNone       Mode = "none"
)

const maxOutputBytes = 1 << 20

type SandboxRunner struct {
	Mode             Mode
	Timeout          time.Duration
	RequireIsolation bool
}

// NewRunner detects available isolation runtimes. It never silently upgrades
// an unisolated fallback: callers can require isolation to fail closed.
func NewRunner(timeout time.Duration, requireIsolation bool) *SandboxRunner {
	return &SandboxRunner{
		Mode:             detectMode(),
		Timeout:          timeout,
		RequireIsolation: requireIsolation,
	}
}

func detectMode() Mode {
	if _, err := exec.LookPath("docker"); err == nil {
		if _, err := exec.LookPath("runsc"); err == nil {
			return ModeGVisor
		}
		return ModeDocker
	}
	if _, err := exec.LookPath("bwrap"); err == nil {
		return ModeBubblewrap
	}
	return ModeNone
}

// Isolation reports the active isolation mode.
func (s *SandboxRunner) Isolation() Mode { return s.Mode }

// ExecutePython runs untrusted Python code with a timeout and bounded output.
func (s *SandboxRunner) ExecutePython(ctx context.Context, code string) (string, error) {
	if strings.TrimSpace(code) == "" {
		return "", errors.New("empty code payload")
	}
	if s.RequireIsolation && s.Mode == ModeNone {
		return "", errors.New("no sandbox runtime available and --require-isolation is set")
	}

	execCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "aegis-sandbox-*")
	if err != nil {
		return "", fmt.Errorf("failed creating ephemeral sandbox dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd, err := s.command(execCtx, tmpDir, code)
	if err != nil {
		return "", err
	}

	var stdout, stderr cappedBuffer
	stdout.max = maxOutputBytes
	stderr.max = maxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	output := stdout.String() + stderr.String()
	if stdout.truncated || stderr.truncated {
		output += "\n[AEGIS: output truncated at 1 MiB]"
	}
	if execCtx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("sandbox execution timed out after %v", s.Timeout)
	}
	if err != nil {
		return output, fmt.Errorf("sandbox exited with error: %v", err)
	}
	return output, nil
}

func (s *SandboxRunner) command(ctx context.Context, tmpDir, code string) (*exec.Cmd, error) {
	switch s.Mode {
	case ModeGVisor, ModeDocker:
		args := []string{"run", "--rm",
			"--network=none",
			"--memory=128m",
			"--memory-swap=128m",
			"--cpus=0.5",
			"--pids-limit=64",
			"--cap-drop=ALL",
			"--security-opt=no-new-privileges",
			"--read-only",
			"--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
			"--user=65534:65534",
			"--workdir=/tmp",
		}
		if s.Mode == ModeGVisor {
			args = append(args, "--runtime=runsc")
		}
		args = append(args, "python:3.12-alpine", "python3", "-I", "-c", code)
		return exec.CommandContext(ctx, "docker", args...), nil

	case ModeBubblewrap:
		args := []string{
			"--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
			"--ro-bind", "/usr", "/usr",
			"--ro-bind", "/bin", "/bin",
			"--ro-bind", "/lib", "/lib",
			"--proc", "/proc",
			"--dev", "/dev",
			"--tmpfs", "/tmp",
			"--chdir", "/tmp",
			"--setenv", "PATH", "/usr/bin:/bin",
			"--setenv", "HOME", "/tmp",
			"--setenv", "PYTHONDONTWRITEBYTECODE", "1",
		}
		for _, p := range []string{"/lib64", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group"} {
			if _, err := os.Stat(p); err == nil {
				args = append(args, "--ro-bind", p, p)
			}
		}
		args = append(args, "python3", "-I", "-c", code)
		return exec.CommandContext(ctx, "bwrap", args...), nil

	default:
		cmd := exec.CommandContext(ctx, "python3", "-I", "-c", code)
		cmd.Dir = tmpDir
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"HOME=" + tmpDir,
			"PYTHONDONTWRITEBYTECODE=1",
		}
		return cmd, nil
	}
}

type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.max - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.truncated = true
		_, _ = b.buf.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }
