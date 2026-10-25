package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type SandboxRunner struct {
	UseGVisor bool
	Timeout   time.Duration
}

func NewRunner(timeout time.Duration) *SandboxRunner {
	_, err := exec.LookPath("runsc")
	return &SandboxRunner{
		UseGVisor: err == nil,
		Timeout:   timeout,
	}
}

func (s *SandboxRunner) ExecutePython(ctx context.Context, code string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "aegis-sandbox-*")
	if err != nil {
		return "", fmt.Errorf("failed creating ephemeral sandbox dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var cmd *exec.Cmd
	if s.UseGVisor {
		// Dispatch via Docker with gVisor (runsc) runtime and network disabled
		cmd = exec.CommandContext(execCtx, "docker", "run", "--rm",
			"--runtime=runsc",
			"--network=none",
			"--memory=128m",
			"--cpus=0.5",
			"--read-only",
			"python:3.12-alpine", "python3", "-I", "-c", code,
		)
	} else {
		// Fallback: isolated process with zero environment inheritance and clean working dir
		cmd = exec.CommandContext(execCtx, "python3", "-I", "-c", code)
		cmd.Dir = tmpDir
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"HOME=" + tmpDir,
			"PYTHONDONTWRITEBYTECODE=1",
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	output := stdout.String() + stderr.String()
	if execCtx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("sandbox execution timed out after %v", s.Timeout)
	}
	if err != nil {
		return output, fmt.Errorf("sandbox exited with error: %v (%s)", err, output)
	}
	return output, nil
}
