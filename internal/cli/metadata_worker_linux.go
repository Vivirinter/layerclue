//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/containerd"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

type identityResponse struct {
	Identity    *casefile.Identity `json:"identity,omitempty"`
	Error       string             `json:"error,omitempty"`
	Unsupported bool               `json:"unsupported,omitempty"`
}

type cappedBuffer struct {
	buffer bytes.Buffer
	Max    int
}

func (b *cappedBuffer) Len() int      { return b.buffer.Len() }
func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.Max-b.Len() {
		return 0, evidence.ErrLimit
	}
	return b.buffer.Write(p)
}

// Crash/CPU/output isolation, not a general filesystem or hard-memory sandbox.
func readIdentity(parent context.Context, c *casefile.Case) (*casefile.Identity, error) {
	if c.Metadata == "" && c.DockerInspect == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	temp, err := os.MkdirTemp("", "layerclue-worker-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temp)
	// #nosec G204 -- Re-executes os.Executable with a fixed subcommand, separate argv and a reduced environment; no shell.
	cmd := exec.CommandContext(ctx, exe, "_identity-worker", c.Root)
	cmd.Env = []string{"TMPDIR=" + temp, "GOMEMLIMIT=128MiB", "GOMAXPROCS=2", "GOTRACEBACK=none"}
	cmd.Dir = temp
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdout := &cappedBuffer{Max: 1 << 20}
	stderr := &cappedBuffer{Max: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("metadata worker: %w", ctx.Err())
		}
		return nil, fmt.Errorf("metadata worker failed: %w", err)
	}
	var response identityResponse
	if err := evidence.DecodeJSON(stdout.Bytes(), &response); err != nil {
		return nil, errors.New("invalid metadata worker response")
	}
	if response.Error != "" {
		if response.Unsupported {
			return nil, fmt.Errorf("%w: %s", containerd.ErrUnsupportedFormat, response.Error)
		}
		return nil, errors.New(response.Error)
	}
	return response.Identity, nil
}

func (a *application) cmdIdentityWorker(args []string) int {
	if len(args) != 1 {
		return exitUsage
	}
	for resource, limit := range map[int]syscall.Rlimit{
		syscall.RLIMIT_CORE:   {Cur: 0, Max: 0},
		syscall.RLIMIT_CPU:    {Cur: 3, Max: 4},
		syscall.RLIMIT_NOFILE: {Cur: 128, Max: 128},
		syscall.RLIMIT_FSIZE:  {Cur: uint64(evidence.MaxDatabaseBytes), Max: uint64(evidence.MaxDatabaseBytes)},
	} {
		if err := syscall.Setrlimit(resource, &limit); err != nil {
			return exitCase
		}
	}
	c, err := casefile.Open(args[0])
	var id *casefile.Identity
	if err == nil {
		id, err = c.Identity()
	}
	response := identityResponse{Identity: id}
	if err != nil {
		response.Error = err.Error()
		response.Unsupported = errors.Is(err, containerd.ErrUnsupportedFormat)
	}
	if err := json.NewEncoder(a.stdout).Encode(response); err != nil {
		return exitCase
	}
	return exitOK
}
