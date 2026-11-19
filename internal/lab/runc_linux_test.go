//go:build linux

package lab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// capturePrivateRunc runs only after all four private namespace checks in the
// outer lab. It uses a manually built non-TTY OCI spec against containerd's own
// mounted snapshot. This is not the containerd shim/task or CRI integration.
func capturePrivateRunc(t *testing.T, ctx context.Context, root, merged string, env []string) {
	t.Helper()
	bundle := filepath.Join(root, "runc-bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	// No devpts/TTY or cgroup configuration is needed for this one-shot helper.
	// All runtime state and logs are explicitly placed in the private lab root.
	if err := os.MkdirAll(filepath.Join(merged, "dev"), 0755); err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{
		"ociVersion": "1.0.2",
		"root":       map[string]any{"path": merged, "readonly": false},
		"process":    map[string]any{"terminal": false, "user": map[string]int{"uid": 0, "gid": 0}, "args": []string{"/lab", "mountinfo"}, "env": []string{"GOMAXPROCS=2", "GOMEMLIMIT=64MiB"}, "cwd": "/", "noNewPrivileges": true, "capabilities": map[string][]string{"bounding": {}, "effective": {}, "inheritable": {}, "permitted": {}, "ambient": {}}},
		"mounts":     []map[string]any{{"destination": "/proc", "type": "proc", "source": "proc", "options": []string{"nosuid", "nodev", "noexec"}}},
		"linux":      map[string]any{"rootfsPropagation": "rprivate", "namespaces": []map[string]string{{"type": "mount"}, {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "network"}}},
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	runcRoot := filepath.Join(root, "runc-state")
	base := []string{"--root", runcRoot, "--rootless=true", "--log", filepath.Join(root, "runc.log")}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "/usr/bin/runc", append(append([]string{}, base...), args...)...)
		cmd.Env = env
		cmd.Dir = bundle
		cmd.WaitDelay = time.Second
		return cmd.CombinedOutput()
	}
	// Cleanup is restricted to the explicitly named process in this private state
	// root. The PID namespace owner is also killed if the outer test times out.
	t.Cleanup(func() {
		if _, err := os.Lstat(filepath.Join(runcRoot, "fixture-process")); err == nil {
			if out, err := run("delete", "--force", "fixture-process"); err != nil {
				t.Errorf("delete owned runc process: %v %.4096s", err, out)
			}
		}
	})
	if out, err := run("run", "--bundle", bundle, "--no-new-keyring", "fixture-process"); err != nil {
		t.Fatalf("private non-TTY runc process: %v %.4096s", err, out)
	}
	version, err := exec.CommandContext(ctx, "/usr/bin/runc", "--version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manual runc process completed: %.256s", version)
}
