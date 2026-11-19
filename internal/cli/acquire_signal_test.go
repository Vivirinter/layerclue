//go:build linux

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/testfixture"
)

func TestAcquireSignalChild(t *testing.T) {
	raw := os.Getenv("LAYERCLUE_ACQUIRE_TEST_PROCESS")
	if raw == "" {
		t.Skip("subprocess entry point")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		os.Exit(99)
	}
	os.Exit(Run(args, os.Stdout, os.Stderr))
}

func TestAcquireSIGTERMRemovesStaging(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	id := strings.Repeat("f", 64)
	testfixture.Write(t, filepath.Join(f.Root, "docker.json"), []byte(fmt.Sprintf(`[{"Id":%q,"Image":%q,"GraphDriver":{"Name":"overlay2","Data":{"LowerDir":"/host/snapshots/2/fs:/host/snapshots/1/fs","UpperDir":"/host/snapshots/3/fs"}}}]`, id, f.ConfigDigest)))
	testfixture.Write(t, filepath.Join(f.Root, "docker-mountinfo"), []byte("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/host/snapshots/2/fs:/host/snapshots/1/fs,upperdir=/host/snapshots/3/fs,userxattr\n"))
	// A bounded set of hardlinks supplies enough hash work to observe staging
	// without allocating a huge source image or relying on slow/network storage.
	payload := filepath.Join(f.Root, "host/snapshots/1/fs/payload")
	testfixture.Write(t, payload, make([]byte, 8<<20))
	for i := 0; i < 63; i++ {
		if err := os.Link(payload, fmt.Sprintf("%s-%02d", payload, i)); err != nil {
			t.Fatal(err)
		}
	}
	base := t.TempDir()
	output := filepath.Join(base, "bundle")
	planName := filepath.Join(base, "plan.json")
	plan := acquire.Plan{Schema: acquire.PlanSchema, ContainerID: id, Inspect: "docker.json", Mountinfo: "docker-mountinfo", Method: "synthetic signal-cancellation fixture", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "native"}
	data, _ := json.Marshal(plan)
	if err := os.WriteFile(planName, data, 0600); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal([]string{"acquire-docker", "--source", f.Root, "--plan", planName, "--output", output})
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestAcquireSignalChild$")
	cmd.Env = append(os.Environ(), "LAYERCLUE_ACQUIRE_TEST_PROCESS="+string(args))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		matches, err := filepath.Glob(filepath.Join(base, ".layerclue-acquire-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("acquisition exited before staging: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("staging was not observed")
		}
		time.Sleep(time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var code *exec.ExitError
		if !errors.As(err, &code) || code.ExitCode() != exitCase {
			t.Fatalf("expected graceful processing failure, got %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("SIGTERM did not cancel acquisition")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("cancelled acquisition published output")
	}
	matches, err := filepath.Glob(filepath.Join(base, ".layerclue-acquire-*"))
	if err != nil || len(matches) > 0 {
		t.Fatalf("cancelled staging remains: %v %v", matches, err)
	}
}
