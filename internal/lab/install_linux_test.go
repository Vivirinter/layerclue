//go:build linux

package lab

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/distribution"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"golang.org/x/sys/unix"
)

func TestBinaryInstallation(t *testing.T) {
	if os.Getenv("LAYERCLUE_INSTALL_CHILD") == "1" {
		installationChild(t)
		return
	}
	if os.Getenv("LAYERCLUE_INSTALL_TEST") != "1" {
		t.Skip("opt in with LAYERCLUE_INSTALL_TEST=1; builds a local bundle and runs it in an empty private chroot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	work := t.TempDir()
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(work, "candidate")
	if err := distribution.Build(ctx, distribution.BuildOptions{Root: source, Output: candidate}); err != nil {
		t.Fatal(err)
	}
	if _, err := distribution.Verify(ctx, candidate, nil); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(work, "installed")
	if err := os.Mkdir(installed, 0700); err != nil {
		t.Fatal(err)
	}
	// This extraction is only a test of our own freshly built candidate. The
	// product's release verifier still never extracts downloaded artifacts.
	files := unpackOwnCandidate(t, filepath.Join(candidate, "layerclue_linux_"+runtime.GOARCH+".tar.gz"), installed)
	var inputs map[string]string
	if err := json.Unmarshal(files["INPUTS.json"], &inputs); err != nil {
		t.Fatal(err)
	}
	for name, hash := range inputs {
		data, ok := files[name]
		sum := sha256.Sum256(data)
		if !ok || hex.EncodeToString(sum[:]) != hash {
			t.Fatalf("bundled input mismatch: %s", name)
		}
	}
	for _, name := range []string{"LICENSE", "README.md", "docs/SECURITY.md", "examples/demo/case.json", "examples/demo/mountinfo", "examples/demo/captures/bin/helper"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing install input: %s", name)
		}
	}
	for _, name := range []string{"proc", "tmp", "home", "dev"} {
		if err := os.Mkdir(filepath.Join(installed, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	image := testfixture.NewProvenanceCase(t)
	copyFixtureTree(t, filepath.Dir(image.Root), filepath.Base(image.Root), filepath.Join(installed, "metadata-case"))
	// This part needs neither namespaces nor privileges and can run on normal
	// CI runners. PATH deliberately contains no compiler or external commands.
	for _, sample := range []struct{ target, capture string }{{"/usr/bin/helper", "examples/demo"}, {"/opt/tool", "metadata-case"}} {
		cmd := exec.CommandContext(ctx, filepath.Join(installed, "layerclue"), "explain", sample.target, "--case", filepath.Join(installed, sample.capture), "--strict")
		cmd.Dir = installed
		cmd.Env = []string{"PATH=/no-executables", "HOME=" + filepath.Join(installed, "home"), "TMPDIR=" + filepath.Join(installed, "tmp"), "GOMAXPROCS=2"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ordinary-user installed CLI: %v %.4096s", err, out)
		}
	}
	t.Logf("Release archive and metadata-worker re-exec passed as uid %d with no executables in PATH", os.Geteuid())
	if os.Getenv("LAYERCLUE_INSTALL_CHROOT_TEST") != "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", "--pid", "--fork", "--kill-child=KILL", "--net", "--mount-proc", exe, "-test.run=^TestBinaryInstallation$", "-test.v")
	cmd.Env = append(labEnvironment(work), "LAYERCLUE_INSTALL_CHILD=1", "LAYERCLUE_INSTALL_ROOT="+installed, "LAYERCLUE_PARENT_NS="+parentNamespaces(t))
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatalf("empty-root installation failed: %v", err)
	}
}

func installationChild(t *testing.T) {
	root := os.Getenv("LAYERCLUE_INSTALL_ROOT")
	requirePrivateNamespaces(t)
	if !filepath.IsAbs(root) || filepath.Base(root) != "installed" {
		t.Fatal("invalid private installation root")
	}
	proc := filepath.Join(root, "proc")
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(proc, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	// os/exec uses the standard null device for absent stdin. Bind only this
	// one existing device into our private root; never mknod or alter the host.
	null := filepath.Join(root, "dev/null")
	f, err := os.OpenFile(null, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("/dev/null", null, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(null, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(want int, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/layerclue", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/no-executables", "HOME=/home", "TMPDIR=/tmp", "GOMAXPROCS=2", "GOMEMLIMIT=64MiB"}
		out, err := cmd.CombinedOutput()
		got := 0
		if err != nil {
			var status *exec.ExitError
			if !errors.As(err, &status) {
				t.Fatalf("start installed binary: %v", err)
			}
			got = status.ExitCode()
		}
		if got != want {
			t.Fatalf("installed CLI %q: exit %d want %d: %.4096s", args, got, want, out)
		}
		return out
	}
	run(0, "version")
	run(0, "inspect", "--case", "/examples/demo")
	report := run(0, "explain", "/usr/bin/helper", "--case", "/examples/demo", "--strict", "--json")
	if err := os.WriteFile(filepath.Join(root, "tmp/report.json"), report, 0600); err != nil {
		t.Fatal(err)
	}
	run(0, "verify", "/tmp/report.json", "--case", "/examples/demo", "--strict")
	run(0, "explain", "/opt/tool", "--case", "/metadata-case", "--strict") // forks its installed metadata worker
	run(0, "keygen", "--private-key", "/tmp/private.hex", "--public-key", "/tmp/public.hex")
	run(0, "collect", "--case", "/examples/demo", "--output", "/tmp/bundle", "--method", "empty-root synthetic install test", "--sign-key", "/tmp/private.hex")
	run(0, "verify-case", "--case", "/tmp/bundle/case", "--inventory", "/tmp/bundle/inventory.json", "--public-key", "/tmp/public.hex")
	run(3, "collect", "--case", "/examples/demo", "--output", "/tmp/bundle", "--method", "refuse replacement")
	t.Log("Installed static binary, bundled demo, metadata-worker re-exec, report replay and signed packaging work without Go, a shell, libraries or network inside the private chroot")
}

func unpackOwnCandidate(t *testing.T, archive, destination string) map[string][]byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	r := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsLocal(h.Name) || filepath.Clean(h.Name) != h.Name || h.Name == "." || h.Typeflag != tar.TypeReg || len(files) >= 512 || h.Size < 0 || h.Size > 16<<20 {
			t.Fatal("unsafe own-candidate member")
		}
		if _, exists := files[h.Name]; exists {
			t.Fatal("duplicate own-candidate member")
		}
		var data bytes.Buffer
		n, err := evidence.Copy(context.Background(), &data, r, (64<<20)-total)
		if err != nil || n != h.Size {
			t.Fatalf("archive read: %v", err)
		}
		total += n
		mode := os.FileMode(0600)
		if h.Name == "layerclue" {
			mode = 0700
		}
		name := filepath.Join(destination, h.Name)
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := out.Write(data.Bytes())
		closeErr := out.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		files[h.Name] = data.Bytes()
	}
	return files
}
