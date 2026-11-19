//go:build linux

package lab

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/verify"
	"golang.org/x/sys/unix"
)

// This lab never uses the host daemon/socket. Its entire daemon and mounts run
// in fresh user/mount/PID/network namespaces with a single-user UID mapping.
// The process uses a snapshot supplied by real containerd. Its default launcher
// is a chroot helper; an explicit opt-in runs a minimal manual runc process.
// Neither profile exercises containerd's task service or Kubernetes workloads.
func TestPrivateContainerd(t *testing.T) {
	if os.Getenv("LAYERCLUE_CONTAINERD_CHILD") == "1" {
		privateContainerd(t)
		return
	}
	if os.Getenv("LAYERCLUE_CONTAINERD_TEST") != "1" {
		t.Skip("opt in with LAYERCLUE_CONTAINERD_TEST=1; requires containerd 1.7, ctr and unprivileged namespaces")
	}
	for _, binary := range []string{"unshare", "containerd", "ctr", "go"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "lc-ctr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removePrivateContainerdRoot(root); err != nil {
			t.Errorf("remove owned private lab: %v", err)
		}
	})
	for name, pkg := range map[string]string{"helper": "../../tools/labfixture", "layerclue": "../../cmd/layerclue"} {
		cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-trimpath", "-o", filepath.Join(root, name), pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build lab binary: %v %s", err, out)
		}
	}
	encoded := parentNamespaces(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", "--pid", "--fork", "--kill-child=KILL", "--net", "--mount-proc", exe, "-test.run=^TestPrivateContainerd$", "-test.v")
	cmd.Env = append(labEnvironment(root), "LAYERCLUE_CONTAINERD_CHILD=1", "LAYERCLUE_LAB_ROOT="+root, "LAYERCLUE_PARENT_NS="+encoded, "LAYERCLUE_RUNC_TEST="+os.Getenv("LAYERCLUE_RUNC_TEST"))
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatalf("private containerd lab failed: %v", err)
	}
}

func labEnvironment(root string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root, "GOMAXPROCS=2", "GOMEMLIMIT=256MiB"}
}

// Called only after the private PID namespace has exited. OverlayFS can leave
// its owned kernel work/work directory mode 000, which an ordinary parent
// cannot traverse for RemoveAll. Repair only that known test-owned location;
// never broaden evidence permissions or walk a caller-selected host directory.
func removePrivateContainerdRoot(root string) error {
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "lc-ctr-") {
		return fmt.Errorf("invalid private cleanup root")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("cleanup root is not an owned directory")
	}
	const snapshots = "root/io.containerd.snapshotter.v1.overlayfs/snapshots"
	dir, err := evidence.OpenDir(root, snapshots)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		names, readErr := dir.Readdirnames(129)
		dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(names) > 128 {
			return evidence.ErrLimit
		}
		for _, name := range names {
			id, err := strconv.ParseUint(name, 10, 64)
			if err != nil || id == 0 || strconv.FormatUint(id, 10) != name {
				return fmt.Errorf("invalid private snapshot directory")
			}
			rel := filepath.Join(snapshots, name, "work/work")
			work, err := evidence.Lstat(root, rel)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			stat, ok := work.Sys().(*syscall.Stat_t)
			if !ok || !work.IsDir() || stat.Uid != uint32(os.Geteuid()) {
				return fmt.Errorf("private work directory was replaced or has foreign ownership")
			}
			if err := unix.Fchmodat(unix.AT_FDCWD, filepath.Join(root, rel), 0700, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
		}
	}
	return os.RemoveAll(root)
}

func privateContainerd(t *testing.T) {
	t.Helper()
	root := os.Getenv("LAYERCLUE_LAB_ROOT")
	requirePrivateNamespaces(t)
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "lc-ctr-") {
		t.Fatal("invalid private lab root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	env := labEnvironment(root)
	version, err := exec.CommandContext(ctx, "/usr/bin/containerd", "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), " 1.7.") {
		t.Fatalf("this lab currently validates containerd 1.7: %q %v", version, err)
	}
	privateContainerdScenario(t, ctx, root, env, version)
}

func parentNamespaces(t *testing.T) string {
	t.Helper()
	parent := map[string]string{}
	for _, name := range []string{"user", "mnt", "pid", "net"} {
		value, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			t.Fatal(err)
		}
		parent[name] = value
	}
	encoded, err := json.Marshal(parent)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func requirePrivateNamespaces(t *testing.T) {
	t.Helper()
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || os.Getpid() != 1 || os.Geteuid() != 0 || len(strings.Fields(string(mapping))) != 3 || strings.Fields(string(mapping))[2] != "1" {
		t.Fatal("lab requires PID 1 in a fresh single-user namespace")
	}
	var parent map[string]string
	if json.Unmarshal([]byte(os.Getenv("LAYERCLUE_PARENT_NS")), &parent) != nil {
		t.Fatal("missing parent namespace identities")
	}
	for _, name := range []string{"user", "mnt", "pid", "net"} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil || parent[name] == "" || current == parent[name] {
			t.Fatalf("%s namespace was not isolated", name)
		}
	}
}

func privateContainerdScenario(t *testing.T, ctx context.Context, root string, env []string, version []byte) {
	t.Helper()
	address := filepath.Join(root, "daemon.sock")
	store := filepath.Join(root, "root")
	config := fmt.Sprintf("version = 2\nroot = %q\nstate = %q\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.internal.v1.opt\", \"io.containerd.internal.v1.restart\", \"io.containerd.nri.v1.nri\", \"io.containerd.internal.v1.tracing\", \"io.containerd.tracing.processor.v1.otlp\"]\n[grpc]\n  address = %q\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\n  mount_options = [\"userxattr\"]\n", store, filepath.Join(root, "state"), address)
	configFile := filepath.Join(root, "containerd.toml")
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(root, "daemon.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	daemon := exec.CommandContext(ctx, "/usr/bin/containerd", "--config", configFile)
	daemon.Env, daemon.Stdout, daemon.Stderr = env, logFile, logFile
	daemon.WaitDelay = time.Second
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- daemon.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = daemon.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-daemonDone:
			if err != nil {
				t.Errorf("stop owned private daemon: %v", err)
			}
		case <-time.After(5 * time.Second):
			_ = daemon.Process.Kill()
			<-daemonDone
			t.Error("private daemon required forced shutdown")
		}
	}
	t.Cleanup(stop)
	ctr := func(args ...string) ([]byte, error) {
		child, done := context.WithTimeout(ctx, 15*time.Second)
		defer done()
		all := append([]string{"--address", address, "--namespace", "layerclue-lab", "--timeout", "10s"}, args...)
		cmd := exec.CommandContext(child, "/usr/bin/ctr", all...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	ready := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(address); err == nil {
			if _, err := ctr("version"); err == nil {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		log, _ := os.ReadFile(filepath.Join(root, "daemon.log"))
		t.Fatalf("private daemon not ready: %.4096s", log)
	}
	runCTR := func(args ...string) []byte {
		t.Helper()
		out, err := ctr(args...)
		if err != nil {
			t.Fatalf("private ctr %q: %v %.4096s", args, err, out)
		}
		return out
	}
	archive, manifest, chain := containerdSeed(t, root)
	runCTR("images", "import", "--snapshotter", "overlayfs", archive)
	runCTR("containers", "create", "--snapshotter", "overlayfs", "--label", "io.kubernetes.pod.name=layerclue-fixture", "layerclue.local/fixture:test", "fixture-container", "/lab", "mountinfo")
	var snapshot struct{ Name, Parent string }
	if err := json.Unmarshal(runCTR("snapshots", "info", "fixture-container"), &snapshot); err != nil || snapshot.Parent != chain {
		t.Fatalf("real snapshot parent differs from image chain: %+v %v", snapshot, err)
	}
	merged := filepath.Join(root, "merged")
	capture := filepath.Join(root, "capture")
	for _, dir := range []string{merged, capture} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// ctr 1.7 prints a mount description; never execute it as shell code.
	// This lab permits only its own whitespace-free paths and a single overlay
	// mount, then supplies the independently returned options to mount(2).
	description := runCTR("snapshots", "--snapshotter", "overlayfs", "mounts", merged, "fixture-container")
	fields := strings.Fields(string(description))
	if len(fields) != 7 || fields[0] != "mount" || fields[1] != "-t" || fields[2] != "overlay" || fields[3] != "overlay" || fields[4] != merged || fields[5] != "-o" {
		t.Fatalf("unexpected private mount description: %q", description)
	}
	for _, option := range strings.Split(fields[6], ",") {
		key, value, hasValue := strings.Cut(option, "=")
		if !hasValue {
			continue
		}
		if key != "lowerdir" && key != "upperdir" && key != "workdir" {
			continue
		}
		for _, address := range strings.Split(value, ":") {
			rel, err := filepath.Rel(store, address)
			if err != nil || !filepath.IsLocal(rel) || rel == "." {
				t.Fatal("runtime mount escaped the private store")
			}
		}
	}
	if err := unix.Mount("overlay", merged, "overlay", 0, fields[6]); err != nil {
		t.Fatal(err)
	}
	mounted := []string{merged}
	unmount := func() {
		for i := len(mounted) - 1; i >= 0; i-- {
			if err := unix.Unmount(mounted[i], unix.MNT_DETACH); err != nil {
				t.Errorf("unmount owned fixture: %v", err)
			}
		}
		mounted = nil
	}
	t.Cleanup(unmount)
	write := func(rel, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(merged, rel), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("opt/modified", "changed bytes\n")
	write("opt/added", "added bytes\n")
	write("opt/same", "same bytes\n")
	for _, name := range []string{"opt/deleted", "d/old", "d"} {
		if err := os.Remove(filepath.Join(merged, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(merged, "d"), 0700); err != nil {
		t.Fatal(err)
	}
	write("d/new", "opaque replacement\n")
	bound := filepath.Join(root, "bound")
	if err := os.WriteFile(bound, []byte("mounted bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		source, target, fs string
		flags              uintptr
	}{
		{"proc", "proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{capture, "capture", "", unix.MS_BIND},
		{bound, "opt/bound", "", unix.MS_BIND},
	} {
		target := filepath.Join(merged, m.target)
		if err := unix.Mount(m.source, target, m.fs, m.flags, ""); err != nil {
			t.Fatal(err)
		}
		mounted = append(mounted, target)
	}
	if os.Getenv("LAYERCLUE_RUNC_TEST") == "1" {
		capturePrivateRunc(t, ctx, root, merged, env)
	} else {
		cmd := exec.CommandContext(ctx, "/lab", "mountinfo")
		cmd.Env, cmd.Dir, cmd.SysProcAttr = env, "/", &syscall.SysProcAttr{Chroot: merged}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("captured chroot process: %v %.4096s", err, out)
		}
	}
	mountinfo, err := os.ReadFile(filepath.Join(capture, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	table, err := mounts.Parse(bytes.NewReader(mountinfo))
	if err != nil {
		t.Fatal(err)
	}
	mountRoot, _, err := table.Select("/")
	if err != nil || mountRoot.FSType != "overlay" || mountRoot.Root != "/" {
		t.Fatalf("bad captured root: %+v %v", mountRoot, err)
	}
	bind, _, err := table.Select("/opt/bound")
	if err != nil || bind.Point != "/opt/bound" {
		t.Fatal("missing captured bind mount")
	}
	unmount()
	stop() // All database/layer copying occurs after clean daemon shutdown.
	caseRoot := filepath.Join(root, "case")
	snapshotRoot := filepath.Join(store, "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	portableRoot := "host/" + strings.TrimPrefix(snapshotRoot, "/")
	copyFixtureTree(t, store, "io.containerd.metadata.v1.bolt/meta.db", filepath.Join(caseRoot, "containerd/meta.db"))
	copyFixtureTree(t, store, "io.containerd.snapshotter.v1.overlayfs/metadata.db", filepath.Join(caseRoot, "snapshotter/metadata.db"))
	copyFixtureTree(t, store, "io.containerd.content.v1.content/blobs", filepath.Join(caseRoot, "oci/blobs"))
	entries, err := os.ReadDir(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		id, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil || id == 0 || !entry.IsDir() {
			t.Fatal("unexpected private snapshot directory")
		}
		copyFixtureTree(t, snapshotRoot, entry.Name()+"/fs", filepath.Join(caseRoot, portableRoot, entry.Name(), "fs"))
	}
	copyFixtureTree(t, root, "bound", filepath.Join(caseRoot, "mounts/bound"))
	if err := os.WriteFile(filepath.Join(caseRoot, "mountinfo"), mountinfo, 0600); err != nil {
		t.Fatal(err)
	}
	manifestData, _ := json.Marshal(map[string]any{"schema": "layerclue.case/v1", "host_root": "host", "mountinfo": "mountinfo", "container_id": "layerclue-lab/fixture-container", "containerd_metadata": "containerd/meta.db", "overlay_xattr_namespace": "capture", "image_provenance": map[string]any{"manifest_digest": manifest, "content_root": "oci", "snapshotter_metadata": "snapshotter/metadata.db", "snapshotter_root": portableRoot}, "mounts": []map[string]any{{"mount_id": bind.ID, "artifact": "mounts/bound", "complete": true}}})
	if err := os.WriteFile(filepath.Join(caseRoot, "case.json"), manifestData, 0600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(root, "layerclue")
	runCLI := func(want int, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		got := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("start CLI: %v", err)
			}
			got = exit.ExitCode()
		}
		if got != want {
			t.Fatalf("CLI %q: exit %d want %d: %.4096s", args, got, want, out)
		}
		return out
	}
	var unchanged model.Report
	for target, verdict := range map[string]model.Verdict{"/opt/unchanged": model.VerdictFromImageLayer, "/opt/image-added": model.VerdictFromImageLayer, "/opt/modified": model.VerdictFromUpperModified, "/opt/added": model.VerdictFromUpperAdded, "/opt/same": model.VerdictFromUpperCopyUpSame, "/opt/deleted": model.VerdictDeletedByWhiteout, "/d/old": model.VerdictDeletedByOpaqueParent, "/opt/bound": model.VerdictShadowedByMount} {
		cmd := exec.CommandContext(ctx, cli, "explain", target, "--case", caseRoot, "--strict", "--json")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("explain %q: %v %.4096s", target, err, out)
		}
		var report model.Report
		if err := json.Unmarshal(out, &report); err != nil {
			t.Fatal(err)
		}
		if report.Runtime != "containerd" || report.ContainerID != "fixture-container" || report.PodName != "layerclue-fixture" || report.Verdict != verdict || report.ImageProvenance == nil || report.ImageProvenance.Status != "verified_metadata_association" {
			t.Fatalf("incorrect real-runtime result for %s: %+v", target, report)
		}
		if problems := verify.Report(&report); len(problems) != 0 {
			t.Fatal(problems)
		}
		if target == "/opt/unchanged" {
			unchanged = report
		}
	}
	comparison := runCLI(0, "compare", "/opt/unchanged", "--case", caseRoot, "--content-root", "oci", "--manifest", manifest, "--json")
	if !bytes.Contains(comparison, []byte(`"status":"matching_bytes"`)) {
		t.Fatal("real snapshot bytes did not match OCI")
	}
	key, public := filepath.Join(root, "test-private.hex"), filepath.Join(root, "test-public.hex")
	runCLI(0, "keygen", "--private-key", key, "--public-key", public)
	bundle := filepath.Join(root, "bundle")
	runCLI(0, "collect", "--case", caseRoot, "--output", bundle, "--method", "private containerd lab, stopped daemon, synthetic image and chroot process", "--sign-key", key)
	runCLI(0, "verify-case", "--case", filepath.Join(bundle, "case"), "--inventory", filepath.Join(bundle, "inventory.json"), "--public-key", public)
	runCLI(0, "explain", "/opt/unchanged", "--case", filepath.Join(bundle, "case"), "--strict")
	if unchanged.Visible == nil || !filepath.IsLocal(unchanged.Visible.CapturedPath) {
		t.Fatal("missing selected captured path")
	}
	if err := os.WriteFile(filepath.Join(caseRoot, unchanged.Visible.CapturedPath), []byte("altered unpacked layer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	comparison = runCLI(1, "compare", "/opt/unchanged", "--case", caseRoot, "--content-root", "oci", "--manifest", manifest, "--json")
	if !bytes.Contains(comparison, []byte(`"status":"different_bytes"`)) {
		t.Fatal("altered unpacked bytes went undetected")
	}
	if os.Getenv("LAYERCLUE_RUNC_TEST") == "1" {
		t.Logf("%s: real snapshots and manually started runc process passed eight path verdicts, OCI/signed-case checks; containerd task service/CRI not covered", strings.TrimSpace(string(version)))
	} else {
		t.Logf("%s: real metadata/OCI/snapshots, eight path verdicts and chroot mount capture passed; no runc task was launched", strings.TrimSpace(string(version)))
	}
}

func fixtureSum(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func containerdSeed(t *testing.T, root string) (archive, manifest, chain string) {
	t.Helper()
	helper, err := os.ReadFile(filepath.Join(root, "helper"))
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string][]byte{}
	var descriptors []map[string]any
	var diffIDs []string
	for i, files := range []map[string][]byte{
		{"lab": helper, "opt/unchanged": []byte("base bytes\n"), "opt/modified": []byte("before\n"), "opt/same": []byte("same bytes\n"), "opt/deleted": []byte("removed\n"), "opt/bound": []byte("image bytes\n"), "d/old": []byte("opaque victim\n")},
		{"opt/image-added": []byte("image layer two\n")},
	} {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		if i == 0 {
			for _, dir := range []string{"proc", "capture", "opt", "d"} {
				if err := writer.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
					t.Fatal(err)
				}
			}
		}
		for name, data := range files {
			mode := int64(0644)
			if name == "lab" {
				mode = 0755
			}
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		data := buffer.Bytes()
		digest := fixtureSum(data)
		blobs[digest] = data
		diffIDs = append(diffIDs, digest)
		if chain == "" {
			chain = digest
		} else {
			chain = fixtureSum([]byte(chain + " " + digest))
		}
		descriptors = append(descriptors, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest, "size": len(data)})
	}
	config, _ := json.Marshal(map[string]any{"os": "linux", "architecture": runtime.GOARCH, "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	configDigest := fixtureSum(config)
	blobs[configDigest] = config
	image, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)}, "layers": descriptors})
	manifest = fixtureSum(image)
	blobs[manifest] = image
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest, "size": len(image), "annotations": map[string]string{"org.opencontainers.image.ref.name": "layerclue.local/fixture:test"}}}})
	archive = filepath.Join(root, "fixture.tar")
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	writer := tar.NewWriter(f)
	for name, data := range map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for digest, data := range blobs {
		if err := writer.WriteHeader(&tar.Header{Name: "blobs/sha256/" + digest[7:], Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive, manifest, chain
}

// Only lab-owned files are copied. Native whiteouts become inert regular
// markers; source capabilities, devices and execution bits are not recreated.
func copyFixtureTree(t *testing.T, root, rel, destination string) {
	t.Helper()
	var count int
	var total int64
	var walk func(string, string, int)
	walk = func(name, dst string, depth int) {
		count++
		if count > 4096 || depth > 64 {
			t.Fatal(evidence.ErrLimit)
		}
		st, err := evidence.Lstat(root, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			t.Fatal(err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			target, err := evidence.Readlink(root, name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dst); err != nil {
				t.Fatal(err)
			}
			return
		}
		if st.IsDir() {
			if err := os.Mkdir(dst, 0700); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				walk(filepath.Join(name, entry.Name()), filepath.Join(dst, entry.Name()), depth+1)
			}
		} else if st.Mode().IsRegular() {
			src, err := evidence.OpenRegular(root, name)
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				src.Close()
				t.Fatal(err)
			}
			n, copyErr := evidence.Copy(context.Background(), out, src, (64<<20)-total)
			total += n
			src.Close()
			closeErr := out.Close()
			if copyErr != nil {
				t.Fatal(copyErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		} else {
			sys, ok := st.Sys().(*syscall.Stat_t)
			if !ok || st.Mode()&os.ModeCharDevice == 0 || sys.Rdev != 0 {
				t.Fatal("refusing non-whiteout special fixture")
			}
			if err := os.WriteFile(dst, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Setxattr(dst, "user.layerclue.overlay.whiteout", nil, 0); err != nil {
				t.Fatal(err)
			}
			return
		}
		for _, feature := range []string{"whiteout", "opaque", "metacopy", "redirect"} {
			value, exists, err := evidence.Xattr(root, name, "user.overlay."+feature)
			if err != nil {
				t.Fatal(err)
			}
			if exists {
				if err := unix.Setxattr(dst, "user.layerclue.overlay."+feature, value, 0); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	walk(rel, destination, 0)
}
