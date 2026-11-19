//go:build linux

package lab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/overlay"
	"golang.org/x/sys/unix"
)

func TestSnapshotAcquisition(t *testing.T) {
	if os.Getenv("LAYERCLUE_ACQUIRE_LAB_CHILD") != "1" {
		if os.Getenv("LAYERCLUE_KERNEL_TEST") != "1" {
			t.Skip("opt in with LAYERCLUE_KERNEL_TEST=1; requires user/mount namespaces")
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--fork", exe, "-test.run=^TestSnapshotAcquisition$", "-test.v")
		cmd.Env = append(os.Environ(), "LAYERCLUE_ACQUIRE_LAB_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatalf("isolated snapshot lab: %v", err)
		}
		return
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || len(strings.Fields(string(uidMap))) != 3 || strings.Fields(string(uidMap))[2] != "1" {
		t.Fatal("requires a single-user mapping")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "snapshot")
	for _, name := range []string{"layers/base", "layers/upper", "metadata"} {
		if err := os.MkdirAll(filepath.Join(source, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"layers/base/kept": "kept bytes", "layers/base/deleted": "deleted bytes"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Native 0:0 whiteout: collection must never open it as data or recreate it.
	if err := unix.Mknod(filepath.Join(source, "layers/upper/deleted"), unix.S_IFCHR|0600, 0); err != nil {
		t.Fatalf("native whiteout fixture requires 0:0 mknod: %v", err)
	}
	id := strings.Repeat("d", 64)
	raw := `[{"Id":"` + id + `","Image":"sha256:` + strings.Repeat("e", 64) + `","GraphDriver":{"Name":"overlay2","Data":{"LowerDir":"/layers/base","UpperDir":"/layers/upper"}}}]`
	if err := os.WriteFile(filepath.Join(source, "metadata/inspect.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "metadata/mountinfo"), []byte("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/layers/base,upperdir=/layers/upper,userxattr\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "metadata/trusted-mountinfo"), []byte("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/layers/base,upperdir=/layers/upper\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, source, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(source, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	if err := unix.Mount("", source, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	if ro, err := evidence.FilesystemReadOnly(source); err != nil || !ro {
		t.Fatalf("read-only observation: %t %v", ro, err)
	}
	if err := os.WriteFile(filepath.Join(source, "layers/base/kept"), []byte("must fail"), 0600); !errors.Is(err, unix.EROFS) {
		t.Fatalf("source was not protected from writes: %v", err)
	}
	trusted := overlay.Stack{Boundary: source, AttrPrefix: "trusted.overlay.", Layers: []overlay.Layer{{Root: filepath.Join(source, "layers/base")}}}
	if _, err := trusted.Lookup("kept"); !errors.Is(err, overlay.ErrUnsupported) {
		t.Fatalf("analysis accepted a subordinate capability as authority for trusted xattrs: %v", err)
	}
	p := acquire.Plan{Schema: acquire.PlanSchema, ContainerID: id, Inspect: "metadata/inspect.json", Mountinfo: "metadata/mountinfo", Method: "isolated synthetic read-only mount fixture", SourceMode: "read_only_mount", OverlayAttributes: "native"}
	subordinate := p
	subordinate.Mountinfo = "metadata/trusted-mountinfo"
	refused := filepath.Join(root, "subordinate-must-fail")
	if _, err := acquire.Docker(context.Background(), acquire.Options{Source: source, Output: refused, Plan: subordinate, Limits: custody.DefaultLimits()}); err == nil {
		t.Fatal("subordinate SYS_ADMIN capability was treated as authority for host trusted attrs")
	}
	if _, err := os.Lstat(refused); !os.IsNotExist(err) {
		t.Fatal("subordinate acquisition published output")
	}
	bundle := filepath.Join(root, "bundle")
	summary, err := acquire.Docker(context.Background(), acquire.Options{Source: source, Output: bundle, Plan: p, Limits: custody.DefaultLimits()})
	if err != nil || !summary.SourceReadOnly {
		t.Fatalf("acquire: %+v %v", summary, err)
	}
	caseRoot := filepath.Join(bundle, "case")
	c, err := casefile.Open(caseRoot)
	if err != nil {
		t.Fatal(err)
	}
	table, err := c.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	stack, missing, err := c.Stack(table)
	if err != nil || len(missing) > 0 {
		t.Fatalf("stack: %v %v", err, missing)
	}
	result, err := stack.Lookup("deleted")
	if err != nil || result.State != overlay.StateDeleted {
		t.Fatalf("whiteout provenance: %+v %v", result, err)
	}
	marker, err := os.Stat(filepath.Join(caseRoot, "host/layers/upper/deleted"))
	if err != nil || !marker.Mode().IsRegular() {
		t.Fatalf("device whiteout was recreated: %v %v", marker, err)
	}
	data, err := os.ReadFile(filepath.Join(bundle, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := custody.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := custody.Verify(context.Background(), caseRoot, seal, custody.DefaultLimits(), nil); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(caseRoot, custody.AcquisitionFile))
	if err != nil {
		t.Fatal(err)
	}
	var journal map[string]json.RawMessage
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(journal["source_entries"]), "native_whiteout") {
		t.Fatal("native whiteout origin not journaled")
	}
	t.Log("read-only source enforced; native whiteout converted to a portable regular marker without opening a device")
}
