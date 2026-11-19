//go:build linux

// Package lab contains opt-in kernel differential checks. Mounts are confined
// to an unprivileged user/mount namespace; no Docker socket or host mount changes.
package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/overlay"
	"github.com/Vivirinter/layerclue/internal/resolve"
	"golang.org/x/sys/unix"
)

func TestKernelOverlay(t *testing.T) {
	if os.Getenv("LAYERCLUE_LAB_CHILD") != "1" {
		if os.Getenv("LAYERCLUE_KERNEL_TEST") != "1" {
			t.Skip("opt in with LAYERCLUE_KERNEL_TEST=1; requires unprivileged user namespaces and OverlayFS")
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--fork", exe, "-test.run=^TestKernelOverlay$", "-test.v")
		cmd.Env = append(os.Environ(), "LAYERCLUE_LAB_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatalf("isolated kernel lab failed: %v", err)
		}
		return
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || len(strings.Fields(string(uidMap))) != 3 || strings.Fields(string(uidMap))[2] != "1" {
		t.Fatal("kernel lab child requires a single-user mapping, not the initial user namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	base, top, upper, work, merged := filepath.Join(root, "base"), filepath.Join(root, "top"), filepath.Join(root, "upper"), filepath.Join(root, "work"), filepath.Join(root, "merged")
	for _, p := range []string{base, top, upper, work, merged} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"unchanged", "modified", "same", "deleted", "bindfile", "d/old", "dir/value", "dir/nested/dummy", "value"} {
		write(filepath.Join(base, name), "base:"+name)
	}
	write(filepath.Join(top, "priority"), "top priority")
	write(filepath.Join(base, "priority"), "base priority")
	if err := os.Symlink("dir/nested", filepath.Join(base, "jump")); err != nil {
		t.Fatal(err)
	}
	opts := "lowerdir=" + top + ":" + base + ",upperdir=" + upper + ",workdir=" + work + ",userxattr"
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Fatalf("mount isolated OverlayFS: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(merged, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	write(filepath.Join(merged, "modified"), "changed")
	write(filepath.Join(merged, "same"), "base:same")
	write(filepath.Join(merged, "added"), "added")
	if err := os.Remove(filepath.Join(merged, "deleted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(merged, "d/old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(merged, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(merged, "d"), 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(merged, "d/new"), "new directory")
	bind := filepath.Join(root, "bindsource")
	write(bind, "bound bytes")
	if err := unix.Mount(bind, filepath.Join(merged, "bindfile"), "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(filepath.Join(merged, "bindfile"), unix.MNT_DETACH) })
	tableAll, err := mounts.ParseFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var table mounts.Table
	sources := map[int]resolve.MountSource{}
	for _, e := range tableAll {
		if e.Point != merged && !strings.HasPrefix(e.Point, merged+"/") {
			continue
		}
		e.Point = strings.TrimPrefix(e.Point, merged)
		if e.Point == "" {
			e.Point = "/"
		} else {
			sources[e.ID] = resolve.MountSource{Root: bind, Artifact: "bindsource", Complete: true}
		}
		table = append(table, e)
	}
	stack := overlay.Stack{Boundary: root, AttrPrefix: "user.overlay.", Layers: []overlay.Layer{{Index: 0, Root: base}, {Index: 1, Root: top}, {Index: 2, Root: upper, Upper: true}}}
	tests := []struct {
		path    string
		verdict model.Verdict
	}{
		{"/unchanged", model.VerdictFromImageLayer}, {"/priority", model.VerdictFromImageLayer},
		{"/modified", model.VerdictFromUpperModified}, {"/same", model.VerdictFromUpperCopyUpSame},
		{"/added", model.VerdictFromUpperAdded}, {"/deleted", model.VerdictDeletedByWhiteout},
		{"/d/old", model.VerdictDeletedByOpaqueParent}, {"/d/new", model.VerdictFromUpperAdded},
		{"/jump/../value", model.VerdictFromImageLayer}, {"/bindfile", model.VerdictShadowedByMount},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			r := resolve.New(resolve.Options{CaseRoot: root, MountinfoArtifact: "/proc/self/mountinfo (isolated lab)", Mounts: table, Stack: stack, OverlayPoint: "/", MountSources: sources})
			out, err := r.Resolve(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if out.Incomplete {
				t.Fatalf("incomplete: %v", out.Missing)
			}
			if out.Verdict != tc.verdict {
				t.Fatalf("verdict=%s want=%s; %s", out.Verdict, tc.verdict, out.Explanation)
			}
			// Do not filepath.Join/Clean: kernel must interpret symlinks before '..'.
			actual, err := os.ReadFile(merged + tc.path)
			if errors.Is(err, os.ErrNotExist) {
				if out.Visible != nil {
					t.Fatalf("kernel absent but resolver visible: %+v", out.Visible)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(actual)
			if out.Visible == nil || out.Visible.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("resolver bytes disagree with kernel: %+v", out.Visible)
			}
		})
	}
	t.Run("escaped-layer-paths", func(t *testing.T) {
		lower := filepath.Join(root, `lower,colon:back\slash`)
		upper := filepath.Join(root, `upper,back\slash`)
		work := filepath.Join(root, "escaped-work")
		merged := filepath.Join(root, "escaped-merged")
		for _, dir := range []string{lower, upper, work, merged} {
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		write(filepath.Join(lower, "tool"), "escaped lower bytes")
		escape := strings.NewReplacer(`\`, `\\`, ":", `\:`, ",", `\,`)
		opts := "lowerdir=" + escape.Replace(lower) + ",upperdir=" + escape.Replace(upper) + ",workdir=" + work + ",userxattr"
		if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
			t.Fatalf("mount escaped-path fixture: %v", err)
		}
		t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
		table, err := mounts.ParseFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		entry, _, err := table.Select(merged + "/tool")
		if err != nil {
			t.Fatal(err)
		}
		lowers := entry.LowerDirs()
		if len(lowers) != 1 || lowers[0] != lower || entry.SuperValue("upperdir") != upper {
			t.Fatalf("decoded kernel paths differ: lower=%q upper=%q", lowers, entry.SuperValue("upperdir"))
		}
		stack := overlay.Stack{Boundary: root, AttrPrefix: "user.overlay.", Layers: []overlay.Layer{{Root: lowers[0]}, {Root: entry.SuperValue("upperdir"), Upper: true}}}
		result, err := stack.Lookup("/tool")
		if err != nil || result.State != overlay.StateFound || result.Entry.HostPath != filepath.Join(lower, "tool") {
			t.Fatalf("wrong escaped-path provenance: %+v %v", result, err)
		}
	})
}
