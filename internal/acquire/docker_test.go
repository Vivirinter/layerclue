package acquire

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/resolve"
	"golang.org/x/sys/unix"
)

func put(t *testing.T, root, name string, data []byte) {
	t.Helper()
	dst := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (string, Plan) {
	t.Helper()
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	alias := strings.Repeat("A", 26)
	for name, body := range map[string]string{
		"docker/overlay2/base/diff/mnt/tool":        "image mountpoint",
		"docker/overlay2/base/diff/opt/kept":        "original",
		"docker/overlay2/base/diff/opt/changed":     "before",
		"docker/overlay2/base/diff/opt/deleted":     "old",
		"docker/overlay2/base/diff/opt/opaque/old":  "hidden",
		"docker/overlay2/upper/diff/opt/changed":    "after",
		"docker/overlay2/upper/diff/opt/deleted":    "",
		"docker/overlay2/upper/diff/opt/opaque/new": "visible",
		"saved-mount/tool":                          "explicit captured mount",
	} {
		put(t, root, name, []byte(body))
	}
	if err := os.Mkdir(filepath.Join(root, "docker/overlay2/base/diff/proc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(root, "docker/overlay2/upper/diff/opt/deleted"), "user.overlay.whiteout", nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(root, "docker/overlay2/upper/diff/opt/opaque"), "user.overlay.opaque", []byte("y"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "docker/overlay2/l"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../base/diff", filepath.Join(root, "docker/overlay2/l", alias)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/kept", filepath.Join(root, "docker/overlay2/base/diff/shortcut")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "docker/overlay2/base/diff/opt/kept"), filepath.Join(root, "docker/overlay2/base/diff/opt/hard")); err != nil {
		t.Fatal(err)
	}
	var record docker.Record
	record.ID = id
	record.Image = "sha256:" + strings.Repeat("b", 64)
	record.Config.Image = "fixture:tag"
	record.GraphDriver.Name = "overlay2"
	record.GraphDriver.Data = map[string]string{"LowerDir": "/docker/overlay2/base/diff", "UpperDir": "/docker/overlay2/upper/diff"}
	record.Mounts = []docker.Mount{{Type: "bind", Source: "/inspect-source-is-not-a-capture", Destination: "/mnt/tool"}}
	data, _ := json.Marshal([]docker.Record{record})
	put(t, root, "metadata/inspect.json", data)
	put(t, root, "metadata/mountinfo", []byte(fmt.Sprintf("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/docker/overlay2/l/%s,upperdir=/docker/overlay2/upper/diff,userxattr\n11 10 8:1 /untrusted-root /mnt/tool rw - ext4 /dev/synthetic rw\n12 10 0:3 / /proc rw - proc proc rw\n", alias)))
	p := Plan{Schema: PlanSchema, ContainerID: id, Inspect: "metadata/inspect.json", Mountinfo: "metadata/mountinfo", Method: "synthetic immutable working-copy fixture", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "native", Mounts: []Mount{{ID: 11, Source: "saved-mount/tool", Complete: true}}}
	return root, p
}
func explain(t *testing.T, root, target string) *resolve.Outcome {
	t.Helper()
	c, err := casefile.Open(root)
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
	mount, _ := c.OverlayMount(table)
	sources := map[int]resolve.MountSource{}
	for id, m := range c.MountSources {
		sources[id] = resolve.MountSource{Root: m.Root, Artifact: m.Artifact, Complete: m.Complete}
	}
	r := resolve.New(resolve.Options{CaseRoot: c.Root, HostRoot: c.HostRoot, MountinfoArtifact: c.MountinfoRef, Mounts: table, Stack: stack, OverlayPoint: mount.Point, MountSources: sources})
	out, err := r.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestImportSignedDockerSnapshot(t *testing.T) {
	source, p := fixture(t)
	before, err := custody.New(context.Background(), source, "before import", custody.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	summary, err := Docker(context.Background(), Options{Source: source, Output: output, Plan: p, Limits: custody.DefaultLimits(), SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if summary.LayerRoots != 2 || summary.CapturedMounts != 1 || summary.UncapturedMounts != 1 || summary.SourceReadOnly {
		t.Fatalf("wrong coverage: %+v", summary)
	}
	data, err := os.ReadFile(filepath.Join(output, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := custody.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	caseRoot := filepath.Join(output, "case")
	if err := custody.Verify(context.Background(), caseRoot, seal, custody.DefaultLimits(), pub); err != nil {
		t.Fatal(err)
	}
	c, err := casefile.Open(caseRoot)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := c.Identity()
	if err != nil || identity.ContainerID != p.ContainerID || len(identity.DockerAliases) != 1 {
		t.Fatalf("identity: %+v %v", identity, err)
	}
	for _, tc := range []struct {
		path    string
		verdict model.Verdict
	}{
		{"/opt/kept", model.VerdictFromImageLayer}, {"/opt/changed", model.VerdictFromUpperModified},
		{"/opt/deleted", model.VerdictDeletedByWhiteout}, {"/opt/opaque/old", model.VerdictDeletedByOpaqueParent},
		{"/mnt/tool", model.VerdictShadowedByMount},
	} {
		out := explain(t, caseRoot, tc.path)
		if out.Incomplete || out.Verdict != tc.verdict {
			t.Fatalf("%s: %+v", tc.path, out)
		}
	}
	out := explain(t, caseRoot, "/proc/not-captured")
	if !out.Incomplete {
		t.Fatal("omitted mount became complete")
	}
	infoA, err := os.Stat(filepath.Join(caseRoot, "host/docker/overlay2/l", strings.Repeat("A", 26), "opt/kept"))
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := os.Stat(filepath.Join(caseRoot, "host/docker/overlay2/l", strings.Repeat("A", 26), "opt/hard"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoA, infoB) || infoA.Mode().Perm() != 0600 {
		t.Fatal("hardlinks/mode not preserved safely")
	}
	if err := custody.Verify(context.Background(), source, before, custody.DefaultLimits(), nil); err != nil {
		t.Fatalf("source changed: %v", err)
	}
	if _, err := Docker(context.Background(), Options{Source: source, Output: output, Plan: p, Limits: custody.DefaultLimits()}); err == nil {
		t.Fatal("existing bundle was replaced")
	}
}
func TestAcquisitionRefusalsLeaveNoBundle(t *testing.T) {
	for _, kind := range []string{"readonly", "bad-alias", "mount-missing", "mount-symlink", "fifo", "layer-symlink", "missing-layer", "budget", "cancel", "recursive", "trusted-unreadable"} {
		t.Run(kind, func(t *testing.T) {
			source, p := fixture(t)
			output := filepath.Join(t.TempDir(), "bundle")
			limits := custody.DefaultLimits()
			ctx := context.Background()
			switch kind {
			case "readonly":
				p.SourceMode = "read_only_mount"
			case "bad-alias":
				name := filepath.Join(source, "docker/overlay2/l", strings.Repeat("A", 26))
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../../../../outside", name); err != nil {
					t.Fatal(err)
				}
			case "mount-missing":
				p.Mounts[0].ID = 999
			case "mount-symlink":
				if err := os.Symlink("/outside", filepath.Join(source, "saved-mount/link")); err != nil {
					t.Fatal(err)
				}
				p.Mounts[0].Source = "saved-mount/link"
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(source, "docker/overlay2/base/diff/fifo"), 0600); err != nil {
					t.Fatal(err)
				}
			case "layer-symlink":
				dir := filepath.Join(source, "docker/overlay2/base/diff")
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			case "missing-layer":
				if err := os.RemoveAll(filepath.Join(source, "docker/overlay2/upper/diff")); err != nil {
					t.Fatal(err)
				}
			case "budget":
				limits.FileBytes = 1
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "recursive":
				output = filepath.Join(source, "bundle")
			case "trusted-unreadable":
				if evidence.CanReadTrusted() {
					t.Skip("trusted read capability available")
				}
				b, err := os.ReadFile(filepath.Join(source, p.Mountinfo))
				if err != nil {
					t.Fatal(err)
				}
				put(t, source, p.Mountinfo, []byte(strings.ReplaceAll(string(b), ",userxattr", "")))
			}
			if _, err := Docker(ctx, Options{Source: source, Output: output, Plan: p, Limits: limits}); err == nil {
				t.Fatal("unsafe acquisition accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("failed acquisition published a bundle")
			}
			matches, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".layerclue-acquire-*"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("staging not cleaned: %v %v", matches, err)
			}
		})
	}
}
func TestSnapshotChangeDetectedAfterCopy(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "xattr"} {
		t.Run(kind, func(t *testing.T) {
			source, _ := fixture(t)
			dst := t.TempDir()
			c := treeCopy{ctx: context.Background(), root: source, dst: dst, limits: custody.DefaultLimits(), links: map[[2]uint64]string{}}
			if err := c.copy("docker/overlay2/base/diff", "layer", "user.overlay.", 0); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file":
				put(t, source, "docker/overlay2/base/diff/opt/kept", []byte("replaced"))
			case "directory":
				put(t, source, "docker/overlay2/base/diff/new-path", nil)
			case "symlink":
				name := filepath.Join(source, "docker/overlay2/base/diff/shortcut")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/different", name); err != nil {
					t.Fatal(err)
				}
			case "xattr":
				if err := unix.Setxattr(filepath.Join(source, "docker/overlay2/base/diff/opt/kept"), "user.overlay.metacopy", nil, 0); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.recheck(); err == nil {
				t.Fatal("changed source was accepted")
			}
		})
	}
}
func TestArtifactRootOverlapIncludesLexicalInterleaving(t *testing.T) {
	if err := disjoint([]tree{{Output: "host/a"}, {Output: "host/a-b"}, {Output: "host/a/x"}}); err == nil {
		t.Fatal("overlap hidden by lexical sort was accepted")
	}
	if err := disjoint([]tree{{Output: "host/a"}, {Output: "host/a-b"}, {Output: "host/another"}}); err != nil {
		t.Fatal(err)
	}
}
func TestPlanValidationAndFuzzSeeds(t *testing.T) {
	_, p := fixture(t)
	b, _ := json.Marshal(p)
	if _, err := DecodePlan(b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Plan){func(p *Plan) { p.Inspect = "../outside" }, func(p *Plan) { p.SourceMode = "" }, func(p *Plan) { p.OverlayAttributes = "guess" }, func(p *Plan) { p.Mounts = append(p.Mounts, p.Mounts[0]) }, func(p *Plan) { p.Method = "" }, func(p *Plan) { p.ContainerID = "short" }} {
		q := p
		change(&q)
		b, _ := json.Marshal(q)
		if _, err := DecodePlan(b); err == nil {
			t.Fatal("invalid plan accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&treeCopy{ctx: ctx}).copy("a", "b", "", 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func FuzzDecodePlan(f *testing.F) {
	seed, _ := json.Marshal(Plan{Schema: PlanSchema, ContainerID: strings.Repeat("a", 64), Inspect: "metadata/inspect.json", Mountinfo: "metadata/mountinfo", Method: "synthetic fuzz seed", SourceMode: "read_only_mount", OverlayAttributes: "native", Mounts: []Mount{{ID: 11, Source: "captured/bin", Complete: true}}})
	f.Add(seed)
	f.Add([]byte(`{"schema":"layerclue.docker-acquisition/v1"}`))
	f.Add([]byte(`{"schema":"a","schema":"b"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 1<<20 {
			_, _ = DecodePlan(b)
		}
	})
}

func TestTrustedReadContextRejectsSubordinateUIDMaps(t *testing.T) {
	for _, data := range []string{"0 1000 1\n", "0 100000 65536\n", "0 0 1\n", "0 0 4294967295\n1 1 1\n", ""} {
		if initialStyleUIDMap([]byte(data)) {
			t.Fatalf("accepted subordinate/ambiguous mapping %q", data)
		}
	}
	if !initialStyleUIDMap([]byte("         0          0 4294967295\n")) {
		t.Fatal("rejected initial-style full UID map")
	}
}

func TestAcquisitionRefusesOverflowingSourceMtime(t *testing.T) {
	source, p := fixture(t)
	name := filepath.Join(source, "docker/overlay2/base/diff/opt/kept")
	far := time.Unix(1<<34, 0)
	if err := os.Chtimes(name, far, far); err != nil {
		t.Skipf("filesystem timestamp range: %v", err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(time.Unix(0, info.ModTime().UnixNano())) {
		t.Skip("filesystem clamped mtime")
	}
	output := filepath.Join(t.TempDir(), "bundle")
	if _, err := Docker(context.Background(), Options{Source: source, Output: output, Plan: p, Limits: custody.DefaultLimits()}); err == nil {
		t.Fatal("overflowing timestamp accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("published case with ambiguous source timestamp")
	}
}
