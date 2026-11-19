package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/xattr"
)

type fixture struct {
	root  string
	host  string
	base  string
	upper string
	bind  string
}

func mustWrite(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(name, 0o755); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	host := filepath.Join(root, "host")
	f := &fixture{
		root:  root,
		host:  host,
		base:  filepath.Join(host, "var/lib/containerd/snapshots/5/fs"),
		upper: filepath.Join(host, "var/lib/containerd/snapshots/9/fs"),
		bind:  filepath.Join(host, "var/lib/k8s/vol/bin"),
	}
	mustWrite(t, filepath.Join(f.base, "usr/bin/helper"), "A")
	mustWrite(t, filepath.Join(f.base, "etc/passwd"), "root:x:0:0")
	mustWrite(t, filepath.Join(f.base, "etc/shadow"), "secret")
	mustWrite(t, filepath.Join(f.bind, "helper"), "B")
	mustMkdir(t, f.upper)

	mi := fmt.Sprintf(
		"22 1 0:21 / /proc rw,nosuid - proc proc rw\n"+
			"120 100 0:52 / / rw,relatime - overlay overlay rw,lowerdir=%s,upperdir=%s,workdir=%s,userxattr\n"+
			"121 120 8:1 / /usr/bin rw - ext4 %s rw\n",
		"/var/lib/containerd/snapshots/5/fs",
		"/var/lib/containerd/snapshots/9/fs",
		"/var/lib/containerd/snapshots/9/work",
		"/var/lib/k8s/vol/bin",
	)
	mustMkdir(t, filepath.Join(host, "proc/4242"))
	mustWrite(t, filepath.Join(host, "proc/4242/mountinfo"), mi)
	mustWrite(t, filepath.Join(root, "case.json"), `{"schema":"layerclue.case/v1","mounts":[{"mount_id":121,"artifact":"host/var/lib/k8s/vol/bin","complete":true}]}`)
	return f
}

func (f *fixture) resolver(t *testing.T) *Resolver {
	t.Helper()
	c, err := casefile.Open(f.root)
	if err != nil {
		t.Fatal(err)
	}
	table, err := c.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	stack, _, err := c.Stack(table)
	if err != nil {
		t.Fatal(err)
	}
	overlayMount, _ := c.OverlayMount(table)
	sources := make(map[int]MountSource)
	for id, m := range c.MountSources {
		sources[id] = MountSource{Root: m.Root, Artifact: m.Artifact, Complete: m.Complete}
	}
	return New(Options{
		CaseRoot:          c.Root,
		HostRoot:          c.HostRoot,
		MountinfoArtifact: c.MountinfoRef,
		Mounts:            table,
		Stack:             stack,
		OverlayPoint:      overlayMount.Point,
		MountSources:      sources,
	})
}

func (f *fixture) explain(t *testing.T, p string) *Outcome {
	t.Helper()
	out, err := f.resolver(t).Resolve(p)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", p, err)
	}
	return out
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestMountShadowsImage(t *testing.T) {
	f := newFixture(t)
	out := f.explain(t, "/usr/bin/helper")

	if out.Verdict != model.VerdictShadowedByMount {
		t.Fatalf("verdict = %s, want shadowed_by_mount", out.Verdict)
	}
	if out.Visible == nil {
		t.Fatal("visible is nil")
	}
	if out.Visible.Provider != ProviderMount {
		t.Fatalf("visible provider = %s", out.Visible.Provider)
	}
	if out.Visible.SHA256 != digest("B") {
		t.Fatalf("visible digest = %s, want digest of B", out.Visible.SHA256)
	}
	if out.Image == nil {
		t.Fatal("image is nil; the image view must be reported separately")
	}
	if out.Image.SHA256 != digest("A") {
		t.Fatalf("image digest = %s, want digest of A", out.Image.SHA256)
	}
}

func TestFromImageLayer(t *testing.T) {
	f := newFixture(t)
	out := f.explain(t, "/etc/passwd")

	if out.Verdict != model.VerdictFromImageLayer {
		t.Fatalf("verdict = %s, want from_image_layer", out.Verdict)
	}
	if out.Visible.LayerIndex != 0 {
		t.Fatalf("layer index = %d, want 0", out.Visible.LayerIndex)
	}
	if out.Visible.SHA256 != digest("root:x:0:0") {
		t.Fatalf("digest = %s", out.Visible.SHA256)
	}
}

func TestFromUpperAdded(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.upper, "opt/tool"), "payload")

	out := f.explain(t, "/opt/tool")
	if out.Verdict != model.VerdictFromUpperAdded {
		t.Fatalf("verdict = %s, want from_upper_added", out.Verdict)
	}
	if out.Image != nil {
		t.Fatal("image view must be empty for an added file")
	}
}

func TestFromUpperModified(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.base, "opt/app/config"), "original")
	mustWrite(t, filepath.Join(f.upper, "opt/app/config"), "tampered")

	out := f.explain(t, "/opt/app/config")
	if out.Verdict != model.VerdictFromUpperModified {
		t.Fatalf("verdict = %s, want from_upper_modified", out.Verdict)
	}
}

func TestCopyUpUnchangedIsNotAModification(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.base, "opt/app/config"), "same")
	mustWrite(t, filepath.Join(f.upper, "opt/app/config"), "same")

	out := f.explain(t, "/opt/app/config")
	if out.Verdict != model.VerdictFromUpperCopyUpSame {
		t.Fatalf("verdict = %s, want from_upper_copyup_unchanged", out.Verdict)
	}
	if out.Visible.SHA256 != out.Image.SHA256 {
		t.Fatal("content digests must match")
	}
}

func TestDeletedByWhiteout(t *testing.T) {
	f := newFixture(t)
	mustMkdir(t, filepath.Join(f.upper, "etc"))
	shadow := filepath.Join(f.upper, "etc/shadow")
	mustWrite(t, shadow, "")
	if err := xattr.Set(shadow, "user.overlay.whiteout", []byte("y")); err != nil {
		t.Skipf("extended attributes unsupported here: %v", err)
	}

	out := f.explain(t, "/etc/shadow")
	if out.Verdict != model.VerdictDeletedByWhiteout {
		t.Fatalf("verdict = %s, want deleted_by_whiteout", out.Verdict)
	}
	if out.Visible != nil {
		t.Fatal("visible must be nil for a deleted path")
	}
}

func TestSymlinkRedirect(t *testing.T) {
	f := newFixture(t)
	mustMkdir(t, filepath.Join(f.base, "opt"))
	if err := os.Symlink("/etc/passwd", filepath.Join(f.base, "opt/link")); err != nil {
		t.Fatal(err)
	}

	out := f.explain(t, "/opt/link")
	if out.Verdict != model.VerdictFromImageLayer {
		t.Fatalf("verdict = %s, want from_image_layer after redirect", out.Verdict)
	}
	if out.Visible.Logical != "/etc/passwd" {
		t.Fatalf("logical = %s, want /etc/passwd", out.Visible.Logical)
	}

	var sawSymlink bool
	for _, s := range out.Trace {
		if s.Kind == model.StepSymlink {
			sawSymlink = true
		}
	}
	if !sawSymlink {
		t.Fatal("trace must record the symlink hop")
	}
}

func TestIncompleteWhenUpperNotCaptured(t *testing.T) {
	f := newFixture(t)
	if err := os.RemoveAll(f.upper); err != nil {
		t.Fatal(err)
	}

	out := f.explain(t, "/etc/passwd")
	if out.Verdict != model.VerdictUnknownInsufficient {
		t.Fatalf("verdict = %s, want unknown_insufficient_evidence", out.Verdict)
	}
	if len(out.Missing) == 0 {
		t.Fatal("missing evidence must be reported")
	}
}

func TestMountWithoutTheFile(t *testing.T) {
	f := newFixture(t)
	out := f.explain(t, "/usr/bin/absent")

	if out.Verdict != model.VerdictAbsent || out.VisibleState != model.PathAbsent || out.Incomplete || len(out.Missing) != 0 {
		t.Fatalf("complete mount absence was not established: %+v", out)
	}
}

func TestClaimsAlwaysReferenceFacts(t *testing.T) {
	f := newFixture(t)
	out := f.explain(t, "/usr/bin/helper")

	known := make(map[string]struct{}, len(out.Facts))
	for _, fact := range out.Facts {
		known[fact.ID] = struct{}{}
	}
	if len(out.Claims) == 0 {
		t.Fatal("expected at least one claim")
	}
	for _, c := range out.Claims {
		if len(c.DependsOn) == 0 {
			t.Fatalf("claim %q has no evidence", c.Kind)
		}
		for _, id := range c.DependsOn {
			if _, ok := known[id]; !ok {
				t.Fatalf("claim %q references unknown fact %s", c.Kind, id)
			}
		}
	}
}

func TestReportIsDeterministic(t *testing.T) {
	build := func() []byte {
		f := newFixture(t)
		// Equal cases include equal metadata, not just equal file bytes.
		fixed := time.Unix(1700000000, 123456789)
		for _, file := range []string{filepath.Join(f.bind, "helper"), filepath.Join(f.base, "usr/bin/helper")} {
			if err := os.Chtimes(file, fixed, fixed); err != nil {
				t.Fatal(err)
			}
		}
		out := f.explain(t, "/usr/bin/helper")
		rep := &model.Report{
			Schema:      model.SchemaReport,
			Path:        "/usr/bin/helper",
			Verdict:     out.Verdict,
			Explanation: out.Explanation,
			Visible:     out.Visible,
			Image:       out.Image,
			Trace:       out.Trace,
			Facts:       out.Facts,
			Claims:      out.Claims,
			Missing:     out.Missing,
		}
		if err := rep.Seal(); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	first := build()
	second := build()
	if string(first) != string(second) {
		t.Fatalf("reports differ:\n%s\n%s", first, second)
	}
}
