package resolve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/xattr"
)

func TestReadOnlyLowerIsNotWritable(t *testing.T) {
	f := newFixture(t)
	r := f.resolver(t)
	r.opts.Stack = r.imageStack()
	out, err := r.Resolve("/etc/passwd")
	if err != nil || out.Verdict != model.VerdictFromImageLayer {
		t.Fatalf("lower-only: %+v %v", out, err)
	}
}

func TestUncapturedFileMountIsUnknown(t *testing.T) {
	f := newFixture(t)
	r := f.resolver(t)
	r.opts.Mounts = append(r.opts.Mounts, mounts.Entry{ID: 122, ParentID: 120, Point: "/etc/passwd", Root: "/file", Source: "/dev/synthetic", FSType: "ext4"})
	out, err := r.Resolve("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != model.VerdictUnknownInsufficient || !out.Incomplete || len(out.Missing) == 0 || out.Visible != nil {
		t.Fatalf("unsupported confidence: %+v", out)
	}
}

func TestMountSourceIsNotTreatedAsHostPath(t *testing.T) {
	f := newFixture(t)
	r := f.resolver(t)
	r.opts.MountSources = nil
	out, err := r.Resolve("/usr/bin/helper")
	if err != nil {
		t.Fatal(err)
	}
	if out.Visible != nil || out.Verdict != model.VerdictUnknownInsufficient {
		t.Fatalf("guessed mount source: %+v", out)
	}
}

func TestSymlinkDotDotUsesResolvedTarget(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.base, "one/result"), "wrong")
	mustWrite(t, filepath.Join(f.base, "two/result"), "correct")
	mustMkdir(t, filepath.Join(f.base, "two/nested"))
	if err := os.Symlink("/two/nested", filepath.Join(f.base, "one/link")); err != nil {
		t.Fatal(err)
	}
	out := f.explain(t, "/one/link/../result")
	if out.Visible == nil || out.Visible.SHA256 != digest("correct") || out.Visible.Logical != "/two/result" {
		t.Fatalf("cleaned path before symlink expansion: %+v", out)
	}
}

func TestMissingUpperCannotProveLowerWhiteout(t *testing.T) {
	f := newFixture(t)
	name := filepath.Join(f.base, "etc/shadow")
	mustWrite(t, name, "")
	if err := xattr.Set(name, "user.overlay.whiteout", []byte{}); err != nil {
		t.Skip(err)
	}
	if err := os.RemoveAll(f.upper); err != nil {
		t.Fatal(err)
	}
	out := f.explain(t, "/etc/shadow")
	if out.Verdict != model.VerdictUnknownInsufficient || !out.Incomplete {
		t.Fatalf("claimed deletion despite missing upper: %+v", out)
	}
}

func TestMetacopyFailsClosed(t *testing.T) {
	f := newFixture(t)
	name := filepath.Join(f.upper, "etc/passwd")
	mustWrite(t, name, "")
	if err := xattr.Set(name, "user.overlay.metacopy", []byte{}); err != nil {
		t.Skip(err)
	}
	out := f.explain(t, "/etc/passwd")
	if out.Verdict != model.VerdictUnsupportedFeature || !out.Incomplete {
		t.Fatalf("guessed metacopy data: %+v", out)
	}
}

func TestHashBudget(t *testing.T) {
	f := newFixture(t)
	r := f.resolver(t)
	r.opts.MaxFileBytes = 1
	if _, err := r.Resolve("/etc/passwd"); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("unbounded hash: %v", err)
	}
}

func TestCancellation(t *testing.T) {
	f := newFixture(t)
	r := f.resolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.opts.Context = ctx
	if _, err := r.Resolve("/etc/passwd"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
}

func TestImageViewFollowsItsOwnSymlinks(t *testing.T) {
	f := newFixture(t)
	mustMkdir(t, filepath.Join(f.base, "links"))
	if err := os.Symlink("/etc/passwd", filepath.Join(f.base, "links/passwd")); err != nil {
		t.Fatal(err)
	}
	out := f.explain(t, "/links/passwd")
	if out.Image == nil || out.Image.SHA256 != digest("root:x:0:0") {
		t.Fatalf("lower symlink not resolved: %+v", out)
	}
}
