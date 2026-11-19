package overlay

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/xattr"
)

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

func setXattrOrSkip(t *testing.T, name, key string, val []byte) {
	t.Helper()
	if err := xattr.Set(name, key, val); err != nil {
		t.Skipf("extended attributes unsupported here: %v", err)
	}
}

func TestLookupFindsImageLayer(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	mustWrite(t, filepath.Join(base, "usr/bin/helper"), "A")
	mustWrite(t, filepath.Join(upper, "etc/hostname"), "x")

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: upper, Upper: true},
	}}

	res, err := s.Lookup("/usr/bin/helper")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateFound {
		t.Fatalf("state = %v, want found", res.State)
	}
	if res.Entry.Layer != 0 {
		t.Fatalf("layer = %d, want 0", res.Entry.Layer)
	}
	if res.Entry.Kind != KindFile {
		t.Fatalf("kind = %v, want file", res.Entry.Kind)
	}
	if res.Incomplete {
		t.Fatal("unexpected incomplete result")
	}
}

func TestLookupUpperWins(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	mustWrite(t, filepath.Join(base, "usr/bin/helper"), "A")
	mustWrite(t, filepath.Join(upper, "usr/bin/helper"), "B")

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: upper, Upper: true},
	}}

	res, err := s.Lookup("/usr/bin/helper")
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Layer != 1 {
		t.Fatalf("layer = %d, want upper", res.Entry.Layer)
	}
	got, err := os.ReadFile(res.Entry.HostPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "B" {
		t.Fatalf("content = %q, want B", got)
	}
}

func TestLookupWhiteoutHidesLower(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	mustWrite(t, filepath.Join(base, "usr/bin/helper"), "A")
	wh := filepath.Join(upper, "usr/bin/helper")
	mustWrite(t, wh, "")
	setXattrOrSkip(t, wh, "user.overlay.whiteout", []byte("y"))

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: upper, Upper: true},
	}}

	res, err := s.Lookup("/usr/bin/helper")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateDeleted {
		t.Fatalf("state = %v, want deleted", res.State)
	}
	if res.DeletedBy.Layer != 1 {
		t.Fatalf("deleted in layer %d, want 1", res.DeletedBy.Layer)
	}
}

func TestLookupOpaqueDirHidesLowerEntries(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	mustWrite(t, filepath.Join(base, "etc/passwd"), "root:x:0:0")
	mustWrite(t, filepath.Join(base, "etc/shadow"), "secret")
	opaque := filepath.Join(upper, "etc")
	mustMkdir(t, opaque)
	mustWrite(t, filepath.Join(opaque, "hostname"), "h")
	setXattrOrSkip(t, opaque, "user.overlay.opaque", []byte("y"))

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: upper, Upper: true},
	}}

	res, err := s.Lookup("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateDeleted || !res.DeletedBy.Opaque {
		t.Fatalf("state = %v, want hidden by opaque parent", res.State)
	}

	res, err = s.Lookup("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateFound || res.Entry.Layer != 1 {
		t.Fatalf("hostname: state=%v layer=%d", res.State, res.Entry.Layer)
	}
}

func TestLookupExtractedLayerMarkers(t *testing.T) {
	base := t.TempDir()
	extracted := t.TempDir()

	mustWrite(t, filepath.Join(base, "bin/tool"), "A")
	mustWrite(t, filepath.Join(extracted, "bin/.wh.tool"), "")

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: extracted, Extracted: true},
	}}

	res, err := s.Lookup("/bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateDeleted {
		t.Fatalf("state = %v, want deleted", res.State)
	}
}

func TestLookupReportsIncompleteWhenLayerMissing(t *testing.T) {
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "bin/tool"), "A")

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{
		{Index: 0, Root: base},
		{Index: 1, Root: filepath.Join(t.TempDir(), "absent"), Missing: true, Upper: true},
	}}

	res, err := s.Lookup("/bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateFound {
		t.Fatalf("state = %v, want found", res.State)
	}
	if !res.Incomplete {
		t.Fatal("a missing upper layer must mark the result incomplete")
	}
}

func TestLookupRoot(t *testing.T) {
	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{{Index: 0, Root: t.TempDir()}}}
	res, err := s.Lookup("/")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateFound || res.Entry.Kind != KindDir {
		t.Fatalf("root: state=%v kind=%v", res.State, res.Entry.Kind)
	}
}

func TestLookupEmptyStack(t *testing.T) {
	if _, err := (Stack{}).Lookup("/x"); err == nil {
		t.Fatal("expected an error for an empty stack")
	}
}

func TestSymlinkEntry(t *testing.T) {
	base := t.TempDir()
	mustMkdir(t, filepath.Join(base, "usr/bin"))
	if err := os.Symlink("/opt/real", filepath.Join(base, "usr/bin/tool")); err != nil {
		t.Fatal(err)
	}

	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{{Index: 0, Root: base}}}
	res, err := s.Lookup("/usr/bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Kind != KindSymlink || res.Entry.LinkTarget != "/opt/real" {
		t.Fatalf("kind=%v target=%q", res.Entry.Kind, res.Entry.LinkTarget)
	}
}
