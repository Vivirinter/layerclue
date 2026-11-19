package overlay

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

func TestUpperDirectorySurvivesLowerFileBarrier(t *testing.T) {
	base, middle, upper := t.TempDir(), t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(base, "dir/hidden"), "must stay hidden")
	mustWrite(t, filepath.Join(middle, "dir"), "file barrier")
	mustWrite(t, filepath.Join(upper, "dir/visible"), "visible")
	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{{Index: 0, Root: base}, {Index: 1, Root: middle}, {Index: 2, Root: upper, Upper: true}}}
	res, err := s.Lookup("/dir/visible")
	if err != nil || res.State != StateFound || res.Entry.Layer != 2 {
		t.Fatalf("lost upper directory: %+v %v", res, err)
	}
	res, err = s.Lookup("/dir/hidden")
	if err != nil || res.State == StateFound {
		t.Fatalf("merged through lower file barrier: %+v %v", res, err)
	}
}

func TestInactiveUserAttributesAreNotOverlayMarkers(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "file")
	mustWrite(t, name, "")
	setXattrOrSkip(t, name, "user.overlay.whiteout", []byte("y"))
	s := Stack{AttrPrefix: "user.layerclue.overlay.", Layers: []Layer{{Root: root}}}
	res, err := s.Lookup("/file")
	if err != nil || res.State != StateFound {
		t.Fatalf("used inactive attribute namespace: %+v %v", res, err)
	}
	setXattrOrSkip(t, name, "user.layerclue.overlay.whiteout", []byte{})
	res, err = s.Lookup("/file")
	if err != nil || res.State != StateDeleted {
		t.Fatalf("ignored exported empty whiteout marker: %+v %v", res, err)
	}
}

func TestUnreadableTrustedMetadataFailsClosed(t *testing.T) {
	if evidence.CanReadTrusted() {
		t.Skip("environment has trusted-attribute capability")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file"), "x")
	s := Stack{Layers: []Layer{{Root: root}}}
	if _, err := s.Lookup("/file"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("trusted absence was guessed: %v", err)
	}
}

func TestOpaqueLayerRootHidesLowerChildren(t *testing.T) {
	base, upper := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(base, "file"), "hidden")
	setXattrOrSkip(t, upper, "user.overlay.opaque", []byte("y"))
	s := Stack{AttrPrefix: "user.overlay.", Layers: []Layer{{Index: 0, Root: base}, {Index: 1, Root: upper, Upper: true}}}
	res, err := s.Lookup("/file")
	if err != nil || res.State != StateDeleted || !res.DeletedBy.Opaque {
		t.Fatalf("ignored opaque layer root: %+v %v", res, err)
	}
}
