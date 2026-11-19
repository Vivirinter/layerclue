package casefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDiscoversMountinfo(t *testing.T) {
	root := t.TempDir()
	write(t, root, "host/proc/77/mountinfo", "1 0 0:1 / / rw - tmpfs t rw\n")

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.MountinfoRef != "host/proc/77/mountinfo" {
		t.Fatalf("mountinfo ref = %q", c.MountinfoRef)
	}
	if c.HostRoot != filepath.Join(root, "host") {
		t.Fatalf("host root = %q", c.HostRoot)
	}
}

func TestOpenRequiresMountinfo(t *testing.T) {
	root := t.TempDir()
	_, err := Open(root)
	if !errors.Is(err, ErrNoMountinfo) {
		t.Fatalf("err = %v, want ErrNoMountinfo", err)
	}
}

func TestStackOrderIsBottomFirst(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"host/lower-top", "host/lower-bottom", "host/upper",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, root, "host/proc/1/mountinfo",
		"10 1 0:9 / / rw - overlay overlay rw,"+
			"lowerdir=/lower-top:/lower-bottom,upperdir=/upper,workdir=/work\n")

	c, err := Open(root)
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
	if stack.Len() != 3 {
		t.Fatalf("layers = %d, want 3", stack.Len())
	}
	if !strings.HasSuffix(stack.Layers[0].Root, "lower-bottom") {
		t.Fatalf("bottom layer = %q, want lower-bottom", stack.Layers[0].Root)
	}
	if !strings.HasSuffix(stack.Layers[1].Root, "lower-top") {
		t.Fatalf("middle layer = %q, want lower-top", stack.Layers[1].Root)
	}
	if !stack.Layers[2].Upper {
		t.Fatal("top layer must be the writable layer")
	}
}

func TestStackKeepsMissingLayers(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "host/upper"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "host/proc/1/mountinfo",
		"10 1 0:9 / / rw - overlay overlay rw,lowerdir=/absent,upperdir=/upper\n")

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	table, err := c.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	stack, missing, err := c.Stack(table)
	if err != nil {
		t.Fatal(err)
	}
	if stack.Len() != 2 {
		t.Fatalf("layers = %d, want 2 (a missing layer must not be dropped)", stack.Len())
	}
	if !stack.Layers[0].Missing {
		t.Fatal("lower layer must be marked missing")
	}
	if len(missing) != 1 || missing[0] != "/absent" {
		t.Fatalf("missing = %v", missing)
	}
}

func TestNoOverlayMount(t *testing.T) {
	root := t.TempDir()
	write(t, root, "host/proc/1/mountinfo", "1 0 0:1 / / rw - tmpfs t rw\n")

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	table, err := c.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Stack(table); !errors.Is(err, ErrNoOverlay) {
		t.Fatalf("err = %v, want ErrNoOverlay", err)
	}
}
