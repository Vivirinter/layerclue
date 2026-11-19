package mounts

import (
	"strings"
	"testing"
)

// The fixture preserves a captured Linux mount-table topology. Opaque path,
// mount/device/namespace IDs and source labels are synthetic, not host identity.
func TestParseSanitizedOverlayMountinfo(t *testing.T) {
	table, err := ParseFile("testdata/sanitized_overlay_mountinfo")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(table) != 71 {
		t.Fatalf("parsed %d entries, want 71", len(table))
	}

	root, rel, ok := table.Deepest("/etc/os-release")
	if !ok {
		t.Fatal("no mount covers /etc/os-release")
	}
	if root.Point != "/" {
		t.Fatalf("mount point = %q, want /", root.Point)
	}
	if root.FSType != "overlay" {
		t.Fatalf("fstype = %q, want overlay", root.FSType)
	}
	if rel != "/etc/os-release" {
		t.Fatalf("relative path = %q", rel)
	}

	lowers := root.LowerDirs()
	if len(lowers) != 3 {
		t.Fatalf("lower layers = %d, want 3", len(lowers))
	}
	for i, lower := range lowers {
		if !strings.HasPrefix(lower, "/var/lib/docker/overlay2/l/") {
			t.Fatalf("lower[%d] = %q", i, lower)
		}
	}
	if upper := root.SuperValue("upperdir"); !strings.HasSuffix(upper, "/diff") {
		t.Fatalf("upperdir = %q", upper)
	}
	if root.Line != 1 {
		t.Fatalf("root overlay line = %d, want 1", root.Line)
	}

	// Optional shared-group fields must survive parsing.
	if len(root.Optional) == 0 || !strings.HasPrefix(root.Optional[0], "shared:") {
		t.Fatalf("optional fields = %v", root.Optional)
	}

	proc, rel, ok := table.Deepest("/proc/self/status")
	if !ok || proc.Point != "/proc" || rel != "/self/status" {
		t.Fatalf("proc lookup = %q %q %v", proc.Point, rel, ok)
	}
	if proc.FSType != "proc" {
		t.Fatalf("proc fstype = %q", proc.FSType)
	}

	devpts, rel, ok := table.Deepest("/dev/pts/0")
	if !ok || devpts.Point != "/dev/pts" || rel != "/0" {
		t.Fatalf("devpts lookup = %q %q %v", devpts.Point, rel, ok)
	}
	if devpts.HasOption("nosuid") == false {
		t.Fatal("devpts must carry nosuid")
	}
}

func TestSanitizedMountinfoOverlayCount(t *testing.T) {
	table, err := ParseFile("testdata/sanitized_overlay_mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var overlays int
	for _, e := range table {
		if e.FSType == "overlay" {
			overlays++
		}
	}
	if overlays != 21 {
		t.Fatalf("overlay mounts = %d, want 21", overlays)
	}
}
