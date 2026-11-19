package mounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
23 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
120 100 0:52 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/5/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/work
121 120 8:1 /vol/empty\040dir /usr/bin rw,relatime shared:9 - ext4 /dev/sda1 rw
122 121 0:30 / /usr/bin/nested\040place rw,relatime - tmpfs tmpfs rw
`

func TestParseFieldsAndEscapes(t *testing.T) {
	table, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(table) != 5 {
		t.Fatalf("got %d entries, want 5", len(table))
	}

	ov := table[2]
	if ov.FSType != "overlay" {
		t.Fatalf("fstype = %q, want overlay", ov.FSType)
	}
	if ov.Point != "/" {
		t.Fatalf("point = %q, want /", ov.Point)
	}
	lowers := ov.LowerDirs()
	if len(lowers) != 2 {
		t.Fatalf("got %d lowers, want 2", len(lowers))
	}
	if !strings.HasSuffix(lowers[0], "/snapshots/7/fs") {
		t.Fatalf("top lower = %q, want snapshot 7", lowers[0])
	}
	if got := ov.SuperValue("upperdir"); !strings.HasSuffix(got, "/snapshots/9/fs") {
		t.Fatalf("upperdir = %q", got)
	}

	bind := table[3]
	if bind.Point != "/usr/bin" {
		t.Fatalf("bind point = %q, want /usr/bin", bind.Point)
	}
	if bind.Root != "/vol/empty dir" {
		t.Fatalf("bind root = %q, want decoded space", bind.Root)
	}

	spaced := table[4]
	if spaced.Point != "/usr/bin/nested place" {
		t.Fatalf("spaced point = %q", spaced.Point)
	}
}

func TestUnescape(t *testing.T) {
	cases := map[string]string{
		`plain`:         `plain`,
		`a\040b`:        `a b`,
		`tab\011here`:   `tab	here`,
		`back\134slash`: `back\slash`,
		`trailing\`:     `trailing\`,
		`not\09`:        `not\09`,
		`\040leading`:   ` leading`,
	}
	for in, want := range cases {
		if got := Unescape(in); got != want {
			t.Errorf("Unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeepest(t *testing.T) {
	table, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}

	e, rel, ok := table.Deepest("/usr/bin/helper")
	if !ok {
		t.Fatal("no mount found")
	}
	if e.Point != "/usr/bin" {
		t.Fatalf("point = %q, want /usr/bin", e.Point)
	}
	if rel != "/helper" {
		t.Fatalf("rel = %q, want /helper", rel)
	}

	e, rel, ok = table.Deepest("/usr/bin/nested place/x")
	if !ok {
		t.Fatal("no mount found")
	}
	if e.Point != "/usr/bin/nested place" {
		t.Fatalf("point = %q", e.Point)
	}
	if rel != "/x" {
		t.Fatalf("rel = %q, want /x", rel)
	}

	e, rel, ok = table.Deepest("/etc/passwd")
	if !ok || e.Point != "/" || rel != "/etc/passwd" {
		t.Fatalf("root lookup = %q %q %v", e.Point, rel, ok)
	}
}

func TestDeepestUsesMountTopologyInsteadOfLineOrder(t *testing.T) {
	const tie = `1 0 0:9 / / rw - overlay overlay rw,lowerdir=/base
11 10 0:2 / /data rw - tmpfs second rw
10 1 0:1 / /data rw - tmpfs first rw
`
	table, err := Parse(strings.NewReader(tie))
	if err != nil {
		t.Fatal(err)
	}
	e, _, ok := table.Deepest("/data/file")
	if !ok {
		t.Fatal("no mount")
	}
	if e.Source != "second" {
		t.Fatalf("source = %q, want second (topologically above first)", e.Source)
	}
}

func TestParseFileAndMalformed(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(name, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := ParseFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(table) != 5 {
		t.Fatalf("got %d entries", len(table))
	}

	if _, err := Parse(strings.NewReader("1 2 3\n")); err == nil {
		t.Fatal("expected malformed line to fail")
	}
}
