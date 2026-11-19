package mounts

import (
	"strings"
	"testing"
)

func TestOvermountHidesChildrenOfOlderMount(t *testing.T) {
	input := `1 0 0:1 / / rw - overlay overlay rw,lowerdir=/base
2 1 0:2 / /data rw - tmpfs old rw
3 2 0:3 / /data/nested rw - tmpfs hidden rw
4 2 0:4 / /data rw - tmpfs top rw
`
	table, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	e, _, err := table.Select("/data/nested/file")
	if err != nil || e.ID != 4 {
		t.Fatalf("selected hidden child: %d %v", e.ID, err)
	}
}

func TestAmbiguousSiblingMountsFailClosed(t *testing.T) {
	input := `1 0 0:1 / / rw - overlay overlay rw,lowerdir=/base
2 1 0:2 / /data rw - tmpfs a rw
3 1 0:3 / /data rw - tmpfs b rw
`
	table, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := table.Select("/data/file"); err == nil {
		t.Fatal("guessed stacking order")
	}
}

func FuzzMountinfo(f *testing.F) {
	f.Add(sample)
	f.Add("1 0 0:1 / / rw - tmpfs tmpfs rw\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		table, err := Parse(strings.NewReader(input))
		if err != nil {
			return
		}
		_, _, _ = table.Select("/etc/passwd")
	})
}
