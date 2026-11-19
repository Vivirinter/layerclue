package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/mounts"
)

func sample() Record {
	var r Record
	r.ID = strings.Repeat("a", 64)
	r.Image = "sha256:" + strings.Repeat("b", 64)
	r.Config.Image = "example:tag"
	r.GraphDriver.Name = "overlay2"
	r.GraphDriver.Data = map[string]string{"UpperDir": "/docker/upper/diff", "LowerDir": "/docker/l/top:/docker/l/base"}
	r.Mounts = []Mount{{Type: "bind", Source: "/host/data", Destination: "/data"}}
	return r
}

func TestLayerLimitIncludesWritableUpper(t *testing.T) {
	for _, count := range []int{255, 256} {
		r := sample()
		var lower []string
		for i := 0; i < count; i++ {
			lower = append(lower, fmt.Sprintf("/docker/l/layer-%d", i))
		}
		r.GraphDriver.Data["LowerDir"] = strings.Join(lower, ":")
		data, err := json.Marshal([]Record{r})
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "inspect.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Read(root, "inspect.json", r.ID)
		if count == 255 && err != nil {
			t.Fatal(err)
		}
		if count == 256 && !errors.Is(err, evidence.ErrLimit) {
			t.Fatalf("accepted 257 total stack positions: %v", err)
		}
	}
}
func TestReadAndStack(t *testing.T) {
	root := t.TempDir()
	r := sample()
	b, _ := json.Marshal([]Record{r})
	if err := os.WriteFile(filepath.Join(root, "inspect.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root, "inspect.json", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 == "" {
		t.Fatal("no source checksum")
	}
	table, err := mounts.Parse(strings.NewReader("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/docker/l/top:/docker/l/base,upperdir=/docker/upper/diff\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckStack(table[0]); err != nil {
		t.Fatal(err)
	}
	table[0].SuperOptions = []string{"rw", "lowerdir=/docker/l/base:/docker/l/top", "upperdir=/docker/upper/diff"}
	if err := got.CheckStack(table[0]); err == nil {
		t.Fatal("accepted swapped lower order")
	}
}
func TestRejectInvalidInspect(t *testing.T) {
	for _, tc := range []string{"wrong_id", "short_id", "driver", "relative", "duplicate_mount", "multiple", "duplicate_json", "image"} {
		t.Run(tc, func(t *testing.T) {
			root := t.TempDir()
			r := sample()
			id := r.ID
			switch tc {
			case "wrong_id":
				r.ID = strings.Repeat("c", 64)
			case "short_id":
				id = id[:12]
			case "driver":
				r.GraphDriver.Name = "btrfs"
			case "relative":
				r.GraphDriver.Data["UpperDir"] = "../../host"
			case "duplicate_mount":
				r.Mounts = append(r.Mounts, r.Mounts[0])
			case "image":
				r.Image = "not-a-digest"
			}
			list := []Record{r}
			if tc == "multiple" {
				list = append(list, r)
			}
			b, _ := json.Marshal(list)
			if tc == "duplicate_json" {
				b = []byte(`[{"Id":"a","Id":"b"}]`)
			}
			if err := os.WriteFile(filepath.Join(root, "inspect.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(root, "inspect.json", id); err == nil {
				t.Fatal("accepted invalid inspect")
			}
		})
	}
}
func FuzzInspect(f *testing.F) {
	b, _ := json.Marshal([]Record{sample()})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "inspect.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = Read(root, "inspect.json", strings.Repeat("a", 64))
	})
}
