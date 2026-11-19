package casefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerAliasReadAsData(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "escape", "wrong-target", "non-link", "physical-layer-link", "missing-root", "mixed-runtime"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			id := strings.Repeat("a", 64)
			alias := strings.Repeat("A", 26)
			lower := "/docker/overlay2/l/" + alias
			upper := "/docker/overlay2/upper/diff"
			write(t, root, "host"+lower+"/tool", "captured bytes")
			if err := os.MkdirAll(filepath.Join(root, "host"+upper), 0700); err != nil {
				t.Fatal(err)
			}
			write(t, root, "mountinfo", "10 1 0:1 / / rw - overlay overlay rw,lowerdir="+lower+",upperdir="+upper+",userxattr\n")
			write(t, root, "inspect.json", `[{"Id":"`+id+`","Image":"sha256:`+strings.Repeat("b", 64)+`","GraphDriver":{"Name":"overlay2","Data":{"LowerDir":"/docker/overlay2/base/diff","UpperDir":"`+upper+`"}},"Config":{"Image":"fixture"}}]`)
			if err := os.Mkdir(filepath.Join(root, "links"), 0700); err != nil {
				t.Fatal(err)
			}
			target := "../base/diff"
			if kind == "escape" {
				target = "../../../../outside"
			}
			if kind == "wrong-target" {
				target = "../other/diff"
			}
			link := filepath.Join(root, "links", alias)
			if kind == "non-link" {
				write(t, root, "links/"+alias, target)
			} else if kind != "missing" {
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			manifest := map[string]any{"schema": SchemaCase, "mountinfo": "mountinfo", "container_id": id, "docker_inspect": "inspect.json", "docker_alias_root": "links"}
			if kind == "missing-root" {
				delete(manifest, "docker_alias_root")
			}
			if kind == "mixed-runtime" {
				manifest["containerd_metadata"] = "meta.db"
			}
			b, _ := json.Marshal(manifest)
			write(t, root, "case.json", string(b))
			c, err := Open(root)
			if kind == "mixed-runtime" {
				if err == nil {
					t.Fatal("mixed runtimes accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "physical-layer-link" {
				path := filepath.Join(root, "host"+lower)
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
				table, err := c.MountTable()
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := c.Stack(table); err == nil {
					t.Fatal("followed materialised layer address as physical symlink")
				}
				return
			}
			identity, err := c.Identity()
			if kind != "valid" {
				if err == nil {
					t.Fatal("accepted invalid alias evidence")
				}
				return
			}
			if err != nil || identity.Runtime != "docker" || len(identity.DockerAliases) != 1 || identity.DockerAliases[0].Target != "../base/diff" {
				t.Fatalf("alias consistency: %+v %v", identity, err)
			}
			// There is intentionally NO host/docker/overlay2/base/diff. The link is
			// checked lexically as evidence; neither it nor a host target is followed.
		})
	}
}
