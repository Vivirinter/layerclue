package casefile

import (
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// These identities are invented fixtures, never values copied from a capture.
const nginxID = "2222222222222222222222222222222222222222222222222222222222222222"
const pauseID = "1111111111111111111111111111111111111111111111111111111111111111"

func buildMetadata(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte("v1"))
		if err != nil {
			return err
		}
		ns, err := root.CreateBucketIfNotExists([]byte("k8s.io"))
		if err != nil {
			return err
		}
		containers, err := ns.CreateBucketIfNotExists([]byte("containers"))
		if err != nil {
			return err
		}
		for _, c := range []struct {
			id, image, pod string
		}{
			{nginxID, "example.invalid/fixture-web:test", "fixture-web"},
			{pauseID, "example.invalid/fixture-pause:test", ""},
		} {
			b, err := containers.CreateBucket([]byte(c.id))
			if err != nil {
				return err
			}
			if err := b.Put([]byte("image"), []byte(c.image)); err != nil {
				return err
			}
			if err := b.Put([]byte("snapshotter"), []byte("overlayfs")); err != nil {
				return err
			}
			if err := b.Put([]byte("snapshotKey"), []byte(c.id)); err != nil {
				return err
			}
			labels, err := b.CreateBucket([]byte("labels"))
			if err != nil {
				return err
			}
			if c.pod != "" {
				if err := labels.Put([]byte("io.kubernetes.pod.name"), []byte(c.pod)); err != nil {
					return err
				}
				if err := labels.Put([]byte("io.kubernetes.pod.namespace"), []byte("fixture-ns")); err != nil {
					return err
				}
			}
		}

		images, err := ns.CreateBucketIfNotExists([]byte("images"))
		if err != nil {
			return err
		}
		img, err := images.CreateBucket([]byte("example.invalid/fixture-web:test"))
		if err != nil {
			return err
		}
		target, err := img.CreateBucket([]byte("target"))
		if err != nil {
			return err
		}
		return target.Put([]byte("digest"), []byte("sha256:4444444444444444444444444444444444444444444444444444444444444444"))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeCase(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "host/proc/1/mountinfo", "10 1 0:9 / / rw - overlay overlay rw,lowerdir=/l,upperdir=/u\n")
	if err := os.MkdirAll(filepath.Join(root, "host/l"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "host/u"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildMetadata(t, filepath.Join(root, "containerd", "meta.db"))
	for name, body := range extra {
		write(t, root, name, body)
	}
	return root
}

func TestIdentityResolvesNamedContainer(t *testing.T) {
	root := writeCase(t, map[string]string{
		"case.json": `{"schema":"layerclue.case/v1","containerd_metadata":"containerd/meta.db","container_id":"` + nginxID + `"}`,
	})

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.MetadataRef != "containerd/meta.db" {
		t.Fatalf("metadata ref = %q", c.MetadataRef)
	}

	id, err := c.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("identity is nil")
	}
	if id.ContainerID != nginxID {
		t.Fatalf("container = %q", id.ContainerID)
	}
	if id.ImageRef != "example.invalid/fixture-web:test" {
		t.Fatalf("image = %q", id.ImageRef)
	}
	if id.ImageDigest != "sha256:4444444444444444444444444444444444444444444444444444444444444444" {
		t.Fatalf("digest = %q", id.ImageDigest)
	}
	if id.PodName != "fixture-web" || id.PodNamespace != "fixture-ns" {
		t.Fatalf("pod = %q/%q", id.PodNamespace, id.PodName)
	}
}

func TestIdentityReportsAmbiguity(t *testing.T) {
	root := writeCase(t, nil)

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("identity is nil")
	}
	if id.ContainerID != "" {
		t.Fatalf("an ambiguous case must not pick a container, got %q", id.ContainerID)
	}
	if len(id.Candidates) != 2 {
		t.Fatalf("candidates = %v", id.Candidates)
	}
}

func TestIdentityIsNilWithoutMetadata(t *testing.T) {
	root := t.TempDir()
	write(t, root, "host/proc/1/mountinfo", "10 1 0:9 / / rw - overlay overlay rw,lowerdir=/l\n")
	if err := os.MkdirAll(filepath.Join(root, "host/l"), 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata != "" {
		t.Fatalf("unexpected metadata at %q", c.Metadata)
	}
	id, err := c.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if id != nil {
		t.Fatalf("identity = %+v, want nil", id)
	}
}

func TestMetadataIsDiscovered(t *testing.T) {
	root := t.TempDir()
	write(t, root, "host/proc/1/mountinfo", "10 1 0:9 / / rw - overlay overlay rw,lowerdir=/l\n")
	if err := os.MkdirAll(filepath.Join(root, "host/l"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildMetadata(t, filepath.Join(root, "evidence", "containerd", "meta.db"))

	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.MetadataRef != "evidence/containerd/meta.db" {
		t.Fatalf("metadata ref = %q", c.MetadataRef)
	}
}
