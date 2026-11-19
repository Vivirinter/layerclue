package containerd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func buildDB(t *testing.T, path string, fill func(tx *bolt.Tx) error) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(fill); err != nil {
		t.Fatal(err)
	}
}

// syntheticLayout reproduces the bucket shape using only invented identities.
func syntheticLayout(tx *bolt.Tx) error {
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
	c, err := containers.CreateBucket([]byte("3333333333333333333333333333333333333333333333333333333333333333"))
	if err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"image", "example.invalid/fixture-web:test"},
		{"snapshotter", "overlayfs"},
		{"snapshotKey", "3333333333333333333333333333333333333333333333333333333333333333"},
	} {
		if err := c.Put([]byte(kv[0]), []byte(kv[1])); err != nil {
			return err
		}
	}
	labels, err := c.CreateBucket([]byte("labels"))
	if err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"io.kubernetes.pod.name", "fixture-web"},
		{"io.kubernetes.pod.namespace", "fixture-ns"},
		{"io.kubernetes.pod.uid", "00000000-0000-4000-8000-000000000001"},
	} {
		if err := labels.Put([]byte(kv[0]), []byte(kv[1])); err != nil {
			return err
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
	if err := target.Put([]byte("digest"), []byte("sha256:5555555555555555555555555555555555555555555555555555555555555555")); err != nil {
		return err
	}
	return target.Put([]byte("mediatype"), []byte("application/vnd.oci.image.manifest.v1+json"))
}

func TestReadsSyntheticLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	buildDB(t, path, syntheticLayout)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	namespaces, err := store.Namespaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 1 || namespaces[0] != "k8s.io" {
		t.Fatalf("namespaces = %v", namespaces)
	}

	list, err := store.Containers("k8s.io")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("containers = %d, want 1", len(list))
	}
	c := list[0]
	if c.Image != "example.invalid/fixture-web:test" {
		t.Fatalf("image = %q", c.Image)
	}
	if c.Snapshotter != "overlayfs" || c.SnapshotKey == "" {
		t.Fatalf("snapshotter=%q key=%q", c.Snapshotter, c.SnapshotKey)
	}
	name, namespace, uid := c.Pod()
	if name == "" || namespace != "fixture-ns" || uid == "" {
		t.Fatalf("pod = %q %q %q", name, namespace, uid)
	}

	one, err := store.Container("k8s.io", c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if one.ID != c.ID {
		t.Fatalf("container id = %q", one.ID)
	}

	img, err := store.Image("k8s.io", "example.invalid/fixture-web:test")
	if err != nil {
		t.Fatal(err)
	}
	if img.Digest != "sha256:5555555555555555555555555555555555555555555555555555555555555555" {
		t.Fatalf("image digest = %q", img.Digest)
	}
}

func TestMissingContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	buildDB(t, path, syntheticLayout)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.Container("k8s.io", "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := store.Container("absent-ns", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestProtobufLayoutIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	buildDB(t, path, func(tx *bolt.Tx) error {
		root, _ := tx.CreateBucketIfNotExists([]byte("v1"))
		ns, _ := root.CreateBucketIfNotExists([]byte("default"))
		containers, _ := ns.CreateBucketIfNotExists([]byte("containers"))
		return containers.Put([]byte("abc"), []byte{0x0a, 0x03, 'a', 'b', 'c'})
	})

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.Containers("default"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("err = %v, want ErrUnsupportedFormat", err)
	}
}

func TestOpenDoesNotTouchTheOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	buildDB(t, path, syntheticLayout)

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	temp := store.temp
	if temp == "" {
		t.Fatal("Open must work on a copy")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("the temporary copy must be removed on Close")
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("the original database was modified")
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected garbage to be rejected")
	}
}
