// Package testfixture builds synthetic artifacts, never production evidence.
package testfixture

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// Reporter is the minimal failure/temp-directory interface used by tests
// and the explicit synthetic-example generator. No incident data is read.
type Reporter interface {
	Helper()
	Fatal(...any)
	TempDir() string
}

type Layer struct {
	Digest, DiffID, ChainID string
	Raw, Blob               []byte
}
type Image struct {
	Root, ContentRoot, ManifestDigest, ConfigDigest string
	Layers                                          []Layer
}

func Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Write(t Reporter, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func PutBlob(t Reporter, root, content string, data []byte) string {
	t.Helper()
	digest := Sum(data)
	Write(t, filepath.Join(root, content, "blobs/sha256", digest[7:]), data)
	return digest
}

func NewImage(t Reporter, root string, compressed bool) *Image {
	t.Helper()
	image := &Image{Root: root, ContentRoot: "oci"}
	files := [][]struct{ name, body string }{
		{{"etc/app.conf", "base-config\n"}, {"usr/bin/helper", "base-helper\n"}},
		{{"etc/app.conf", "image-config\n"}, {"opt/tool", "image-tool\n"}},
	}
	var diffs []string
	var descriptors []map[string]any
	for i, entries := range files {
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		for _, entry := range entries {
			if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
			Write(t, filepath.Join(root, "host/snapshots", fmt.Sprint(i+1), "fs", entry.name), []byte(entry.body))
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		raw := append([]byte(nil), archive.Bytes()...)
		blob := raw
		media := "application/vnd.oci.image.layer.v1.tar"
		if compressed {
			var out bytes.Buffer
			gz := gzip.NewWriter(&out)
			if _, err := gz.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			blob = out.Bytes()
			media += "+gzip"
		}
		diff := Sum(raw)
		chain := diff
		if i > 0 {
			chain = Sum([]byte(image.Layers[i-1].ChainID + " " + diff))
		}
		digest := PutBlob(t, root, image.ContentRoot, blob)
		image.Layers = append(image.Layers, Layer{Digest: digest, DiffID: diff, ChainID: chain, Raw: raw, Blob: blob})
		diffs = append(diffs, diff)
		descriptors = append(descriptors, map[string]any{"mediaType": media, "digest": digest, "size": len(blob)})
	}
	cfg := map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}, "config": map[string]any{"Env": []string{"EXAMPLE=value"}}}
	configData, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	image.ConfigDigest = PutBlob(t, root, image.ContentRoot, configData)
	manifestData, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": image.ConfigDigest, "size": len(configData)}, "layers": descriptors})
	if err != nil {
		t.Fatal(err)
	}
	image.ManifestDigest = PutBlob(t, root, image.ContentRoot, manifestData)
	return image
}

func NewProvenanceCase(t Reporter) *Image {
	t.Helper()
	root := t.TempDir()
	image := NewImage(t, root, true)
	if err := os.MkdirAll(filepath.Join(root, "host/snapshots/3/fs"), 0700); err != nil {
		t.Fatal(err)
	}
	Write(t, filepath.Join(root, "mountinfo"), []byte("100 1 0:52 / / rw - overlay overlay rw,lowerdir=/snapshots/2/fs:/snapshots/1/fs,upperdir=/snapshots/3/fs,workdir=/snapshots/3/work,userxattr\n"))
	Write(t, filepath.Join(root, "case.json"), []byte(fmt.Sprintf(`{"schema":"layerclue.case/v1","host_root":"host","mountinfo":"mountinfo","container_id":"k8s.io/ctr","containerd_metadata":"containerd/meta.db","image_provenance":{"manifest_digest":%q,"content_root":"oci","snapshotter_metadata":"snapshotter/metadata.db","snapshotter_root":"host/snapshots"}}`, image.ManifestDigest)))
	DB(t, filepath.Join(root, "containerd/meta.db"), func(tx *bolt.Tx) error {
		b, err := Bucket(tx, "v1", "k8s.io", "containers", "ctr")
		if err != nil {
			return err
		}
		for _, kv := range [][2]string{{"snapshotter", "overlayfs"}, {"snapshotKey", "ctr"}, {"image", "demo:latest"}} {
			if err := b.Put([]byte(kv[0]), []byte(kv[1])); err != nil {
				return err
			}
		}
		img, err := Bucket(tx, "v1", "k8s.io", "images", "demo:latest", "target")
		if err != nil {
			return err
		}
		if err := img.Put([]byte("digest"), []byte(image.ManifestDigest)); err != nil {
			return err
		}
		keys := []string{image.Layers[0].ChainID, image.Layers[1].ChainID, "ctr"}
		for i, key := range keys {
			rec, err := Bucket(tx, "v1", "k8s.io", "snapshots", "overlayfs", key)
			if err != nil {
				return err
			}
			if err := rec.Put([]byte("name"), []byte(backendName(i+1))); err != nil {
				return err
			}
			if i > 0 {
				// #nosec G602 -- i is a range index into keys and this predecessor is accessed only inside i > 0.
				if err := rec.Put([]byte("parent"), []byte(keys[i-1])); err != nil {
					return err
				}
			}
		}
		return nil
	})
	DB(t, filepath.Join(root, "snapshotter/metadata.db"), func(tx *bolt.Tx) error {
		for i := 1; i <= 3; i++ {
			rec, err := Bucket(tx, "v1", "snapshots", backendName(i))
			if err != nil {
				return err
			}
			var encoded [binary.MaxVarintLen64]byte
			n := binary.PutUvarint(encoded[:], uint64(i))
			if err := rec.Put([]byte("id"), encoded[:n]); err != nil {
				return err
			}
			kind := byte(3)
			if i == 3 {
				kind = 2
			}
			if err := rec.Put([]byte("kind"), []byte{kind}); err != nil {
				return err
			}
			if i > 1 {
				if err := rec.Put([]byte("parent"), []byte(backendName(i-1))); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return image
}

func backendName(i int) string { return fmt.Sprintf("k8s.io/%d/backend", i) }

func Bucket(tx *bolt.Tx, keys ...string) (*bolt.Bucket, error) {
	var b *bolt.Bucket
	for i, key := range keys {
		var err error
		if i == 0 {
			b, err = tx.CreateBucketIfNotExists([]byte(key))
		} else {
			b, err = b.CreateBucketIfNotExists([]byte(key))
		}
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func DB(t Reporter, path string, edit func(*bolt.Tx) error) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(edit); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
