// Package containerd reads the containerd metadata database.
//
// The reader accepts the bucketed v1 metadata layout, which is used by
// containerd 1.7 and 2.x. A value record is unsupported; its presence does not
// identify a particular runtime version. Runtime identity is metadata only,
// not proof that the selected mount context belongs to that container.
//
// Open copies already-captured metadata before mmap/locking. Copying a live
// database is not a consistent acquisition procedure. The CLI isolates this
// parser in a child process; in-process callers must trust their input.
package containerd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
	bolt "go.etcd.io/bbolt"
)

var (
	// ErrNoMetadata means the file is not a readable containerd database.
	ErrNoMetadata = errors.New("containerd: not a metadata database")
	// ErrUnsupportedFormat means the database uses a layout this version does
	// not decode.
	ErrUnsupportedFormat = errors.New("containerd: unsupported metadata layout")
	// ErrNotFound means the requested object is absent.
	ErrNotFound = errors.New("containerd: not found")
)

const (
	bucketRoot = "v1"
)

// Container is the subset of the runtime record layerclue needs.
type Container struct {
	Namespace   string
	ID          string
	Image       string
	Snapshotter string
	SnapshotKey string
	Labels      map[string]string
}

// Pod returns the Kubernetes pod identity recorded in the labels, if any.
func (c *Container) Pod() (name, namespace, uid string) {
	return c.Labels["io.kubernetes.pod.name"],
		c.Labels["io.kubernetes.pod.namespace"],
		c.Labels["io.kubernetes.pod.uid"]
}

// Image is the subset of the image record layerclue needs.
type Image struct {
	Namespace string
	Name      string
	Digest    string
	MediaType string
	Size      int64
}

// Store is an open, read-only view of a metadata database.
type Store struct {
	SHA256 string
	db     *bolt.DB
	temp   string
}

// Open copies the database to a temporary file and opens the copy read-only.
//
// The source must be an offline, consistent capture. A private bounded copy
// avoids locking the supplied database, but does not make a live copy atomic.
func Open(path string) (*Store, error) {
	return OpenWithin(filepath.Dir(path), path)
}

func OpenWithin(root, path string) (*Store, error) {
	dir, err := os.MkdirTemp("", "layerclue-meta-")
	if err != nil {
		return nil, err
	}
	copyPath := filepath.Join(dir, "meta.db")
	digest, err := copyFile(root, path, copyPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	db, err := bolt.Open(copyPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("%w: %v", ErrNoMetadata, err)
	}
	return &Store{db: db, temp: dir, SHA256: digest}, nil
}

// Close releases the database and the temporary copy.
func (s *Store) Close() error {
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.temp != "" {
		if rmErr := os.RemoveAll(s.temp); err == nil {
			err = rmErr
		}
	}
	return err
}

// Namespaces lists the namespaces present in the database.
func (s *Store) Namespaces() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(bucketRoot))
		if root == nil {
			return ErrNoMetadata
		}
		return root.ForEach(func(k, v []byte) error {
			if len(out) >= 4096 || len(k) > 4096 || !utf8.Valid(k) {
				return evidence.ErrLimit
			}
			if v == nil {
				out = append(out, string(k))
			}
			return nil
		})
	})
	sort.Strings(out)
	return out, err
}

// Containers lists the containers of a namespace.
func (s *Store) Containers(namespace string) ([]Container, error) {
	var out []Container
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := bucket(tx, bucketRoot, namespace, "containers")
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			if len(out) >= 100000 || len(k) > 4096 || !utf8.Valid(k) {
				return evidence.ErrLimit
			}
			if v != nil {
				return fmt.Errorf("%w: container record %s is a protobuf value", ErrUnsupportedFormat, k)
			}
			rec := bucket.Bucket(k)
			if rec == nil {
				return nil
			}
			c, err := readContainer(namespace, string(k), rec)
			if err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// Container returns one container by identifier.
func (s *Store) Container(namespace, id string) (Container, error) {
	var out Container
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := bucket(tx, bucketRoot, namespace, "containers")
		if bucket == nil {
			return ErrNotFound
		}
		rec := bucket.Bucket([]byte(id))
		if rec == nil {
			if v := bucket.Get([]byte(id)); v != nil {
				return fmt.Errorf("%w: container %s is a protobuf value", ErrUnsupportedFormat, id)
			}
			return ErrNotFound
		}
		var err error
		out, err = readContainer(namespace, id, rec)
		return err
	})
	return out, err
}

// Images lists the images of a namespace.
func (s *Store) Images(namespace string) ([]Image, error) {
	var out []Image
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := bucket(tx, bucketRoot, namespace, "images")
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			if len(out) >= 100000 || len(k) > 4096 || !utf8.Valid(k) {
				return evidence.ErrLimit
			}
			if v != nil {
				return nil
			}
			rec := bucket.Bucket(k)
			if rec == nil {
				return nil
			}
			img, err := readImage(namespace, string(k), rec)
			if err != nil {
				return err
			}
			out = append(out, img)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// Image returns one image by reference.
func (s *Store) Image(namespace, ref string) (Image, error) {
	var out Image
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := bucket(tx, bucketRoot, namespace, "images")
		if bucket == nil {
			return ErrNotFound
		}
		rec := bucket.Bucket([]byte(ref))
		if rec == nil {
			return ErrNotFound
		}
		var err error
		out, err = readImage(namespace, ref, rec)
		return err
	})
	return out, err
}

func readImage(namespace, name string, rec *bolt.Bucket) (Image, error) {
	img := Image{Namespace: namespace, Name: name}
	if target := rec.Bucket([]byte("target")); target != nil {
		var err error
		img.Digest, err = metadataText(target.Get([]byte("digest")))
		if err != nil {
			return img, err
		}
		img.MediaType, err = metadataText(target.Get([]byte("mediatype")))
		if err != nil {
			return img, err
		}
	}
	return img, nil
}

func readContainer(namespace, id string, rec *bolt.Bucket) (Container, error) {
	c := Container{Namespace: namespace, ID: id, Labels: make(map[string]string)}
	if _, err := metadataText([]byte(id)); err != nil {
		return c, err
	}
	fields := []struct {
		key string
		dst *string
	}{{"image", &c.Image}, {"snapshotter", &c.Snapshotter}, {"snapshotKey", &c.SnapshotKey}}
	for _, field := range fields {
		value, err := metadataText(rec.Get([]byte(field.key)))
		if err != nil {
			return c, err
		}
		*field.dst = value
	}
	if labels := rec.Bucket([]byte("labels")); labels != nil {
		// Unknown labels are irrelevant to identity. Do not materialise an
		// attacker-controlled label map just to read these three values.
		for _, key := range []string{"io.kubernetes.pod.name", "io.kubernetes.pod.namespace", "io.kubernetes.pod.uid"} {
			value, err := metadataText(labels.Get([]byte(key)))
			if err != nil {
				return c, err
			}
			if value != "" {
				c.Labels[key] = value
			}
		}
	}
	return c, nil
}

func bucket(tx *bolt.Tx, path ...string) *bolt.Bucket {
	var b *bolt.Bucket
	for i, name := range path {
		if i == 0 {
			b = tx.Bucket([]byte(name))
		} else {
			if b == nil {
				return nil
			}
			b = b.Bucket([]byte(name))
		}
	}
	return b
}

func copyFile(root, src, dst string) (string, error) {
	in, err := evidence.OpenRegular(root, src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return "", err
	}
	if before.Size() < 8192 || before.Size() > evidence.MaxDatabaseBytes {
		return "", fmt.Errorf("%w: database size", evidence.ErrLimit)
	}
	// #nosec G304 -- Fixed meta.db name inside this call's newly created 0700 temporary directory.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, err := evidence.Copy(ctx, io.MultiWriter(out, h), in, evidence.MaxDatabaseBytes)
	if err != nil {
		_ = out.Close()
		return "", err
	}
	after, err := in.Stat()
	if err != nil {
		_ = out.Close()
		return "", err
	}
	if n != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		_ = out.Close()
		return "", errors.New("database changed during copying; use a consistent offline capture")
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
