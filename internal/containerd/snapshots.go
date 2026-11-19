package containerd

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

// SnapshotRecord combines one logical metadata record with its snapshotter
// storage record. Keys are not paths; the disk ID is decoded as a canonical
// positive uvarint before it can be used in any filesystem address.
type SnapshotRecord struct {
	Key           string `json:"key"`
	Parent        string `json:"parent"`
	BackendKey    string `json:"backend_key"`
	BackendParent string `json:"backend_parent"`
	DiskID        string `json:"disk_id"`
	Kind          byte   `json:"kind"`
}

func metadataText(v []byte) (string, error) {
	if len(v) > 4096 || !utf8.Valid(v) || strings.ContainsRune(string(v), 0) {
		return "", fmt.Errorf("%w: invalid metadata text", ErrUnsupportedFormat)
	}
	return string(v), nil
}

func (s *Store) LogicalSnapshot(namespace, snapshotter, key string) (SnapshotRecord, error) {
	result := SnapshotRecord{Key: key}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := bucket(tx, "v1", namespace, "snapshots", snapshotter, key)
		if b == nil {
			return fmt.Errorf("%w: logical snapshot %q", ErrNotFound, key)
		}
		var err error
		result.BackendKey, err = metadataText(b.Get([]byte("name")))
		if err != nil {
			return err
		}
		result.Parent, err = metadataText(b.Get([]byte("parent")))
		if err != nil {
			return err
		}
		if result.BackendKey == "" {
			return fmt.Errorf("%w: missing backend snapshot name", ErrUnsupportedFormat)
		}
		return nil
	})
	return result, err
}

func (s *Store) StorageSnapshot(key string) (SnapshotRecord, error) {
	result := SnapshotRecord{BackendKey: key}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := bucket(tx, "v1", "snapshots", key)
		if b == nil {
			return fmt.Errorf("%w: storage snapshot %q", ErrNotFound, key)
		}
		encoded := b.Get([]byte("id"))
		id, n := binary.Uvarint(encoded)
		var canonical [binary.MaxVarintLen64]byte
		length := binary.PutUvarint(canonical[:], id)
		if id == 0 || n <= 0 || n != len(encoded) || length != n || string(canonical[:length]) != string(encoded) {
			return fmt.Errorf("%w: invalid storage snapshot ID", ErrUnsupportedFormat)
		}
		result.DiskID = strconv.FormatUint(id, 10)
		kind := b.Get([]byte("kind"))
		if len(kind) != 1 || kind[0] < 1 || kind[0] > 3 {
			return fmt.Errorf("%w: invalid snapshot kind", ErrUnsupportedFormat)
		}
		result.Kind = kind[0]
		var err error
		result.BackendParent, err = metadataText(b.Get([]byte("parent")))
		return err
	})
	return result, err
}

// SnapshotChain is ordered base first and includes the selected active/view
// record. Both graphs must agree. Cycles and disk-ID aliasing fail closed.
func SnapshotChain(logical, storage *Store, namespace, snapshotter, key string) ([]SnapshotRecord, error) {
	var reverse []SnapshotRecord
	keys, ids := make(map[string]bool), make(map[string]bool)
	for key != "" {
		if len(reverse) >= 257 || keys[key] {
			return nil, fmt.Errorf("%w: snapshot chain cycle or depth limit", ErrUnsupportedFormat)
		}
		keys[key] = true
		rec, err := logical.LogicalSnapshot(namespace, snapshotter, key)
		if err != nil {
			return nil, err
		}
		raw, err := storage.StorageSnapshot(rec.BackendKey)
		if err != nil {
			return nil, err
		}
		if ids[raw.DiskID] {
			return nil, fmt.Errorf("%w: duplicate disk ID in snapshot chain", ErrUnsupportedFormat)
		}
		ids[raw.DiskID] = true
		rec.DiskID, rec.Kind, rec.BackendParent = raw.DiskID, raw.Kind, raw.BackendParent
		reverse = append(reverse, rec)
		key = rec.Parent
	}
	result := make([]SnapshotRecord, len(reverse))
	for i, rec := range reverse {
		result[len(reverse)-1-i] = rec
	}
	for i, rec := range result {
		expected := ""
		if i > 0 {
			expected = result[i-1].BackendKey
		}
		if rec.BackendParent != expected {
			return nil, fmt.Errorf("%w: logical and storage parent chains disagree", ErrUnsupportedFormat)
		}
	}
	return result, nil
}
