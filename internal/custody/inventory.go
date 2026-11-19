// Package custody inventories prepared cases. A signature authenticates the
// inventory signer, not the original acquisition or a compromised source host.
package custody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"golang.org/x/sys/unix"
)

const Schema = "layerclue.inventory/v1"
const MaxEntries = 50000
const MaxInventoryBytes = 16 << 20

type Limits struct {
	FileBytes  int64 `json:"file_bytes"`
	TotalBytes int64 `json:"total_bytes"`
}

func DefaultLimits() Limits { return Limits{FileBytes: 256 << 20, TotalBytes: 4 << 30} }
func (l Limits) valid() bool {
	return l.FileBytes > 0 && l.FileBytes <= 8<<30 && l.TotalBytes > 0 && l.TotalBytes <= 32<<30
}

type Entry struct {
	Path     string            `json:"path"`
	Kind     string            `json:"kind"`
	Mode     uint32            `json:"mode"`
	UID      uint32            `json:"uid"`
	GID      uint32            `json:"gid"`
	MtimeNS  int64             `json:"mtime_ns"`
	Size     int64             `json:"size,omitempty"`
	SHA256   string            `json:"sha256,omitempty"`
	Target   string            `json:"target,omitempty"`
	Hardlink string            `json:"hardlink,omitempty"`
	Xattrs   map[string]string `json:"xattrs,omitempty"` // values hex-encoded, never recreated as capabilities
}
type Inventory struct {
	Schema      string  `json:"schema"`
	StartedAt   string  `json:"inventory_started_at"`
	CompletedAt string  `json:"inventory_completed_at"`
	Method      string  `json:"acquisition_method_assertion"`
	Scope       string  `json:"scope"`
	Limits      Limits  `json:"limits"`
	Entries     []Entry `json:"entries"`
}
type Seal struct {
	Inventory Inventory `json:"inventory"`
	SHA256    string    `json:"inventory_sha256"`
	Signature string    `json:"ed25519_signature,omitempty"`
}

func attrs(f *os.File) (map[string]string, error) {
	n, err := unix.Flistxattr(int(f.Fd()), nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil, errors.New("filesystem does not support xattr enumeration")
	}
	if err != nil {
		return nil, err
	}
	if n > 64<<10 {
		return nil, evidence.ErrLimit
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	n, err = unix.Flistxattr(int(f.Fd()), buf)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	total := n
	for _, key := range strings.Split(strings.TrimSuffix(string(buf[:n]), "\x00"), "\x00") {
		if key == "" || !utf8.ValidString(key) {
			return nil, errors.New("invalid xattr name")
		}
		size, err := unix.Fgetxattr(int(f.Fd()), key, nil)
		if err != nil {
			return nil, err
		}
		total += size
		if total > 64<<10 {
			return nil, evidence.ErrLimit
		}
		value := make([]byte, size)
		got, err := unix.Fgetxattr(int(f.Fd()), key, value)
		if err != nil {
			return nil, err
		}
		out[key] = hex.EncodeToString(value[:got])
	}
	return out, nil
}
func stable(a, b os.FileInfo) bool {
	return evidence.SameState(a, b)
}

// Scan does not follow physical symlinks, cross mounts or open devices/FIFOs.
// It checks detected changes but is not an atomic snapshot. The root and kernel
// must be trusted and immutable. Unreadable/unlisted privileged xattrs remain
// subject to the caller's acquisition privileges, recorded in Scope.
func Scan(ctx context.Context, root string, limits Limits) ([]Entry, error) {
	if ctx == nil || !limits.valid() {
		return nil, evidence.ErrLimit
	}
	var entries []Entry
	var total int64
	var encoded int
	hardlinks := map[[2]uint64]string{}
	appendEntry := func(e Entry) error {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		encoded += len(b) + 1
		if encoded > MaxInventoryBytes-(1<<20) {
			return evidence.ErrLimit
		}
		entries = append(entries, e)
		return nil
	}
	var walk func(string, int) error
	walk = func(rel string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 128 || len(entries) >= MaxEntries || len(rel) > 4096 || !utf8.ValidString(rel) {
			return evidence.ErrLimit
		}
		before, err := evidence.Lstat(root, rel)
		if err != nil {
			return err
		}
		st, ok := before.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("Linux inode metadata unavailable")
		}
		mtime, err := evidence.NanosecondMtime(before)
		if err != nil {
			return err
		}
		e := Entry{Path: rel, Mode: uint32(before.Mode()), UID: st.Uid, GID: st.Gid, MtimeNS: mtime}
		switch {
		case before.Mode().IsRegular():
			e.Kind = "file"
			e.Size = before.Size()
			if e.Size > limits.FileBytes || e.Size > limits.TotalBytes-total {
				return evidence.ErrLimit
			}
			f, err := evidence.OpenRegular(root, rel)
			if err != nil {
				return err
			}
			defer f.Close()
			pinned, err := f.Stat()
			if err != nil {
				return err
			}
			if !stable(before, pinned) {
				return errors.New("artifact changed before inventory read")
			}
			e.Xattrs, err = attrs(f)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, err := evidence.Copy(ctx, h, f, max(1, min(limits.FileBytes, limits.TotalBytes-total)))
			if err != nil {
				return err
			}
			if n != e.Size || n > limits.TotalBytes-total {
				return errors.New("artifact size changed")
			}
			total += n
			after, err := f.Stat()
			if err != nil {
				return err
			}
			if !stable(before, after) {
				return errors.New("artifact changed during inventory read")
			}
			e.SHA256 = hex.EncodeToString(h.Sum(nil))
			key := [2]uint64{uint64(st.Dev), st.Ino}
			if st.Nlink > 1 {
				if first, ok := hardlinks[key]; ok {
					e.Hardlink = first
				} else {
					hardlinks[key] = rel
				}
			}
		case before.IsDir():
			e.Kind = "directory"
			f, err := evidence.OpenDir(root, rel)
			if err != nil {
				return err
			}
			pinned, err := f.Stat()
			if err != nil || !stable(before, pinned) {
				_ = f.Close()
				return errors.New("directory changed before inventory read")
			}
			e.Xattrs, err = attrs(f)
			if err != nil {
				_ = f.Close()
				return err
			}
			// Read batches instead of allocating an unbounded list for one directory.
			var names []string
			for {
				batch, err := f.Readdirnames(256)
				names = append(names, batch...)
				if len(names) > MaxEntries-len(entries) {
					_ = f.Close()
					return evidence.ErrLimit
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					_ = f.Close()
					return err
				}
			}
			if err := f.Close(); err != nil {
				return err
			}
			sort.Strings(names)
			if err := appendEntry(e); err != nil {
				return err
			}
			for _, name := range names {
				if name == "." || name == ".." || strings.ContainsRune(name, '/') || !utf8.ValidString(name) {
					return errors.New("invalid directory entry")
				}
				if err := walk(filepath.Join(rel, name), depth+1); err != nil {
					return err
				}
			}
			after, err := evidence.Lstat(root, rel)
			if err != nil {
				return err
			}
			if !stable(before, after) {
				return errors.New("directory changed during inventory scan")
			}
			return nil
		case before.Mode()&os.ModeSymlink != 0:
			e.Kind = "symlink"
			e.Target, err = evidence.Readlink(root, rel)
			if err != nil {
				return err
			}
			if !utf8.ValidString(e.Target) {
				return errors.New("non-UTF8 symlink is unsupported")
			}
			after, err := evidence.Lstat(root, rel)
			if err != nil {
				return err
			}
			if !stable(before, after) {
				return errors.New("symlink changed during inventory scan")
			}
		default:
			return fmt.Errorf("unsupported artifact type at %q; export devices/whiteouts into a portable capture first", rel)
		}
		return appendEntry(e)
	}
	if err := walk(".", 0); err != nil {
		return nil, err
	}
	return entries, nil
}

func New(ctx context.Context, root, method string, limits Limits, key ed25519.PrivateKey) (*Seal, error) {
	if method == "" || len(method) > 4096 || !utf8.ValidString(method) {
		return nil, errors.New("a bounded acquisition method assertion is required")
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	entries, err := Scan(ctx, root, limits)
	if err != nil {
		return nil, err
	}
	s := &Seal{Inventory: Inventory{Schema: Schema, StartedAt: started, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), Method: method, Scope: "readable regular files, directories, symlink targets, modes, owners, mtimes, hardlink relationships and enumerable non-symlink xattrs; access times, symlink xattrs, inaccessible metadata, source authenticity and atomic acquisition are not proven", Limits: limits, Entries: entries}}
	b, err := json.Marshal(s.Inventory)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	s.SHA256 = hex.EncodeToString(sum[:])
	if len(key) != 0 {
		if len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 private key")
		}
		s.Signature = hex.EncodeToString(ed25519.Sign(key, b))
	}
	return s, nil
}

func Decode(b []byte) (*Seal, error) {
	if len(b) > MaxInventoryBytes {
		return nil, evidence.ErrLimit
	}
	var s Seal
	if err := evidence.DecodeInventoryJSON(b, &s); err != nil {
		return nil, err
	}
	if s.Inventory.Schema != Schema || !s.Inventory.Limits.valid() || len(s.Inventory.Entries) == 0 || len(s.Inventory.Entries) > MaxEntries || s.Inventory.Entries[0].Path != "." {
		return nil, errors.New("invalid inventory header")
	}
	b, err := json.Marshal(s.Inventory)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != s.SHA256 {
		return nil, errors.New("inventory checksum mismatch")
	}
	return &s, nil
}

// Verify uses caller-controlled limits, never an untrusted inventory's budget.
// A supplied public key is a required external trust anchor; unsigned inventory
// or any invalid signature then fails. With no key, only integrity is checked.
func Verify(ctx context.Context, root string, s *Seal, limits Limits, key ed25519.PublicKey) error {
	if s == nil {
		return errors.New("missing inventory")
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := Decode(encoded); err != nil {
		return err
	}
	if len(key) > 0 {
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return errors.New("missing/invalid Ed25519 signature")
		}
		b, err := json.Marshal(s.Inventory)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, b, sig) {
			return errors.New("inventory signature does not match trusted key")
		}
	}
	current, err := Scan(ctx, root, limits)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(s.Inventory.Entries)
	if !bytes.Equal(a, b) {
		return errors.New("case inventory mismatch: paths, bytes or recorded metadata changed")
	}
	return nil
}
