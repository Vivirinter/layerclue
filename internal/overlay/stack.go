// Package overlay resolves paths through an overlayfs layer stack without
// mounting anything.
//
// Only the documented subset is supported. Unimplemented semantics fail closed:
//
//   - upper layers are consulted before lower ones;
//   - a whiteout removes the path from every layer below it;
//   - an opaque directory stops the merge, hiding everything below it;
//   - directories merge across layers while files do not;
//   - metacopy and redirects are detected and refused until fully supported.
//
// A layer that was not captured is not silently treated as empty: lookups
// report the result as incomplete, because a missing lower layer can change
// the answer.
package overlay

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

var (
	// ErrNoLayers is returned when a stack has nothing to resolve against.
	ErrNoLayers    = errors.New("overlay: empty layer stack")
	ErrUnsupported = errors.New("overlay: unsupported feature")
)

const MaxLayers = 256

// Kind classifies a directory entry.
type Kind int

const (
	KindAbsent Kind = iota
	KindFile
	KindDir
	KindSymlink
	KindOther
)

func (k Kind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDir:
		return "directory"
	case KindSymlink:
		return "symlink"
	case KindOther:
		return "other"
	default:
		return "absent"
	}
}

// Layer is one directory of an overlay stack.
type Layer struct {
	// Index is the position of the layer in the stack, 0 at the bottom.
	Index int
	// Root is the host path of the layer directory.
	Root string
	// Digest is the OCI digest of the layer when it is known.
	Digest string
	// Upper marks the writable layer.
	Upper bool
	// Extracted marks a tree unpacked from an OCI layer tar, where deletions
	// are encoded as ".wh." marker files rather than device nodes.
	Extracted bool
	// Missing marks a layer directory that was not captured.
	Missing bool
}

// Stack is an overlay stack ordered from the bottom (index 0) to the top.
type Stack struct {
	Layers   []Layer
	Boundary string
	// AttrPrefix is the active native or explicitly exported attribute namespace.
	// An empty prefix means trusted.overlay.; it requires CAP_SYS_ADMIN to read.
	AttrPrefix string
	Context    context.Context
}

// Len reports the number of layers, including missing ones.
func (s Stack) Len() int { return len(s.Layers) }

// TopIndex returns the highest layer index, which need not be writable.
func (s Stack) TopIndex() int { return len(s.Layers) - 1 }

// Entry is a single filesystem object found in one layer.
type Entry struct {
	Layer      int
	HostPath   string
	Kind       Kind
	Size       int64
	Mode       os.FileMode
	LinkTarget string
	Whiteout   bool
	Opaque     bool
	MetaCopy   bool
	Info       os.FileInfo
}

// State describes the outcome of a lookup.
type State int

const (
	// StateMissing means no layer contributes the path.
	StateMissing State = iota
	// StateDeleted means a whiteout removed the path.
	StateDeleted
	// StateFound means a layer provides the path.
	StateFound
)

// Result is the outcome of resolving a path through a stack.
type Result struct {
	State State
	// Entry is set when State is StateFound.
	Entry Entry
	// DeletedBy is set when State is StateDeleted.
	DeletedBy Entry
	// Traversal lists the layer indexes that contributed to the directories
	// leading to the result, topmost first.
	Traversal []int
	// Incomplete means a layer was missing above the answer and could have
	// changed it.
	Incomplete bool
}

// Lookup resolves rel inside the merged view.
func (s Stack) Lookup(rel string) (Result, error) {
	if len(s.Layers) == 0 {
		return Result{}, ErrNoLayers
	}
	if len(s.Layers) > MaxLayers {
		return Result{}, evidence.ErrLimit
	}

	clean := path.Clean("/" + rel)
	parts := splitPath(clean)
	if len(parts) == 0 {
		incomplete := false
		for i := len(s.Layers) - 1; i >= 0; i-- {
			if s.Layers[i].Missing {
				incomplete = true
				continue
			}
			e, ok, err := s.stat(i, "/")
			if err != nil {
				return Result{}, err
			}
			if ok {
				return Result{State: StateFound, Entry: e, Incomplete: incomplete}, nil
			}
		}
		return Result{Incomplete: true}, nil
	}

	active := make([]int, 0, len(s.Layers))
	var rootBarrier *Entry
	for i := len(s.Layers) - 1; i >= 0; i-- {
		if s.Context != nil {
			if err := s.Context.Err(); err != nil {
				return Result{}, err
			}
		}
		active = append(active, i)
		if s.Layers[i].Missing {
			continue
		}
		e, ok, err := s.stat(i, "/")
		if err != nil {
			return Result{}, err
		}
		if !ok || e.Kind != KindDir {
			return Result{}, errors.New("captured layer root is not a directory")
		}
		if e.Opaque {
			b := e
			rootBarrier = &b
			break
		}
	}

	var (
		traversal  []int
		incomplete bool
		cur        string
		barrier    = rootBarrier
	)

	for i, part := range parts {
		cur += "/" + part
		last := i == len(parts)-1
		next := make([]int, 0, len(active))

		for _, li := range active {
			if s.Context != nil {
				if err := s.Context.Err(); err != nil {
					return Result{}, err
				}
			}
			if s.Layers[li].Missing {
				incomplete = true
				continue
			}
			e, ok, err := s.stat(li, cur)
			if err != nil {
				return Result{}, err
			}
			if !ok {
				continue
			}
			if e.Whiteout {
				if len(next) > 0 {
					break
				}
				return Result{
					State:      StateDeleted,
					DeletedBy:  e,
					Traversal:  append(traversal, li),
					Incomplete: incomplete,
				}, nil
			}
			if last {
				return Result{
					State:      StateFound,
					Entry:      e,
					Traversal:  append(traversal, li),
					Incomplete: incomplete,
				}, nil
			}
			if e.Kind != KindDir {
				if len(next) > 0 {
					break
				}
				// A non-directory in an upper layer blocks the walk.
				return Result{Traversal: traversal, Incomplete: incomplete}, nil
			}
			next = append(next, li)
			if e.Opaque {
				b := e
				barrier = &b
				break
			}
		}

		if len(next) == 0 {
			if barrier != nil {
				return Result{State: StateDeleted, DeletedBy: *barrier, Traversal: traversal, Incomplete: incomplete}, nil
			}
			return Result{Traversal: traversal, Incomplete: incomplete}, nil
		}
		active = next
		traversal = append(traversal, next[0])
	}

	return Result{Traversal: traversal, Incomplete: incomplete}, nil
}

func (s Stack) stat(li int, rel string) (Entry, bool, error) {
	l := s.Layers[li]
	if l.Missing {
		return Entry{}, false, nil
	}
	boundary := s.Boundary
	if boundary == "" {
		boundary = l.Root
	}
	full := filepath.Join(l.Root, filepath.FromSlash(rel))
	fi, err := evidence.Lstat(boundary, full)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return Entry{}, false, fmt.Errorf("lstat %s: %w", full, err)
		}
		if l.Extracted {
			marker := filepath.Join(filepath.Dir(full), ".wh."+filepath.Base(full))
			if m, err := evidence.Lstat(boundary, marker); err == nil && m.Mode().IsRegular() {
				return Entry{Layer: li, HostPath: marker, Kind: KindOther, Whiteout: true}, true, nil
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return Entry{}, false, err
			}
		}
		return Entry{}, false, nil
	}
	e := Entry{Layer: li, HostPath: full, Mode: fi.Mode(), Size: fi.Size(), Info: fi}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		e.Kind = KindSymlink
		e.LinkTarget, err = evidence.Readlink(boundary, full)
		if err != nil {
			return Entry{}, false, err
		}
		return e, true, nil
	case fi.IsDir():
		e.Kind = KindDir
	case fi.Mode().IsRegular():
		e.Kind = KindFile
	default:
		e.Kind = KindOther
	}
	if isDeviceWhiteout(fi) {
		e.Whiteout = true
		return e, true, nil
	}
	if e.Kind == KindOther {
		return e, true, nil
	}
	prefix := s.AttrPrefix
	if prefix == "" {
		prefix = "trusted.overlay."
	}
	if prefix == "trusted.overlay." && !evidence.CanReadTrusted() {
		return Entry{}, false, fmt.Errorf("%w: trusted OverlayFS attributes are not readable; use an explicitly exported capture or an isolated capable environment", ErrUnsupported)
	}
	for _, prefix := range []string{prefix} {
		for _, feature := range []string{"metacopy", "redirect"} {
			if _, ok, err := evidence.Xattr(boundary, full, prefix+feature); err != nil {
				return Entry{}, false, err
			} else if ok {
				return Entry{}, false, fmt.Errorf("%w: %s on %s", ErrUnsupported, feature, rel)
			}
		}
		if _, ok, err := evidence.Xattr(boundary, full, prefix+"whiteout"); err != nil {
			return Entry{}, false, err
		} else if ok {
			if e.Kind != KindFile || e.Size != 0 {
				return Entry{}, false, fmt.Errorf("%w: invalid whiteout object", ErrUnsupported)
			}
			e.Whiteout = true
		}
		if e.Kind == KindDir {
			if value, ok, err := evidence.Xattr(boundary, full, prefix+"opaque"); err != nil {
				return Entry{}, false, err
			} else if ok && string(value) == "y" {
				e.Opaque = true
			} else if ok && string(value) != "x" {
				return Entry{}, false, fmt.Errorf("%w: opaque attribute value", ErrUnsupported)
			}
		}
	}
	if e.Kind == KindDir && l.Extracted {
		marker := filepath.Join(full, ".wh..wh..opq")
		if _, err := evidence.Lstat(boundary, marker); err == nil {
			e.Opaque = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return Entry{}, false, err
		}
	}
	return e, true, nil
}

// isDeviceWhiteout reports whether fi is the character device 0:0 overlayfs
// writes to mark a deletion.
func isDeviceWhiteout(fi os.FileInfo) bool {
	if fi.Mode()&os.ModeDevice == 0 || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Rdev == 0
}

func splitPath(p string) []string {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
