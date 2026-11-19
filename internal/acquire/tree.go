package acquire

import (
	"context"
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
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"golang.org/x/sys/unix"
)

type sourceEntry struct {
	Source         string            `json:"source"`
	Output         string            `json:"output"`
	Kind           string            `json:"original_kind"`
	Mode           uint32            `json:"mode"`
	UID            uint32            `json:"uid"`
	GID            uint32            `json:"gid"`
	MtimeNS        int64             `json:"mtime_ns"`
	Size           int64             `json:"size,omitempty"`
	SHA256         string            `json:"sha256,omitempty"`
	Target         string            `json:"target,omitempty"`
	ChildrenSHA256 string            `json:"children_sha256,omitempty"`
	OverlayAttrs   map[string]string `json:"overlay_attrs,omitempty"`
	Hardlink       string            `json:"output_hardlink,omitempty"`
	info           os.FileInfo
	prefix         string
}
type treeCopy struct {
	ctx       context.Context
	root, dst string
	limits    custody.Limits
	entries   []sourceEntry
	bytes     int64
	encoded   int
	links     map[[2]uint64]string
}

func stateEqual(a, b os.FileInfo) bool {
	return evidence.SameState(a, b)
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (c *treeCopy) append(e sourceEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	c.encoded += len(b) + 1
	if len(c.entries) >= MaxEntries || c.encoded > 12<<20 {
		return evidence.ErrLimit
	}
	c.entries = append(c.entries, e)
	return nil
}
func (c *treeCopy) attributes(source, prefix string) (map[string]string, error) {
	if prefix == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, suffix := range []string{"whiteout", "opaque", "metacopy", "redirect"} {
		value, present, err := evidence.Xattr(c.root, source, prefix+suffix)
		if err != nil {
			return nil, err
		}
		if present {
			out[suffix] = hex.EncodeToString(value)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
func (c *treeCopy) names(source string) ([]string, error) {
	dir, err := evidence.OpenDir(c.root, source)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var names []string
	for {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := dir.Readdirnames(256)
		names = append(names, batch...)
		if len(names) > MaxEntries {
			return nil, evidence.ErrLimit
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}
func (c *treeCopy) copy(source, output, prefix string, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if !canonical(source) || !canonical(output) || depth > 128 || len(c.entries) >= MaxEntries {
		return evidence.ErrLimit
	}
	st, err := evidence.Lstat(c.root, source)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("Linux inode identity unavailable")
	}
	mtime, err := evidence.NanosecondMtime(st)
	if err != nil {
		return err
	}
	e := sourceEntry{Source: source, Output: output, Mode: uint32(st.Mode()), UID: sys.Uid, GID: sys.Gid, MtimeNS: mtime, info: st, prefix: prefix}
	dst := filepath.Join(c.dst, output)
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		e.Kind = "symlink"
		e.Target, err = evidence.Readlink(c.root, source)
		if err != nil {
			return err
		}
		if !utf8.ValidString(e.Target) {
			return errors.New("non-UTF8 logical symlink is unsupported")
		}
		if err := os.Symlink(e.Target, dst); err != nil {
			return err
		}
	case st.IsDir():
		e.Kind = "directory"
		e.OverlayAttrs, err = c.attributes(source, prefix)
		if err != nil {
			return err
		}
		if err := os.Mkdir(dst, 0700); err != nil {
			return err
		}
		names, err := c.names(source)
		if err != nil {
			return err
		}
		data, _ := json.Marshal(names)
		e.ChildrenSHA256 = hash(data)
		if err := c.append(e); err != nil {
			return err
		}
		for _, name := range names {
			if name == "." || name == ".." || strings.ContainsRune(name, '/') || !utf8.ValidString(name) {
				return errors.New("invalid source directory entry")
			}
			if err := c.copy(filepath.Join(source, name), filepath.Join(output, name), prefix, depth+1); err != nil {
				return err
			}
		}
		if err := c.export(dst, e.OverlayAttrs); err != nil {
			return err
		}
		return c.checkState(e)
	case st.Mode().IsRegular():
		e.Kind = "file"
		e.Size = st.Size()
		if e.Size < 0 || e.Size > c.limits.FileBytes || e.Size > c.limits.TotalBytes-c.bytes {
			return evidence.ErrLimit
		}
		e.OverlayAttrs, err = c.attributes(source, prefix)
		if err != nil {
			return err
		}
		f, err := evidence.OpenRegular(c.root, source)
		if err != nil {
			return err
		}
		defer f.Close()
		pinned, err := f.Stat()
		if err != nil {
			return err
		}
		if !stateEqual(st, pinned) {
			return errors.New("source changed before copy")
		}
		key := [2]uint64{uint64(sys.Dev), sys.Ino}
		first := c.links[key]
		h := sha256.New()
		var dstFile *os.File
		var sink io.Writer = h
		if first == "" {
			// #nosec G304 -- Local validated tree entry in the new private import stage; logical evidence symlinks are copied as data.
			dstFile, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			sink = io.MultiWriter(dstFile, h)
		}
		n, copyErr := evidence.Copy(c.ctx, sink, f, max(1, min(c.limits.FileBytes, c.limits.TotalBytes-c.bytes)))
		if dstFile != nil {
			if copyErr == nil {
				copyErr = dstFile.Sync()
			}
			closeErr := dstFile.Close()
			if copyErr == nil {
				copyErr = closeErr
			}
		}
		if copyErr != nil {
			return copyErr
		}
		if n != e.Size || n > c.limits.TotalBytes-c.bytes {
			return errors.New("source size changed while copying")
		}
		c.bytes += n
		after, err := f.Stat()
		if err != nil {
			return err
		}
		if !stateEqual(st, after) {
			return errors.New("source changed while copying")
		}
		e.SHA256 = hex.EncodeToString(h.Sum(nil))
		if first != "" {
			e.Hardlink = first
			if err := os.Link(filepath.Join(c.dst, first), dst); err != nil {
				return err
			}
		} else if sys.Nlink > 1 {
			c.links[key] = output
		}
		if err := c.export(dst, e.OverlayAttrs); err != nil {
			return err
		}
	case prefix != "" && st.Mode()&os.ModeCharDevice != 0 && sys.Rdev == 0:
		// Inspect the O_PATH inode only. Never open a device for data or recreate it.
		e.Kind = "native_whiteout"
		// #nosec G304 -- Portable whiteout in the owned private stage; destination comes from a validated local tree entry.
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := unix.Setxattr(dst, "user.layerclue.overlay.whiteout", nil, 0); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported source object %q (%s)", source, st.Mode())
	}
	if err := c.checkState(e); err != nil {
		return err
	}
	return c.append(e)
}
func (c *treeCopy) export(dst string, attrs map[string]string) error {
	for key, value := range attrs {
		b, err := hex.DecodeString(value)
		if err != nil {
			return err
		}
		if err := unix.Setxattr(dst, "user.layerclue.overlay."+key, b, 0); err != nil {
			return err
		}
	}
	return nil
}
func (c *treeCopy) checkState(e sourceEntry) error {
	after, err := evidence.Lstat(c.root, e.Source)
	if err != nil {
		return err
	}
	if !stateEqual(e.info, after) {
		return fmt.Errorf("source changed: %q", e.Source)
	}
	return nil
}
func (c *treeCopy) recheck() error {
	var total int64
	for _, e := range c.entries {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if err := c.checkState(e); err != nil {
			return err
		}
		switch e.Kind {
		case "file":
			f, err := evidence.OpenRegular(c.root, e.Source)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, copyErr := evidence.Copy(c.ctx, h, f, max(1, min(c.limits.FileBytes, c.limits.TotalBytes-total)))
			_ = f.Close()
			if copyErr != nil {
				return copyErr
			}
			if n != e.Size || n > c.limits.TotalBytes-total || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
				return errors.New("source file changed after copy")
			}
			total += n
		case "directory":
			names, err := c.names(e.Source)
			if err != nil {
				return err
			}
			b, _ := json.Marshal(names)
			if hash(b) != e.ChildrenSHA256 {
				return errors.New("source directory entries changed after copy")
			}
		case "symlink":
			target, err := evidence.Readlink(c.root, e.Source)
			if err != nil {
				return err
			}
			if target != e.Target {
				return errors.New("source symlink changed after copy")
			}
		}
		if e.Kind == "file" || e.Kind == "directory" {
			attrs, err := c.attributes(e.Source, e.prefix)
			if err != nil {
				return err
			}
			a, _ := json.Marshal(attrs)
			b, _ := json.Marshal(e.OverlayAttrs)
			if string(a) != string(b) {
				return errors.New("source overlay metadata changed after copy")
			}
		}
		if err := c.checkState(e); err != nil {
			return err
		}
	}
	return nil
}
