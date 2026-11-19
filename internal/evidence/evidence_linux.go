//go:build linux

// Package evidence provides bounded, read-only access to captured artifacts.
// Logical container symlinks belong to the resolver: artifact paths never
// follow symlinks or cross mounts. Linux openat2 (5.6+) is required; failures
// are not replaced with a weaker path-based fallback.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ErrLimit = errors.New("artifact processing limit exceeded")

// SameState compares Linux inode identity and observable metadata, excluding
// atime (which a read may update). This detects changes, not snapshot atomicity.
func SameState(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && x.Ctim == y.Ctim && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}

// NanosecondMtime refuses timestamps that UnixNano cannot represent without
// overflow. An evidence inventory must not silently record a different date.
func NanosecondMtime(st os.FileInfo) (int64, error) {
	n := st.ModTime().UnixNano()
	if !time.Unix(0, n).Equal(st.ModTime()) {
		return 0, errors.New("artifact modification time is outside the signed nanosecond timestamp range")
	}
	return n, nil
}

// CanReadTrusted checks the capability and rejects subordinate UID mappings.
// Linux may conceal inaccessible attributes as ENODATA, so absence alone
// cannot establish that a trusted OverlayFS marker was not present. These are
// necessary guards, not proof of the filesystem's owning user namespace.
func CanReadTrusted() bool {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return false
	}
	if data[0].Effective&(1<<unix.CAP_SYS_ADMIN) == 0 {
		return false
	}
	f, err := os.Open("/proc/self/uid_map")
	if err != nil {
		return false
	}
	defer f.Close()
	mapping, err := ReadAll(f, 4096)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(mapping))
	return len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

const (
	MaxManifestBytes  int64 = 1 << 20
	MaxMountinfoBytes int64 = 16 << 20
	MaxReportBytes    int64 = 16 << 20
	MaxDatabaseBytes  int64 = 256 << 20
	DefaultHashBytes  int64 = 256 << 20
)

// Local validates a manifest reference before it is joined to a case root.
func Local(name string) error {
	if name == "" || !filepath.IsLocal(name) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("artifact path must stay inside the case: %q", name)
	}
	return nil
}

// Relative converts a host-side artifact address to a confined relative name.
func Relative(root, name string) (string, error) {
	if root == "" {
		return "", errors.New("artifact root is required")
	}
	if !filepath.IsAbs(name) {
		return name, Local(name)
	}
	rel, err := filepath.Rel(root, name)
	if err != nil {
		return "", err
	}
	return rel, Local(rel)
}

func pathHandle(root, name string) (*os.File, error) {
	rel, err := Relative(root, name)
	if err != nil {
		return nil, err
	}
	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat2(dir, rel, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, fmt.Errorf("open artifact %q: %w", rel, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func Lstat(root, name string) (os.FileInfo, error) {
	f, err := pathHandle(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func Readlink(root, name string) (string, error) {
	f, err := pathHandle(root, name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 4097)
	n, err := unix.Readlinkat(int(f.Fd()), "", buf)
	if err != nil {
		return "", err
	}
	if n == len(buf) {
		return "", ErrLimit
	}
	return string(buf[:n]), nil
}

func openData(root, name string, allowDir bool) (*os.File, error) {
	h, err := pathHandle(root, name)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	st, err := h.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() && !(allowDir && st.IsDir()) {
		return nil, fmt.Errorf("refusing to read non-regular artifact %q (%s)", name, st.Mode())
	}
	// Reopen the pinned inode, not the original pathname. A concurrent rename
	// cannot replace it with a device or FIFO between validation and open.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", h.Fd()), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func OpenRegular(root, name string) (*os.File, error) { return openData(root, name, false) }

func OpenDir(root, name string) (*os.File, error) {
	f, err := openData(root, name, true)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.IsDir() {
		_ = f.Close()
		return nil, errors.New("artifact is not a directory")
	}
	return f, nil
}

// FilesystemReadOnly checks the selected root's mount flags, not snapshot
// authenticity or whether another writable mount of the same storage exists.
func FilesystemReadOnly(root string) (bool, error) {
	f, err := OpenDir(root, ".")
	if err != nil {
		return false, err
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}

func ReadFile(root, name string, max int64) ([]byte, error) {
	f, err := OpenRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f, max)
}

func ReadAll(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 || max == math.MaxInt64 {
		return nil, ErrLimit
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrLimit
	}
	return b, nil
}

// Copy checks cancellation between reads and limits actual bytes, including
// files that grow after stat. Callers must enforce hard OS limits separately.
func Copy(ctx context.Context, dst io.Writer, src io.Reader, max int64) (int64, error) {
	if ctx == nil {
		return 0, errors.New("copy context is required")
	}
	if max <= 0 || max == math.MaxInt64 {
		return 0, ErrLimit
	}
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		want := int64(len(buf))
		if want > max-total+1 {
			want = max - total + 1
		}
		n, err := src.Read(buf[:int(want)])
		total += int64(n)
		if total > max {
			return total, ErrLimit
		}
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			if werr != nil {
				return total, werr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}

// Xattr distinguishes an absent attribute (including an empty value) from
// unreadable metadata. It never dereferences an artifact symlink.
func Xattr(root, name, key string) ([]byte, bool, error) {
	f, err := openData(root, name, true)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	size, err := unix.Fgetxattr(int(f.Fd()), key, nil)
	if errors.Is(err, unix.ENODATA) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if size > 64<<10 {
		return nil, false, ErrLimit
	}
	buf := make([]byte, size)
	n, err := unix.Fgetxattr(int(f.Fd()), key, buf)
	if err != nil {
		return nil, false, err
	}
	return buf[:n], true, nil
}
