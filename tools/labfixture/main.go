// Command labfixture is ONLY a disposable Docker-lab helper, not a supported
// acquisition tool. It runs on self-created fixtures and refuses special files
// other than native OverlayFS whiteouts. Do not use it on incident evidence.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"golang.org/x/sys/unix"
)

type mapping struct {
	Source   string `json:"source"`
	Artifact string `json:"artifact"`
}
type plan struct {
	UID, GID   int
	Mappings   []mapping
	AliasNames []string
	Output     string
	AliasRoot  string
	Raw        bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) != 1 {
		return errors.New("labfixture expects serve, mountinfo or copy")
	}
	if args[0] == "mountinfo" {
		data, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return err
		}
		f, err := os.OpenFile("/capture/mountinfo", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	if args[0] == "serve" {
		for p, s := range map[string]string{"/opt/modified": "changed\n", "/opt/added": "added\n"} {
			if err := os.WriteFile(p, []byte(s), 0600); err != nil {
				return err
			}
		}
		if err := os.Remove("/opt/deleted"); err != nil {
			return err
		}
		data, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return err
		}
		// #nosec G306 G703 -- Fixed destination under the explicitly mounted private synthetic lab output; readable mode lets the receiving lab user inspect it.
		if err := os.WriteFile("/capture/mountinfo", data, 0644); err != nil {
			return err
		}
		// #nosec G306 -- Fixed synthetic readiness marker in private lab output, not incident data.
		if err := os.WriteFile("/capture/ready", []byte("ready"), 0644); err != nil {
			return err
		}
		time.Sleep(10 * time.Minute)
		return nil
	}
	if args[0] != "copy" {
		return errors.New("unknown lab mode")
	}
	if !evidence.CanReadTrusted() {
		return errors.New("lab metadata export requires readable trusted OverlayFS attributes")
	}
	data, err := evidence.ReadFile("/capture", "plan.json", 1<<20)
	if err != nil {
		return err
	}
	var p plan
	if err := evidence.DecodeJSON(data, &p); err != nil {
		return err
	}
	if p.UID < 0 || p.GID < 0 || len(p.Mappings) > 256 {
		return errors.New("invalid lab plan")
	}
	if p.Output == "" {
		p.Output = "case"
	}
	if p.Output != "case" && p.Output != "snapshot" && p.Output != "raw-snapshot" {
		return errors.New("invalid lab output")
	}
	if p.Raw && p.Output != "raw-snapshot" {
		return errors.New("raw lab markers require a separate raw-snapshot output")
	}
	base := filepath.Join("/capture", p.Output)
	if p.AliasRoot == "" {
		p.AliasRoot = "docker-links"
	}
	if evidence.Local(p.AliasRoot) != nil {
		return errors.New("invalid lab alias root")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer func() {
		_ = assignOwner(base, p.UID, p.GID)
	}()
	var files int
	var bytes int64
	var copyTree func(string, string, string, int) error
	copyTree = func(source, rel, destination string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		files++
		if files > 10000 || depth > 128 {
			return evidence.ErrLimit
		}
		st, err := evidence.Lstat(source, rel)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			target, err := evidence.Readlink(source, rel)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, destination); err != nil {
				return err
			}
			return os.Lchown(destination, p.UID, p.GID)
		}
		whiteout := false
		if st.Mode()&os.ModeDevice != 0 {
			stat, ok := st.Sys().(*syscall.Stat_t)
			whiteout = ok && st.Mode()&os.ModeCharDevice != 0 && stat.Rdev == 0
			if !whiteout {
				return errors.New("lab refuses non-whiteout devices")
			}
		}
		if st.IsDir() {
			if err := os.Mkdir(destination, 0700); err != nil {
				return err
			}
		} else if st.Mode().IsRegular() || whiteout {
			if whiteout && p.Raw {
				if err := unix.Mknod(destination, unix.S_IFCHR|0600, 0); err != nil {
					return err
				}
			} else {
				// #nosec G304 -- Recursive synthetic copy builds this destination only from validated local directory entries, in private output.
				dst, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				if !whiteout {
					src, err := evidence.OpenRegular(source, rel)
					if err != nil {
						_ = dst.Close()
						return err
					}
					n, copyErr := evidence.Copy(ctx, dst, src, (64<<20)-bytes)
					bytes += n
					_ = src.Close()
					if copyErr != nil {
						_ = dst.Close()
						return copyErr
					}
				}
				if err := dst.Close(); err != nil {
					return err
				}
			}

		} else {
			return errors.New("lab refuses special files")
		}
		if whiteout && !p.Raw {
			if err := unix.Setxattr(destination, "user.layerclue.overlay.whiteout", nil, 0); err != nil {
				return err
			}
		} else if !whiteout {
			for _, suffix := range []string{"whiteout", "opaque", "metacopy", "redirect"} {
				value, exists, err := evidence.Xattr(source, rel, "trusted.overlay."+suffix)
				if err != nil {
					return err
				}
				if exists {
					prefix := "user.layerclue.overlay."
					if p.Raw {
						prefix = "trusted.overlay."
					}
					if err := unix.Setxattr(destination, prefix+suffix, value, 0); err != nil {
						return err
					}
				}
			}
		}
		if st.IsDir() {
			dir, err := evidence.OpenDir(source, rel)
			if err != nil {
				return err
			}
			defer dir.Close()
			for {
				names, err := dir.Readdirnames(128)
				for _, name := range names {
					if name == "." || name == ".." || strings.ContainsRune(name, '/') {
						return errors.New("invalid lab source entry")
					}
					if err := copyTree(source, filepath.Join(rel, name), filepath.Join(destination, name), depth+1); err != nil {
						return err
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
			}
		}
		return os.Chown(destination, p.UID, p.GID)
	}
	for i, m := range p.Mappings {
		if m.Source != "/sources/"+strconv.Itoa(i) || evidence.Local(m.Artifact) != nil {
			return errors.New("invalid lab mapping")
		}
		dest := filepath.Join(base, m.Artifact)
		// #nosec G301 -- Synthetic capture parents need traversal by the receiving lab user; the capture root is private.
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		st, err := os.Lstat(m.Source)
		if err != nil {
			return err
		}
		if st.Mode().IsRegular() {
			src, err := os.Open(m.Source)
			if err != nil {
				return err
			}
			// #nosec G304 -- Artifact is validated local and confined to this helper's synthetic output; final entries cannot be replaced.
			dst, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				_ = src.Close()
				return err
			}
			n, copyErr := evidence.Copy(ctx, dst, src, (64<<20)-bytes)
			bytes += n
			_ = src.Close() // The source is read-only; preserve a copy failure.
			closeErr := dst.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		} else if err := copyTree(m.Source, ".", dest, 0); err != nil {
			return fmt.Errorf("copy %s: %w", m.Source, err)
		}
	}
	if len(p.AliasNames) > 256 {
		return evidence.ErrLimit
	}
	if len(p.AliasNames) > 0 {
		if err := os.MkdirAll(filepath.Join(base, p.AliasRoot), 0700); err != nil {
			return err
		}
	}
	for _, name := range p.AliasNames {
		if len(name) != 26 || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			return errors.New("invalid lab alias")
		}
		target, err := evidence.Readlink("/aliases", name)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, filepath.Join(base, p.AliasRoot, name)); err != nil {
			return err
		}
	}

	return assignOwner(base, p.UID, p.GID)
}

// Restrict ownership changes to the generated output, including when an
// intermediate directory is replaced by a symlink during traversal.
func assignOwner(base string, uid, gid int) error {
	dir, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer dir.Close()
	return fs.WalkDir(dir.FS(), ".", func(pth string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return dir.Lchown(pth, uid, gid)
	})
}
