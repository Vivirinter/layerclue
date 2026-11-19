package custody

import (
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
	"strings"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"golang.org/x/sys/unix"
)

const AcquisitionFile = "layerclue-acquisition.json"

func Outside(root, name string) error {
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(name))
	if err != nil {
		return err
	}
	name = filepath.Join(parent, filepath.Base(name))
	rel, err := filepath.Rel(r, name)
	if err != nil {
		return err
	}
	if rel == "." || filepath.IsLocal(rel) {
		return errors.New("output/key must be outside the evidence directory")
	}
	return nil
}

// Collect packages an already prepared, immutable portable case. It does not
// snapshot a running runtime, stop containers or infer missing mount captures.
// Original mode/ownership/attributes are journaled; output never recreates
// executable bits, capabilities or devices. Only required user OverlayFS attrs
// are restored. The caller must treat symlinks as evidence, never follow them.
func Collect(ctx context.Context, source, output, method string, limits Limits, key ed25519.PrivateKey) error {
	source, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if err := Outside(source, output); err != nil {
		return err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output already exists or cannot be checked")
	}
	c, err := casefile.Open(source)
	if err != nil {
		return err
	}
	table, err := c.MountTable()
	if err != nil {
		return err
	}
	stack, missing, err := c.Stack(table)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return errors.New("collect requires all declared overlay layer directories")
	}
	if c.XattrNamespace != "capture" && stack.AttrPrefix != "user.overlay." {
		return errors.New("collect requires portable capture attributes or userxattr; raw trusted OverlayFS metadata must be exported by acquisition")
	}
	if _, err := evidence.Lstat(source, AcquisitionFile); !errors.Is(err, os.ErrNotExist) {
		return errors.New("reserved acquisition journal already exists or cannot be checked")
	}
	original, err := New(ctx, source, method, limits, nil)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".layerclue-collect-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	dst := filepath.Join(stage, "case")
	if err := os.Mkdir(dst, 0700); err != nil {
		return err
	}
	for _, e := range original.Inventory.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.Join(dst, e.Path)
		switch e.Kind {
		case "directory":
			if e.Path != "." {
				if err := os.Mkdir(name, 0700); err != nil {
					return err
				}
			}
		case "file":
			if e.Hardlink != "" {
				if err := os.Link(filepath.Join(dst, e.Hardlink), name); err != nil {
					return err
				}
			} else if err := copyFile(ctx, source, e, name, limits.FileBytes); err != nil {
				return err
			}
		case "symlink":
			if err := os.Symlink(e.Target, name); err != nil {
				return err
			}
		default:
			return errors.New("invalid source entry type")
		}
		for k, v := range e.Xattrs {
			if !strings.HasPrefix(k, "user.overlay.") && !strings.HasPrefix(k, "user.layerclue.overlay.") {
				continue
			}
			raw, err := hex.DecodeString(v)
			if err != nil {
				return err
			}
			if err := unix.Setxattr(name, k, raw, 0); err != nil {
				return err
			}
		}
	}
	if err := Verify(ctx, source, original, limits, nil); err != nil {
		return fmt.Errorf("source changed while packaging: %w", err)
	}
	journal, err := json.MarshalIndent(struct {
		Schema          string `json:"schema"`
		SourceInventory *Seal  `json:"source_inventory"`
		Transform       string `json:"transform"`
	}{"layerclue.acquisition/v1", original, "prepared-case packaging; source authenticity/atomicity asserted by operator; output permissions reduced, ownership/timestamps not restored, only user OverlayFS attrs restored; source metadata retained in this journal"}, "", "  ")
	if err != nil {
		return err
	}
	if len(journal) > MaxInventoryBytes {
		return evidence.ErrLimit
	}
	if err := os.WriteFile(filepath.Join(dst, AcquisitionFile), journal, 0600); err != nil {
		return err
	}
	if _, err := casefile.Open(dst); err != nil {
		return fmt.Errorf("packaged case is invalid: %w", err)
	}
	seal, err := New(ctx, dst, method, limits, key)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(seal, "", "  ")
	if err != nil {
		return err
	}
	if _, err := Decode(data); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "inventory.json"), data, 0600); err != nil {
		return err
	}
	// Publish only after the complete bundle verifies, without replacing anything.
	if err := Verify(ctx, dst, seal, limits, publicKey(key)); err != nil {
		return err
	}
	return unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE)
}

func publicKey(key ed25519.PrivateKey) ed25519.PublicKey {
	if len(key) == 0 {
		return nil
	}
	return key.Public().(ed25519.PublicKey)
}
func copyFile(ctx context.Context, root string, e Entry, dst string, max int64) error {
	src, err := evidence.OpenRegular(root, e.Path)
	if err != nil {
		return err
	}
	defer src.Close()
	// #nosec G304 -- Validated inventory-relative output in the new private stage; no source symlink becomes an output ancestor.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := evidence.Copy(ctx, io.MultiWriter(out, h), src, max)
	if copyErr == nil {
		copyErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
		return errors.New("source bytes changed while copying")
	}
	return nil
}
