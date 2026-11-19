// Package signing loads explicit external Ed25519 trust keys. No key is
// auto-discovered from a case or distribution bundle.
package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

// Read accepts a 32-byte hex private seed or public key. Physical symlinks are
// refused and private seeds must have owner-only permissions.
func Read(name string, private bool) ([]byte, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	f, err := evidence.OpenRegular(filepath.Dir(abs), filepath.Base(abs))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || private && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key must be a regular file; private key requires owner-only permissions")
	}
	// Inspect permissions and read bytes from the same pinned descriptor; a
	// pathname replacement must not substitute a different key after the check.
	b, err := evidence.ReadAll(f, 256)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("key must be 32 hex-encoded bytes (private seed or public key)")
	}
	if private {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	return raw, nil
}

// Outside refuses a trust/signing key placed inside the selected evidence or
// release tree. Trust is selected separately from downloaded content.
func Outside(root, name string) error {
	basePath, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	base, err := filepath.EvalSymlinks(basePath)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, filepath.Join(parent, filepath.Base(absolute)))
	if err != nil {
		return err
	}
	if rel == "." || filepath.IsLocal(rel) {
		return errors.New("signing/trust key must be outside the source or release directory")
	}
	return nil
}
