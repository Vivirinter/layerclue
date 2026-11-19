// Package distribution builds and verifies local LayerClue release artifacts.
// Metadata is self-reported; authentication requires an external trusted key.
package distribution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

const MaxFileBytes int64 = 64 << 20
const MaxSourceBytes int64 = 128 << 20
const MaxReleaseBytes int64 = 512 << 20

var rootFiles = []string{"go.mod", "go.sum", "README.md", "CHANGELOG.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt", "SECURITY.md", ".gitignore"}
var optionalRootFiles = []string{"CONTRIBUTING.md", ".gitattributes"}

var sourceDirs = []string{"cmd", "internal", "tools", "docs", ".github", "third_party", "examples/demo"}

type SourceManifest struct {
	Schema string            `json:"schema"`
	Files  map[string]string `json:"files"` // relative path -> SHA-256, lowercase hex
}
type Snapshot struct {
	Manifest SourceManifest
	Data     map[string][]byte
}

func digest(b []byte) string                       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonicalJSON(v any) ([]byte, error)          { return json.Marshal(v) }
func (s *Snapshot) ManifestBytes() ([]byte, error) { return canonicalJSON(s.Manifest) }

// Capture reads only the explicit source/documentation inputs, excluding build
// outputs, generated captures and keys. Every address is confined, regular,
// bounded and non-symlink. Builds run on this captured tree, not the live tree.
func Capture(ctx context.Context, root string) (*Snapshot, error) {
	if ctx == nil {
		return nil, errors.New("source capture requires a context")
	}
	s := &Snapshot{Manifest: SourceManifest{Schema: "layerclue.source-inputs/v1", Files: map[string]string{}}, Data: map[string][]byte{}}
	var total int64
	add := func(name string) error {
		if !safeRelative(name) || !utf8.ValidString(name) || len(name) > 4096 {
			return errors.New("invalid source input path")
		}
		if sensitiveSourceName(name) {
			return fmt.Errorf("sensitive-looking source filename refused: %q", name)
		}
		if _, exists := s.Data[name]; exists {
			return nil
		}
		if len(s.Data) >= 10000 {
			return evidence.ErrLimit
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := evidence.OpenRegular(root, name)
		if err != nil {
			return err
		}
		var data bytes.Buffer
		_, err = evidence.Copy(ctx, &data, f, min(16<<20, MaxSourceBytes-total))
		_ = f.Close()
		b := data.Bytes()
		if err != nil {
			return fmt.Errorf("source input %q: %w", name, err)
		}
		total += int64(len(b))
		s.Data[name] = b
		s.Manifest.Files[name] = digest(b)
		return nil
	}
	for _, name := range rootFiles {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	for _, name := range optionalRootFiles {
		if _, err := evidence.Lstat(root, name); err == nil {
			if err := add(name); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	for _, dir := range sourceDirs {
		if err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() && (d.Name() == "__pycache__" || d.Name() == ".pytest_cache") {
				return filepath.SkipDir
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("source input is a symlink: %q", rel)
			}
			if d.IsDir() {
				_, err := evidence.Lstat(root, rel)
				return err
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("source input is not regular: %q", rel)
			}
			return add(rel)
		}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// This filename guard supplements local secret scanning; it cannot recognise
// arbitrary personal content or every possible credential stored in source.
func sensitiveSourceName(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if base == ".env" || strings.HasPrefix(base, ".env.") || base == "id_rsa" || base == "id_ed25519" || base == "credentials.json" || base == "kubeconfig" {
		return true
	}
	for _, suffix := range []string{".key", ".pem", ".p12", ".pfx", ".kubeconfig"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return strings.Contains(base, "private") && strings.HasSuffix(base, ".hex")
}
func (s *Snapshot) Materialise(ctx context.Context, root string) error {
	if ctx == nil {
		return errors.New("source materialisation requires a context")
	}
	names := make([]string, 0, len(s.Data))
	for name := range s.Data {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeRelative(name) {
			return errors.New("invalid snapshot input address")
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := writeNew(target, s.Data[name]); err != nil {
			return err
		}
	}
	return nil
}
func safeRelative(name string) bool {
	return name != "" && filepath.IsLocal(name) && filepath.ToSlash(filepath.Clean(name)) == name && name != "." && !strings.ContainsRune(name, 0)
}
func writeNew(name string, b []byte) error {
	// #nosec G304 -- Destination is constructed only from checked local names inside the owned private build stage.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
