// Package docker interprets a bounded, saved Docker Engine inspect response.
// It never connects to a daemon. Metadata consistency is not acquisition trust.
package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/oci"
	"github.com/Vivirinter/layerclue/internal/overlay"
)

type Mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type Alias struct {
	Artifact string `json:"artifact"`
	Address  string `json:"address"`
	Target   string `json:"target"`
}

type Record struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"` // image CONFIG digest, never a manifest digest
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	GraphDriver struct {
		Name string            `json:"Name"`
		Data map[string]string `json:"Data"`
	} `json:"GraphDriver"`
	Mounts []Mount `json:"Mounts"`
	SHA256 string  `json:"-"`
}

func text(s string) bool     { return len(s) <= 4096 && utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
func hostPath(s string) bool { return text(s) && strings.HasPrefix(s, "/") && path.Clean(s) == s }
func FullID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && strings.ToLower(s) == s
}

// AliasName accepts only classic overlay2's short alias directory/name.
func AliasName(upper, address string) (string, error) {
	base := path.Dir(path.Dir(upper))
	name := path.Base(address)
	if !hostPath(upper) || !hostPath(address) || path.Dir(address) != path.Join(base, "l") || len(name) != 26 || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		return "", errors.New("invalid Docker overlay2 lower alias address")
	}
	return name, nil
}

// CheckAliasTarget compares link text lexically. It never follows a link.
func CheckAliasTarget(upper, address, wanted, target string) error {
	if _, err := AliasName(upper, address); err != nil {
		return err
	}
	parts := strings.Split(target, "/")
	base := path.Dir(path.Dir(upper))
	if len(parts) != 3 || parts[0] != ".." || parts[2] != "diff" || parts[1] == "" || parts[1] == "." || parts[1] == ".." || !hostPath(wanted) || path.Join(base, "l", target) != wanted {
		return errors.New("saved Docker alias does not name the expected inspect layer")
	}
	return nil
}

func Read(root, artifact, id string) (*Record, error) {
	if !FullID(id) {
		return nil, errors.New("Docker requires a full lowercase 64-hex container ID")
	}
	b, err := evidence.ReadFile(root, artifact, evidence.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	var records []Record
	if err := evidence.DecodeExtensibleJSON(b, &records); err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, errors.New("docker_inspect must contain exactly one container record")
	}
	r := &records[0]
	if r.ID != id {
		return nil, errors.New("Docker inspect container ID differs from case container_id")
	}
	if !oci.ValidDigest(r.Image) || !text(r.Config.Image) {
		return nil, errors.New("invalid Docker image identity")
	}
	if r.GraphDriver.Name != "overlay2" {
		return nil, fmt.Errorf("unsupported Docker storage driver %q: only captured classic overlay2 is supported", r.GraphDriver.Name)
	}
	if len(r.GraphDriver.Data) > 32 || len(r.Mounts) > 8192 {
		return nil, evidence.ErrLimit
	}
	if !hostPath(r.GraphDriver.Data["UpperDir"]) {
		return nil, errors.New("Docker overlay2 UpperDir is unavailable or invalid")
	}
	lower := r.GraphDriver.Data["LowerDir"]
	if lower == "" {
		return nil, errors.New("Docker overlay2 LowerDir is unavailable")
	}
	parts := strings.Split(lower, ":")
	// The required writable upper layer also consumes one stack position.
	if len(parts)+1 > overlay.MaxLayers {
		return nil, evidence.ErrLimit
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if !hostPath(p) || seen[p] {
			return nil, errors.New("invalid/duplicate Docker lower directory")
		}
		seen[p] = true
	}
	seen = map[string]bool{}
	for _, m := range r.Mounts {
		if m.Type != "bind" && m.Type != "volume" && m.Type != "tmpfs" {
			return nil, fmt.Errorf("unsupported Docker mount type %q", m.Type)
		}
		if !hostPath(m.Destination) || seen[m.Destination] || (m.Type != "tmpfs" && !hostPath(m.Source)) {
			return nil, errors.New("invalid/duplicate Docker mount mapping")
		}
		seen[m.Destination] = true
	}
	sum := sha256.Sum256(b)
	r.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// CheckStack checks literal captured addresses. Aliases must already be
// materialised by acquisition: it never follows Docker overlay2/l symlinks.
func (r *Record) CheckStack(root mounts.Entry) error {
	return r.CheckStackWithAliases(root, nil)
}

func (r *Record) CheckStackWithAliases(root mounts.Entry, resolve func(string, string) error) error {
	if root.FSType != "overlay" || root.SuperValue("upperdir") != r.GraphDriver.Data["UpperDir"] {
		return errors.New("Docker UpperDir and captured root mount disagree")
	}
	a, b := root.LowerDirs(), strings.Split(r.GraphDriver.Data["LowerDir"], ":")
	if len(a) != len(b) {
		return errors.New("Docker lower stack length differs from captured mountinfo")
	}
	for i := range a {
		if a[i] != b[i] {
			if resolve == nil {
				return fmt.Errorf("Docker lower stack order/path mismatch at %d", i)
			}
			if err := resolve(a[i], b[i]); err != nil {
				return fmt.Errorf("Docker lower alias %d: %w", i, err)
			}
		}
	}
	return nil
}
