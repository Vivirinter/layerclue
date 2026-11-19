package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

var ErrUnsupportedPath = errors.New("unsupported OCI filesystem semantics")

const maxTreeEntries = 100000
const maxTreeNames = 16 << 20

type File struct {
	Path         string `json:"path"`
	ResolvedPath string `json:"resolved_path"`
	Status       string `json:"status"`
	Kind         string `json:"kind,omitempty"`
	Size         int64  `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	LayerDigest  string `json:"layer_digest,omitempty"`
}
type node struct {
	kind, target, hash, digest string
	size                       int64
}
type changes struct {
	nodes         map[string]node
	whiteouts     []string
	opaque        []string
	markerParents map[string]bool
}

// SelectFile interprets OCI tar entries in memory, without extraction. Every
// stream is rechecked against its descriptor/diffID in the SAME pass that reads
// tar entries. It verifies file type/content only, not ownership or xattrs.
// Relevant hardlinks and sparse encodings fail closed rather than claiming
// filesystem equivalence. Publisher trust and original launch are out of scope.
func SelectFile(ctx context.Context, root, contentRoot, digest, target string, limits Limits) (*File, error) {
	if target == "" || !strings.HasPrefix(target, "/") || len(target) > 4096 || !utf8.ValidString(target) || strings.ContainsRune(target, 0) {
		return nil, errors.New("invalid container path")
	}
	image, err := Verify(ctx, root, contentRoot, digest, limits)
	if err != nil {
		return nil, err
	}
	tree := map[string]node{"": {kind: "directory"}}
	var total int64
	for _, layer := range image.Layers {
		change, err := readChanges(ctx, root, layer, limits, total)
		if err != nil {
			return nil, fmt.Errorf("OCI tar layer %d: %w", layer.Index, err)
		}
		total += layer.ExpandedSize
		if err := apply(ctx, tree, change); err != nil {
			return nil, err
		}
	}
	result, err := lookup(tree, target)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func archivePath(s string, dir bool) (string, error) {
	if len(s) > 4096 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) || strings.HasPrefix(s, "/") {
		return "", errors.New("invalid/absolute OCI tar path")
	}
	if len(strings.Split(s, "/")) > 128 {
		return "", evidence.ErrLimit
	}
	for _, p := range strings.Split(s, "/") {
		if p == ".." {
			return "", errors.New("OCI tar path contains '..'")
		}
	}
	s = path.Clean(s)
	if s == "." {
		if dir {
			return "", nil
		}
		return "", errors.New("non-directory OCI root entry")
	}
	return s, nil
}

type zeroPadding struct{}

func (zeroPadding) Write(b []byte) (int, error) {
	for _, v := range b {
		if v != 0 {
			return 0, errors.New("non-zero data after OCI tar end marker")
		}
	}
	return len(b), nil
}

func readChanges(ctx context.Context, root string, layer Layer, limits Limits, total int64) (*changes, error) {
	f, err := evidence.OpenRegular(root, layer.Artifact)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != layer.Size {
		return nil, errors.New("layer changed before tar interpretation")
	}
	compressedHash := sha256.New()
	rawLimit := &io.LimitedReader{R: &contextReader{ctx: ctx, r: f}, N: layer.Size + 1}
	raw := io.TeeReader(rawLimit, compressedHash)
	// Media type came from the verified manifest; never sniff a raw tar as gzip.
	var expanded io.Reader = raw
	if layer.MediaType == GzipType || layer.MediaType == "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip" || layer.MediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip" || layer.MediaType == "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip" {
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		expanded = gz
	}
	budget := min(limits.ExpandedBytes, limits.TotalExpandedBytes-total)
	if budget <= 0 {
		return nil, evidence.ErrLimit
	}
	expandedLimit := &io.LimitedReader{R: expanded, N: budget + 1}
	expandedHash := sha256.New()
	stream := io.TeeReader(expandedLimit, expandedHash)
	tr := tar.NewReader(stream)
	out := &changes{nodes: map[string]node{}, markerParents: map[string]bool{}}
	seen := map[string]bool{}
	names := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(seen) >= maxTreeEntries {
			return nil, evidence.ErrLimit
		}
		name, err := archivePath(h.Name, h.Typeflag == tar.TypeDir)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, errors.New("duplicate OCI tar path")
		}
		seen[name] = true
		names += len(name) + len(h.Linkname)
		if names > maxTreeNames || len(h.Linkname) > 4096 {
			return nil, evidence.ErrLimit
		}
		for key := range h.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse") || strings.HasPrefix(key, "SCHILY.realsize") {
				return nil, fmt.Errorf("%w: sparse tar", ErrUnsupportedPath)
			}
		}
		if h.Typeflag == tar.TypeGNUSparse {
			return nil, fmt.Errorf("%w: sparse tar", ErrUnsupportedPath)
		}
		if strings.HasPrefix(path.Base(name), ".wh.") {
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || h.Size != 0 {
				return nil, errors.New("invalid OCI whiteout entry")
			}
			dir := path.Dir(name)
			if dir == "." {
				dir = ""
			}
			out.markerParents[dir] = true
			if path.Base(name) == ".wh..wh..opq" {
				out.opaque = append(out.opaque, dir)
			} else {
				base := strings.TrimPrefix(path.Base(name), ".wh.")
				if base == "" || base == "." || base == ".." {
					return nil, errors.New("invalid OCI whiteout name")
				}
				out.whiteouts = append(out.whiteouts, path.Join(dir, base))
			}
			continue
		}
		n := node{digest: layer.Digest, size: h.Size}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > limits.ExpandedBytes {
				return nil, evidence.ErrLimit
			}
			n.kind = "file"
			hash := sha256.New()
			got, err := evidence.Copy(ctx, hash, tr, limits.ExpandedBytes)
			if err != nil {
				return nil, err
			}
			if got != h.Size {
				return nil, errors.New("short OCI tar file")
			}
			n.hash = hex.EncodeToString(hash.Sum(nil))
		case tar.TypeDir:
			n.kind = "directory"
		case tar.TypeSymlink:
			if !utf8.ValidString(h.Linkname) || h.Linkname == "" || strings.ContainsRune(h.Linkname, 0) {
				return nil, errors.New("invalid OCI symlink")
			}
			n.kind = "symlink"
			n.target = h.Linkname
		case tar.TypeLink:
			if _, err := archivePath(h.Linkname, false); err != nil {
				return nil, err
			}
			n.kind = "hardlink"
			n.target = h.Linkname
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			n.kind = "special"
		default:
			return nil, fmt.Errorf("%w: tar entry type %d", ErrUnsupportedPath, h.Typeflag)
		}
		out.nodes[name] = n
	}
	if _, err := evidence.Copy(ctx, zeroPadding{}, stream, budget); err != nil {
		return nil, err
	}
	expandedBytes := budget + 1 - expandedLimit.N
	if expandedBytes > budget || expandedBytes != layer.ExpandedSize {
		return nil, errors.New("OCI expanded stream size mismatch")
	}
	// Drain raw bytes buffered beyond gzip EOF and reject descriptor changes.
	if _, err := evidence.Copy(ctx, io.Discard, raw, limits.BlobBytes); err != nil {
		return nil, err
	}
	if layer.Size+1-rawLimit.N != layer.Size || "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != layer.Digest || "sha256:"+hex.EncodeToString(expandedHash.Sum(nil)) != layer.DiffID {
		return nil, errors.New("OCI bytes changed during tar interpretation")
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("OCI blob changed during tar interpretation")
	}
	return out, nil
}

// apply walks inherited paths once; it avoids a full-tree scan per whiteout
// or replacement (quadratic work on hostile archives).
func apply(ctx context.Context, tree map[string]node, c *changes) error {
	whiteouts := map[string]bool{}
	opaque := map[string]bool{}
	for _, p := range c.whiteouts {
		whiteouts[p] = true
	}
	for _, p := range c.opaque {
		opaque[p] = true
	}
	for name := range tree {
		if err := ctx.Err(); err != nil {
			return err
		}
		drop := whiteouts[name] || name != "" && opaque[""]
		for parent := path.Dir(name); parent != "." && parent != "/" && parent != ""; parent = path.Dir(parent) {
			if whiteouts[parent] || opaque[parent] {
				drop = true
				break
			}
			if replacement, ok := c.nodes[parent]; ok && replacement.kind != "directory" {
				drop = true
				break
			}
		}
		if drop {
			delete(tree, name)
		}
	}
	names := make([]string, 0, len(c.nodes))
	for p := range c.nodes {
		names = append(names, p)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		if names[i] == "" {
			a = -1
		}
		if names[j] == "" {
			b = -1
		}
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	used := 0
	for p, n := range tree {
		used += len(p) + len(n.target)
	}
	set := func(p string, n node) error {
		if old, ok := tree[p]; ok {
			used -= len(p) + len(old.target)
		} else if len(tree) >= maxTreeEntries {
			return evidence.ErrLimit
		}
		used += len(p) + len(n.target)
		if used > maxTreeNames {
			return evidence.ErrLimit
		}
		tree[p] = n
		return nil
	}
	for _, p := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := c.nodes[p]
		var ancestors []string
		for parent := path.Dir(p); parent != "." && parent != "/" && parent != ""; parent = path.Dir(parent) {
			ancestors = append(ancestors, parent)
		}
		for i := len(ancestors) - 1; i >= 0; i-- {
			parent := ancestors[i]
			if old, ok := tree[parent]; ok {
				if old.kind != "directory" {
					return fmt.Errorf("%w: non-directory tar parent %q", ErrUnsupportedPath, parent)
				}
			} else {
				if err := set(parent, node{kind: "directory", digest: n.digest}); err != nil {
					return err
				}
			}
		}
		if err := set(p, n); err != nil {
			return err
		}
	}
	// A whiteout's directory must exist even when the tar omits its header.
	// Refuse inherited non-directory parents unless an explicit directory entry
	// replaced them; never follow a lower symlink while applying a layer.
	for parent := range c.markerParents {
		if parent == "" {
			continue
		}
		parts := strings.Split(parent, "/")
		for i := range parts {
			p := strings.Join(parts[:i+1], "/")
			if old, ok := tree[p]; ok {
				if old.kind != "directory" {
					return fmt.Errorf("%w: whiteout parent is not a directory", ErrUnsupportedPath)
				}
			} else if err := set(p, node{kind: "directory"}); err != nil {
				return err
			}
		}
	}

	return nil
}

func lookup(tree map[string]node, target string) (*File, error) {
	parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
	var current []string
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(current) > 0 {
				current = current[:len(current)-1]
			}
			continue
		}
		current = append(current, part)
		name := strings.Join(current, "/")
		n, ok := tree[name]
		if !ok {
			return &File{Path: target, ResolvedPath: "/" + name, Status: "absent"}, nil
		}
		if n.kind == "hardlink" {
			return nil, fmt.Errorf("%w: selected path traverses a hardlink", ErrUnsupportedPath)
		}
		if n.kind == "symlink" {
			links++
			if links > 40 {
				return nil, errors.New("OCI symlink expansion limit exceeded")
			}
			current = current[:len(current)-1]
			if strings.HasPrefix(n.target, "/") {
				current = nil
			}
			parts = append(strings.Split(n.target, "/"), parts...)
			if len(parts) > 8192 {
				return nil, evidence.ErrLimit
			}
			continue
		}
		if len(parts) > 0 && n.kind != "directory" {
			return nil, errors.New("OCI path traverses a non-directory")
		}
	}
	name := strings.Join(current, "/")
	n, ok := tree[name]
	if !ok {
		return &File{Path: target, ResolvedPath: "/" + name, Status: "absent"}, nil
	}
	return &File{Path: target, ResolvedPath: "/" + name, Status: "present", Kind: n.kind, Size: n.size, SHA256: n.hash, LayerDigest: n.digest}, nil
}
