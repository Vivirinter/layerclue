// Package oci verifies captured image bytes without fetching or extracting them.
// Digests bind artifacts to each other, not to a trusted publisher or to every
// byte of an already-unpacked snapshot.
package oci

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

const (
	ManifestType = "application/vnd.oci.image.manifest.v1+json"
	ConfigType   = "application/vnd.oci.image.config.v1+json"
	TarType      = "application/vnd.oci.image.layer.v1.tar"
	GzipType     = "application/vnd.oci.image.layer.v1.tar+gzip"
)

type Limits struct{ BlobBytes, ExpandedBytes, TotalBlobBytes, TotalExpandedBytes int64 }

func DefaultLimits() Limits {
	return Limits{BlobBytes: 256 << 20, ExpandedBytes: 512 << 20, TotalBlobBytes: 1 << 30, TotalExpandedBytes: 1 << 30}
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}
type config struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type Layer struct {
	MediaType    string `json:"media_type"`
	Index        int    `json:"index"`
	Digest       string `json:"digest"`
	DiffID       string `json:"diff_id"`
	ChainID      string `json:"chain_id"`
	Artifact     string `json:"artifact"`
	Size         int64  `json:"size"`
	ExpandedSize int64  `json:"expanded_size"`
}
type Image struct {
	ManifestSize     int64   `json:"manifest_size"`
	ManifestDigest   string  `json:"manifest_digest"`
	ManifestArtifact string  `json:"manifest_artifact"`
	ConfigDigest     string  `json:"config_digest"`
	ConfigArtifact   string  `json:"config_artifact"`
	Architecture     string  `json:"architecture"`
	Layers           []Layer `json:"layers"`
}

func ValidDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return false
	}
	hexpart := strings.TrimPrefix(digest, "sha256:")
	_, err := hex.DecodeString(hexpart)
	return err == nil && strings.ToLower(hexpart) == hexpart
}

func ChainID(parent, diffID string) string {
	if parent == "" {
		return diffID
	}
	sum := sha256.Sum256([]byte(parent + " " + diffID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func artifact(contentRoot, digest string) (string, error) {
	if err := evidence.Local(contentRoot); err != nil {
		return "", err
	}
	if !ValidDigest(digest) {
		return "", fmt.Errorf("unsupported or invalid OCI digest %q", digest)
	}
	return filepath.ToSlash(filepath.Join(contentRoot, "blobs", "sha256", digest[len("sha256:"):])), nil
}

func readJSONBlob(ctx context.Context, root, contentRoot, digest string, max int64) ([]byte, string, error) {
	name, err := artifact(contentRoot, digest)
	if err != nil {
		return nil, "", err
	}
	f, err := evidence.OpenRegular(root, name)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	data, err := evidence.ReadAll(&contextReader{ctx: ctx, r: f}, max)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, "", errors.New("OCI JSON digest mismatch")
	}
	return data, name, nil
}

// Verify checks manifest/config and every layer digest/diffID under independent
// compressed, per-layer expanded and cumulative expanded budgets. Tar entries
// are not materialised or validated as a filesystem.
func Verify(ctx context.Context, root, contentRoot, digest string, limits Limits) (*Image, error) {
	if ctx == nil {
		return nil, errors.New("OCI verification requires a context")
	}
	if limits.BlobBytes <= 0 || limits.ExpandedBytes <= 0 || limits.TotalBlobBytes <= 0 || limits.TotalExpandedBytes <= 0 {
		return nil, evidence.ErrLimit
	}
	data, manifestPath, err := readJSONBlob(ctx, root, contentRoot, digest, 1<<20)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := evidence.DecodeExtensibleJSON(data, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion != 2 || (m.MediaType != "" && m.MediaType != ManifestType && m.MediaType != "application/vnd.docker.distribution.manifest.v2+json") {
		return nil, errors.New("expected a single-platform OCI/Docker v2 image manifest")
	}
	if m.Config.MediaType != ConfigType && m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return nil, errors.New("unsupported image config media type")
	}
	if m.Config.Size <= 0 || m.Config.Size > 4<<20 || len(m.Layers) > 256 || m.Layers == nil {
		return nil, errors.New("invalid image descriptors or layer count")
	}
	configData, configPath, err := readJSONBlob(ctx, root, contentRoot, m.Config.Digest, 4<<20)
	if err != nil {
		return nil, err
	}
	if int64(len(configData)) != m.Config.Size {
		return nil, errors.New("OCI config size mismatch")
	}
	var c config
	if err := evidence.DecodeExtensibleJSON(configData, &c); err != nil {
		return nil, err
	}
	if c.OS != "linux" || c.Architecture == "" || len(c.Architecture) > 128 || c.RootFS.Type != "layers" || c.RootFS.DiffIDs == nil || len(c.RootFS.DiffIDs) != len(m.Layers) {
		return nil, errors.New("unsupported or inconsistent image rootfs configuration")
	}
	result := &Image{ManifestSize: int64(len(data)), ManifestDigest: digest, ManifestArtifact: manifestPath, ConfigDigest: m.Config.Digest, ConfigArtifact: configPath, Architecture: c.Architecture, Layers: make([]Layer, 0, len(m.Layers))}
	var total int64
	var blobTotal int64
	var chain string
	for i, desc := range m.Layers {
		if desc.Size <= 0 || desc.Size > limits.TotalBlobBytes-blobTotal {
			return nil, evidence.ErrLimit
		}
		if !ValidDigest(c.RootFS.DiffIDs[i]) {
			return nil, errors.New("invalid image diffID")
		}
		name, err := artifact(contentRoot, desc.Digest)
		if err != nil {
			return nil, err
		}
		expanded, err := verifyLayer(ctx, root, name, desc, c.RootFS.DiffIDs[i], limits, total)
		if err != nil {
			return nil, fmt.Errorf("OCI layer %d: %w", i, err)
		}
		total += expanded
		blobTotal += desc.Size
		chain = ChainID(chain, c.RootFS.DiffIDs[i])
		result.Layers = append(result.Layers, Layer{MediaType: desc.MediaType, Index: i, Digest: desc.Digest, DiffID: c.RootFS.DiffIDs[i], ChainID: chain, Artifact: name, Size: desc.Size, ExpandedSize: expanded})
	}
	return result, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func verifyLayer(ctx context.Context, root, name string, d descriptor, diffID string, limits Limits, total int64) (int64, error) {
	if d.Size <= 0 || d.Size > limits.BlobBytes {
		return 0, evidence.ErrLimit
	}
	compressed := false
	switch d.MediaType {
	case TarType, "application/vnd.oci.image.layer.nondistributable.v1.tar":
	case GzipType, "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		compressed = true
	default:
		return 0, fmt.Errorf("unsupported layer media type %q", d.MediaType)
	}
	f, err := evidence.OpenRegular(root, name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if before.Size() != d.Size {
		return 0, errors.New("layer blob size mismatch")
	}
	compressedHash := sha256.New()
	rawLimit := &io.LimitedReader{R: &contextReader{ctx: ctx, r: f}, N: d.Size + 1}
	raw := io.TeeReader(rawLimit, compressedHash)
	var reader io.Reader = raw
	if compressed {
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		reader = gz
	}
	h := sha256.New()
	remaining := limits.TotalExpandedBytes - total
	if remaining > limits.ExpandedBytes {
		remaining = limits.ExpandedBytes
	}
	if remaining <= 0 {
		return 0, evidence.ErrLimit
	}
	expanded, err := evidence.Copy(ctx, h, reader, remaining)
	if err != nil {
		return 0, err
	}
	if d.Size+1-rawLimit.N != d.Size || "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != d.Digest {
		return 0, errors.New("layer blob size/digest mismatch")
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != diffID {
		return 0, errors.New("uncompressed layer diffID mismatch")
	}
	after, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !sameFileState(before, after) {
		return 0, errors.New("OCI layer changed during verification")
	}
	return expanded, nil
}

func sameFileState(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
