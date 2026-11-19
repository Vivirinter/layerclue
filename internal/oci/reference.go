package oci

import (
	"context"
	"errors"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

type Reference struct {
	Digest       string
	Artifact     string
	Kind         string
	ManifestSize int64
	Architecture string
}

// VerifyReference accepts a direct platform manifest or one captured OCI index
// / Docker manifest list containing it. Selection is explicit, not heuristic.
// Nested indexes, ambiguous descriptors and external URL resolution are refused.
// Direct equality only establishes the reference relation; the caller must
// still run Verify to check candidate bytes, config and layers.
func VerifyReference(ctx context.Context, root, contentRoot, reference, candidate string) (*Reference, error) {
	if ctx == nil {
		return nil, errors.New("image reference verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ValidDigest(reference) || !ValidDigest(candidate) {
		return nil, errors.New("image reference/candidate digest is unavailable or unsupported")
	}
	if reference == candidate {
		name, err := artifact(contentRoot, candidate)
		if err != nil {
			return nil, err
		}
		return &Reference{Digest: reference, Artifact: name, Kind: "direct"}, nil
	}
	data, name, err := readJSONBlob(ctx, root, contentRoot, reference, 1<<20)
	if err != nil {
		return nil, err
	}
	var index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			descriptor
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := evidence.DecodeExtensibleJSON(data, &index); err != nil {
		return nil, err
	}
	if index.SchemaVersion != 2 || (index.MediaType != "application/vnd.oci.image.index.v1+json" && index.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json") || len(index.Manifests) == 0 || len(index.Manifests) > 1024 {
		return nil, errors.New("captured image target is not a supported OCI index/manifest list")
	}
	var result *Reference
	for _, entry := range index.Manifests {
		if entry.Digest != candidate {
			continue
		}
		if result != nil {
			return nil, errors.New("ambiguous candidate descriptors in image index")
		}
		if entry.Size <= 0 || entry.Size > 1<<20 || (entry.MediaType != ManifestType && entry.MediaType != "application/vnd.docker.distribution.manifest.v2+json") || entry.Platform.OS != "linux" || entry.Platform.Architecture == "" || len(entry.Platform.Architecture) > 128 {
			return nil, errors.New("unsupported candidate platform/manifest descriptor")
		}
		result = &Reference{Digest: reference, Artifact: name, Kind: "index_member", ManifestSize: entry.Size, Architecture: entry.Platform.Architecture}
	}
	if result == nil {
		return nil, errors.New("candidate manifest is not referenced by the captured image index")
	}
	return result, nil
}
