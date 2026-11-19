package analysis

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/containerd"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/oci"
	"github.com/Vivirinter/layerclue/internal/overlay"
)

const imageProofScope = "verified blobs and consistent captured image/snapshot metadata; original launch configuration, unpacked file equivalence and publisher authenticity are not proven"

func attachImageProvenance(ctx context.Context, c *casefile.Case, id *casefile.Identity, stack overlay.Stack, rootMount mounts.Entry, rep *model.Report) {
	if c.ImageProvenance == nil {
		return
	}
	config := c.ImageProvenance
	proof := &model.ImageProvenance{Status: "unverified", Scope: imageProofScope, ManifestDigest: config.ManifestDigest}
	rep.ImageProvenance = proof
	fail := func(err error) {
		proof.Error = err.Error()
		rep.Incomplete = true
		rep.Missing = append(rep.Missing, "image provenance: "+err.Error())
	}
	if id == nil || id.ContainerID == "" {
		fail(errors.New("no unambiguous container identity"))
		return
	}
	if id.ProvenanceError != "" {
		fail(errors.New(id.ProvenanceError))
		return
	}
	if !oci.ValidDigest(id.MetadataSHA256) || !oci.ValidDigest(id.SnapshotterSHA256) {
		fail(errors.New("snapshot source checksums are unavailable"))
		return
	}
	if err := checkSnapshotPaths(c, stack, id.SnapshotChain); err != nil {
		fail(err)
		return
	}
	reference, err := oci.VerifyReference(ctx, c.Root, config.ContentRoot, id.ImageDigest, config.ManifestDigest)
	if err != nil {
		fail(err)
		return
	}
	image, err := oci.Verify(ctx, c.Root, config.ContentRoot, config.ManifestDigest, oci.DefaultLimits())
	if err != nil {
		fail(err)
		return
	}
	if reference.Kind == "index_member" && (reference.ManifestSize != image.ManifestSize || reference.Architecture != image.Architecture) {
		fail(errors.New("image index descriptor and platform manifest/config disagree"))
		return
	}
	associations, err := associateImage(c, stack, id.SnapshotChain, image)
	if err != nil {
		fail(err)
		return
	}
	proof.Status = "verified_metadata_association"
	proof.ConfigDigest = image.ConfigDigest
	proof.ReferenceDigest = reference.Digest
	proof.ReferenceKind = reference.Kind
	proof.Layers = associations
	for _, location := range []*model.Location{rep.Visible, rep.Image} {
		if location != nil && location.Provider == "overlay_layer" && location.LayerIndex >= 0 && location.LayerIndex < len(associations) {
			location.LayerDigest = associations[location.LayerIndex].Digest
			location.LayerAssociation = "captured_metadata"
		}
	}
	var deps []string
	add := func(kind, artifact string, strength model.Strength, value map[string]any) {
		factID := "image-proof-" + strconv.Itoa(len(rep.Facts)+1)
		rep.Facts = append(rep.Facts, model.Fact{ID: factID, Kind: kind, Source: model.Source{Artifact: artifact}, Strength: strength, Value: value})
		deps = append(deps, factID)
	}
	add("oci_manifest", image.ManifestArtifact, model.Observed, map[string]any{"sha256": image.ManifestDigest, "config_digest": image.ConfigDigest, "layer_count": len(image.Layers)})
	if reference.Kind == "index_member" {
		add("oci_index_reference", reference.Artifact, model.Observed, map[string]any{"sha256": reference.Digest, "manifest_digest": image.ManifestDigest, "manifest_size": reference.ManifestSize, "architecture": reference.Architecture})
	}
	diffs := make([]string, 0, len(image.Layers))
	for _, layer := range image.Layers {
		diffs = append(diffs, layer.DiffID)
	}
	add("oci_config", image.ConfigArtifact, model.Observed, map[string]any{"sha256": image.ConfigDigest, "diff_ids": diffs, "os": "linux", "architecture": image.Architecture})
	logical := make([]map[string]any, 0, len(id.SnapshotChain))
	storage := make([]map[string]any, 0, len(id.SnapshotChain))
	for _, rec := range id.SnapshotChain {
		logical = append(logical, map[string]any{"key": rec.Key, "parent": rec.Parent, "name": rec.BackendKey})
		storage = append(storage, map[string]any{"key": rec.BackendKey, "parent": rec.BackendParent, "id": rec.DiskID, "kind": rec.Kind})
	}
	add("runtime_snapshot_chain", c.MetadataRef, model.Observed, map[string]any{"sha256": id.MetadataSHA256, "namespace": id.Namespace, "container_id": id.ContainerID, "snapshot_key": id.SnapshotKey, "records": logical})
	add("storage_snapshot_chain", config.SnapshotterMetadata, model.Observed, map[string]any{"sha256": id.SnapshotterSHA256, "records": storage})
	add("mountinfo_snapshot_stack", c.MountinfoRef, model.Observed, map[string]any{"line": rootMount.Line, "lowerdir": rootMount.LowerDirs(), "upperdir": rootMount.SuperValue("upperdir")})
	for _, layer := range image.Layers {
		add("oci_layer_identity", layer.Artifact, model.Derived, map[string]any{"sha256": layer.Digest, "diff_id": layer.DiffID, "chain_id": layer.ChainID, "blob_bytes": layer.Size, "expanded_bytes": layer.ExpandedSize})
	}
	rep.Claims = append(rep.Claims, model.Claim{Kind: "snapshot_image_layer_association", Answer: image.ManifestDigest, DependsOn: deps, Strength: model.Derived})
}

func lowerRecords(stack overlay.Stack, chain []containerd.SnapshotRecord) ([]containerd.SnapshotRecord, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty snapshot chain")
	}
	hasUpper := len(stack.Layers) > 0 && stack.Layers[len(stack.Layers)-1].Upper
	last := chain[len(chain)-1]
	if hasUpper {
		if last.Kind != 2 {
			return nil, errors.New("writable stack does not match an active snapshot")
		}
		chain = chain[:len(chain)-1]
	} else if last.Kind == 1 {
		chain = chain[:len(chain)-1]
	} else if last.Kind != 3 {
		return nil, errors.New("read-only stack does not match committed/view snapshots")
	}
	for _, rec := range chain {
		if rec.Kind != 3 {
			return nil, errors.New("non-committed snapshot inside image lower chain")
		}
	}
	count := len(stack.Layers)
	if hasUpper {
		count--
	}
	if len(chain) != count {
		return nil, errors.New("snapshot chain length differs from captured lower stack")
	}
	return chain, nil
}

func checkSnapshotPaths(c *casefile.Case, stack overlay.Stack, chain []containerd.SnapshotRecord) error {
	lowers, err := lowerRecords(stack, chain)
	if err != nil {
		return err
	}
	base := filepath.Join(c.Root, c.ImageProvenance.SnapshotterRoot)
	for i, rec := range lowers {
		if stack.Layers[i].Missing || filepath.Join(base, rec.DiskID, "fs") != stack.Layers[i].Root {
			return fmt.Errorf("snapshot disk ID/path mismatch at lower layer %d", i)
		}
	}
	if len(stack.Layers) > len(lowers) {
		upper := stack.Layers[len(stack.Layers)-1]
		last := chain[len(chain)-1]
		if upper.Missing || filepath.Join(base, last.DiskID, "fs") != upper.Root {
			return errors.New("active snapshot disk ID/path mismatch")
		}
	}
	return nil
}

func associateImage(c *casefile.Case, stack overlay.Stack, chain []containerd.SnapshotRecord, image *oci.Image) ([]model.ImageLayerAssociation, error) {
	if err := checkSnapshotPaths(c, stack, chain); err != nil {
		return nil, err
	}
	lowers, err := lowerRecords(stack, chain)
	if err != nil {
		return nil, err
	}
	if len(lowers) != len(image.Layers) {
		return nil, errors.New("OCI layer count differs from snapshot chain")
	}
	result := make([]model.ImageLayerAssociation, 0, len(lowers))
	for i, rec := range lowers {
		layer := image.Layers[i]
		if rec.Key != layer.ChainID {
			return nil, fmt.Errorf("OCI chainID does not match snapshot key at layer %d", i)
		}
		artifact, err := filepath.Rel(c.Root, stack.Layers[i].Root)
		if err != nil {
			return nil, err
		}
		result = append(result, model.ImageLayerAssociation{Index: i, Digest: layer.Digest, DiffID: layer.DiffID, ChainID: layer.ChainID, SnapshotKey: rec.Key, SnapshotID: rec.DiskID, SnapshotArtifact: filepath.ToSlash(artifact), BlobArtifact: layer.Artifact, BlobBytes: layer.Size, ExpandedBytes: layer.ExpandedSize})
	}
	return result, nil
}
