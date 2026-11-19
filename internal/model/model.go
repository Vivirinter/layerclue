// Package model defines the domain vocabulary shared by every layerclue
// component: facts, claims, trace steps, verdicts and the report envelope.
//
// The types here are free of I/O and of any filesystem knowledge. A report is
// a value: it can be hashed, compared and verified without the code that
// produced it.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// SchemaReport is the wire schema of a report document.
const SchemaReport = "layerclue.report/v3"

// Strength states how well a claim is supported by the underlying artifacts.
type Strength string

const (
	// Observed means the fact was read directly from an artifact.
	Observed Strength = "observed"
	// Derived means the fact follows from observed facts by a documented rule.
	Derived Strength = "derived"
	// Assumed means the fact rests on a premise the tool could not check.
	Assumed Strength = "assumed"
	// Unknown means the evidence does not allow a conclusion at all.
	Unknown Strength = "unknown"
)

// Verdict is the single conclusion a report states about a path.
type Verdict string

const (
	// VerdictFromImageLayer is the legacy Go name for a captured lower layer.
	// An OCI image association is not inferred without a digest mapping.
	VerdictFromImageLayer Verdict = "from_lower_layer"
	// VerdictFromUpperAdded means the object exists only in the writable layer.
	VerdictFromUpperAdded Verdict = "from_upper_added"
	// VerdictFromUpperModified means the writable layer holds different content
	// than the image.
	VerdictFromUpperModified Verdict = "from_upper_modified"
	VerdictFromUpper         Verdict = "from_upper"
	// VerdictFromUpperCopyUpSame is the legacy Go name for matching bytes in
	// the upper and captured lower view; it does not establish copy-up history.
	VerdictFromUpperCopyUpSame Verdict = "from_upper_content_unchanged"
	// VerdictFromUpperMetadataOnly means overlayfs metacopy: the writable layer
	// holds metadata only and the data lives in a lower layer.
	VerdictFromUpperMetadataOnly Verdict = "from_upper_metadata_only"
	// VerdictDeletedByWhiteout means a whiteout hides the object.
	VerdictDeletedByWhiteout Verdict = "deleted_by_whiteout"
	// VerdictDeletedByOpaqueParent means an opaque directory hides the object.
	VerdictDeletedByOpaqueParent Verdict = "deleted_by_opaque_parent"
	// VerdictShadowedByMount means another mount serves the path, so the
	// container filesystem is not what is actually visible.
	VerdictShadowedByMount Verdict = "shadowed_by_mount"
	// VerdictSymlinkRedirect means the path is a symlink and was followed.
	VerdictSymlinkRedirect Verdict = "symlink_redirect"
	// VerdictUnknownInsufficient means the captured evidence does not answer
	// the question.
	VerdictUnknownInsufficient Verdict = "unknown_insufficient_evidence"
	// VerdictUnsupportedFeature means overlayfs used a feature that changes
	// resolution semantics and is not implemented.
	VerdictUnsupportedFeature Verdict = "unsupported_overlay_feature"
)

// Source points at the exact artifact a fact was read from.
type Source struct {
	Artifact string `json:"artifact"`
	Line     int    `json:"line,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Fact is something the tool read. Facts are the only ground truth a report
// is allowed to rest on.
type Fact struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Source   Source         `json:"source"`
	Strength Strength       `json:"strength"`
	Value    map[string]any `json:"value,omitempty"`
}

// Claim is a statement derived from facts.
type Claim struct {
	Kind      string   `json:"kind"`
	Answer    string   `json:"answer"`
	DependsOn []string `json:"depends_on"`
	Strength  Strength `json:"strength"`
}

// StepKind names one stage of the resolution trace.
type StepKind string

const (
	StepMountSelect StepKind = "mount_selected"
	StepOverlayHit  StepKind = "overlay_hit"
	StepOverlayMiss StepKind = "overlay_miss"
	StepWhiteout    StepKind = "whiteout"
	StepOpaque      StepKind = "opaque_dir"
	StepMetaCopy    StepKind = "metacopy"
	StepSymlink     StepKind = "symlink"
	StepMissing     StepKind = "missing_evidence"
	StepUnsupported StepKind = "unsupported_feature"
)

// Step is one entry of the resolution trace, in execution order.
type Step struct {
	View     string   `json:"view,omitempty"`
	Kind     StepKind `json:"kind"`
	Path     string   `json:"path"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// Location describes an object as seen through one particular view.
type Location struct {
	CapturedPath     string `json:"captured_path,omitempty"`
	Provider         string `json:"provider"`
	Logical          string `json:"logical"`
	LayerIndex       int    `json:"layer_index,omitempty"`
	LayerTotal       int    `json:"layer_total,omitempty"`
	LayerDigest      string `json:"layer_digest,omitempty"`
	LayerAssociation string `json:"layer_association,omitempty"`
	MountPoint       string `json:"mount_point,omitempty"`
	MountSource      string `json:"mount_source,omitempty"`
	Type             string `json:"type,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Size             int64  `json:"size,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	LinkTarget       string `json:"link_target,omitempty"`
	MetaCopy         bool   `json:"metacopy,omitempty"`
}

type AnalysisConfig struct {
	EngineVersion string `json:"engine_version"`
	MaxFileBytes  int64  `json:"max_file_bytes"`
}

type ImageLayerAssociation struct {
	Index            int    `json:"index"`
	Digest           string `json:"digest"`
	DiffID           string `json:"diff_id"`
	ChainID          string `json:"chain_id"`
	SnapshotKey      string `json:"snapshot_key"`
	SnapshotID       string `json:"snapshot_id"`
	SnapshotArtifact string `json:"snapshot_artifact"`
	BlobArtifact     string `json:"blob_artifact"`
	BlobBytes        int64  `json:"blob_bytes"`
	ExpandedBytes    int64  `json:"expanded_bytes"`
}

// ImageProvenance distinguishes integrity of captured OCI bytes and metadata
// association from verification of unpacked snapshot contents or signatures.
type ImageProvenance struct {
	Status          string                  `json:"status"`
	Scope           string                  `json:"scope"`
	ManifestDigest  string                  `json:"manifest_digest"`
	ReferenceDigest string                  `json:"reference_digest,omitempty"`
	ReferenceKind   string                  `json:"reference_kind,omitempty"`
	ConfigDigest    string                  `json:"config_digest,omitempty"`
	Layers          []ImageLayerAssociation `json:"layers,omitempty"`
	Error           string                  `json:"error,omitempty"`
}

// Report is the verifiable document layerclue produces.
type Report struct {
	Schema          string           `json:"schema"`
	Analysis        *AnalysisConfig  `json:"analysis,omitempty"`
	ImageProvenance *ImageProvenance `json:"image_provenance,omitempty"`
	Path            string           `json:"path"`
	ContainerID     string           `json:"container_id,omitempty"`
	Runtime         string           `json:"runtime,omitempty"`
	ImageRef        string           `json:"image_ref,omitempty"`
	ImageDigest     string           `json:"image_digest,omitempty"`
	PodName         string           `json:"pod_name,omitempty"`
	PodNamespace    string           `json:"pod_namespace,omitempty"`
	Verdict         Verdict          `json:"verdict"`
	Explanation     string           `json:"explanation"`
	Visible         *Location        `json:"visible,omitempty"`
	Image           *Location        `json:"lower,omitempty"`
	Trace           []Step           `json:"trace"`
	Facts           []Fact           `json:"facts"`
	Claims          []Claim          `json:"claims"`
	Missing         []string         `json:"missing,omitempty"`
	Incomplete      bool             `json:"incomplete,omitempty"`
	SHA256          string           `json:"report_sha256,omitempty"`
}

// Seal computes the report digest over the canonical encoding of the report
// with the digest field cleared. Sealing an unmodified report yields the same
// value on every platform and every run.
func (r *Report) Seal() error {
	r.SHA256 = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	r.SHA256 = hex.EncodeToString(sum[:])
	return nil
}

// HasAssumed reports whether any claim rests on an unchecked premise.
func (r *Report) HasAssumed() bool {
	for _, c := range r.Claims {
		if c.Strength == Assumed {
			return true
		}
	}
	return false
}

// Complete reports whether strict mode may accept this analysis. Missing
// evidence and unimplemented semantics cannot become a successful strict run.
func (r *Report) Complete() bool {
	if r.Analysis == nil || r.Analysis.EngineVersion == "" || r.Analysis.MaxFileBytes <= 0 {
		return false
	}
	if r.ImageProvenance != nil && r.ImageProvenance.Status != "verified_metadata_association" {
		return false
	}
	if r.Incomplete || len(r.Missing) > 0 || r.HasAssumed() || len(r.Claims) == 0 {
		return false
	}
	for _, claim := range r.Claims {
		if claim.Strength != Observed && claim.Strength != Derived {
			return false
		}
	}
	return r.Verdict != "" && r.Verdict != VerdictUnknownInsufficient && r.Verdict != VerdictUnsupportedFeature
}

func ValidVerdict(v Verdict) bool {
	switch v {
	case VerdictFromImageLayer, VerdictFromUpper, VerdictFromUpperAdded, VerdictFromUpperModified, VerdictFromUpperCopyUpSame, VerdictFromUpperMetadataOnly, VerdictDeletedByWhiteout, VerdictDeletedByOpaqueParent, VerdictShadowedByMount, VerdictSymlinkRedirect, VerdictUnknownInsufficient, VerdictUnsupportedFeature:
		return true
	}
	return false
}
