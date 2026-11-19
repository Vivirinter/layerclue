// Package verify checks a report against itself: every claim must name facts
// that exist, every fact must name its artifact, and the digest must match a
// re-encoding of the document.
//
// The verifier is deliberately independent of the resolver. If it shared code
// with the producer, a bug would confirm itself.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/model"
)

// Report checks internal structure and checksum only. A matching unkeyed
// digest does not authenticate the producer or prove any claim about a case.
func Report(rep *model.Report) []string {
	var problems []string

	if rep.Schema != model.SchemaReport {
		problems = append(problems, fmt.Sprintf("unexpected schema %q", rep.Schema))
	}
	if rep.Analysis == nil || rep.Analysis.EngineVersion == "" || len(rep.Analysis.EngineVersion) > 128 || rep.Analysis.MaxFileBytes <= 0 || rep.Analysis.MaxFileBytes > 8<<30 {
		problems = append(problems, "invalid or missing analysis configuration")
	}
	problems = append(problems, checkImageProvenance(rep)...)
	if !model.ValidVerdict(rep.Verdict) {
		problems = append(problems, "report has an unknown verdict")
	}
	if !strings.HasPrefix(rep.Path, "/") || len(rep.Path) > 4096 || !utf8.ValidString(rep.Path) || strings.ContainsRune(rep.Path, 0) {
		problems = append(problems, "invalid container path")
	}
	if rep.Verdict != model.VerdictUnknownInsufficient && rep.Verdict != model.VerdictUnsupportedFeature && len(rep.Claims) == 0 {
		problems = append(problems, "answered report has no claims")
	}

	known := make(map[string]struct{}, len(rep.Facts))
	for _, f := range rep.Facts {
		if f.ID == "" {
			problems = append(problems, "a fact has no id")
		}
		if f.Source.Artifact == "" {
			problems = append(problems, fmt.Sprintf("fact %s has no source artifact", f.ID))
		}
		if f.Source.Path != "" && (!filepath.IsLocal(f.Source.Path) || strings.ContainsRune(f.Source.Path, 0)) {
			problems = append(problems, fmt.Sprintf("fact %s has an escaping artifact path", f.ID))
		}
		if f.Source.Line < 0 {
			problems = append(problems, "negative source line")
		}
		if f.Strength != model.Observed && f.Strength != model.Derived {
			problems = append(problems, fmt.Sprintf("fact %s has strength %q, which a fact may not have", f.ID, f.Strength))
		}
		if _, dup := known[f.ID]; dup {
			problems = append(problems, fmt.Sprintf("duplicate fact id %s", f.ID))
		}
		known[f.ID] = struct{}{}
	}

	for _, c := range rep.Claims {
		if c.Kind == "snapshot_image_layer_association" && (rep.ImageProvenance == nil || rep.ImageProvenance.Status != "verified_metadata_association" || c.Answer != rep.ImageProvenance.ManifestDigest) {
			problems = append(problems, "image association claim contradicts provenance status")
		}
		if c.Strength != model.Observed && c.Strength != model.Derived && c.Strength != model.Assumed {
			problems = append(problems, "claim has invalid strength")
		}
		if c.Kind == "" {
			problems = append(problems, "a claim has no kind")
		}
		if len(c.DependsOn) == 0 {
			problems = append(problems, fmt.Sprintf("claim %q rests on no facts", c.Kind))
		}
		for _, id := range c.DependsOn {
			if _, ok := known[id]; !ok {
				problems = append(problems, fmt.Sprintf("claim %q references unknown fact %s", c.Kind, id))
			}
		}
	}
	for _, step := range rep.Trace {
		for _, id := range step.Evidence {
			if _, ok := known[id]; !ok {
				problems = append(problems, "trace references unknown fact "+id)
			}
		}
	}

	if rep.SHA256 == "" {
		problems = append(problems, "report is not sealed")
		return problems
	}
	if raw, err := hex.DecodeString(rep.SHA256); err != nil || len(raw) != sha256.Size {
		problems = append(problems, "invalid report checksum")
	}

	clone := *rep
	want := rep.SHA256
	clone.SHA256 = ""
	b, err := json.Marshal(&clone)
	if err != nil {
		return append(problems, "cannot re-encode report: "+err.Error())
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		problems = append(problems, fmt.Sprintf("digest mismatch: document says %s, recomputed %s", short(want), short(got)))
	}
	return problems
}

func validSHA256(d string) bool {
	if !strings.HasPrefix(d, "sha256:") || len(d) != 71 {
		return false
	}
	raw, err := hex.DecodeString(d[7:])
	return err == nil && len(raw) == 32 && strings.ToLower(d) == d
}

func localArtifact(name string) bool {
	return name != "" && filepath.IsLocal(name) && filepath.ToSlash(filepath.Clean(name)) == name && !strings.ContainsRune(name, 0)
}

func checkImageProvenance(rep *model.Report) []string {
	var problems []string
	p := rep.ImageProvenance
	if p != nil {
		if !validSHA256(p.ManifestDigest) || p.Scope == "" || len(p.Scope) > 1024 {
			problems = append(problems, "invalid image proof header")
		}
		switch p.Status {
		case "unverified":
			if p.Error == "" || len(p.Layers) > 0 || p.ConfigDigest != "" || p.ReferenceDigest != "" || p.ReferenceKind != "" {
				problems = append(problems, "unverified image proof contains successful associations")
			}
		case "verified_metadata_association":
			if p.Error != "" || !validSHA256(p.ConfigDigest) || len(p.Layers) > 256 {
				problems = append(problems, "invalid verified image proof")
			}
			if !validSHA256(p.ReferenceDigest) || (p.ReferenceKind != "direct" && p.ReferenceKind != "index_member") || (p.ReferenceKind == "direct" && p.ReferenceDigest != p.ManifestDigest) || (p.ReferenceKind == "index_member" && p.ReferenceDigest == p.ManifestDigest) {
				problems = append(problems, "invalid image reference relationship")
			}
			found := 0
			for _, c := range rep.Claims {
				if c.Kind == "snapshot_image_layer_association" && c.Answer == p.ManifestDigest {
					found++
				}
			}
			if found != 1 {
				problems = append(problems, "verified image proof must have one association claim")
			}
			parent := ""
			for i, layer := range p.Layers {
				chain := layer.DiffID
				if parent != "" {
					sum := sha256.Sum256([]byte(parent + " " + layer.DiffID))
					chain = "sha256:" + hex.EncodeToString(sum[:])
				}
				id, err := strconv.ParseUint(layer.SnapshotID, 10, 64)
				if layer.Index != i || !validSHA256(layer.Digest) || !validSHA256(layer.DiffID) || layer.ChainID != chain || layer.SnapshotKey != chain || err != nil || id == 0 || strconv.FormatUint(id, 10) != layer.SnapshotID || !localArtifact(layer.SnapshotArtifact) || !localArtifact(layer.BlobArtifact) || layer.BlobBytes <= 0 || layer.ExpandedBytes < 0 {
					problems = append(problems, fmt.Sprintf("invalid OCI/snapshot association at layer %d", i))
				}
				parent = chain
			}
		default:
			problems = append(problems, "unknown image provenance status")
		}
	}
	for _, loc := range []*model.Location{rep.Visible, rep.Image} {
		if loc == nil {
			continue
		}
		if loc.LayerDigest == "" {
			if loc.LayerAssociation != "" {
				problems = append(problems, "layer association has no digest")
			}
			continue
		}
		if p == nil || p.Status != "verified_metadata_association" || loc.LayerAssociation != "captured_metadata" || loc.Provider != "overlay_layer" || loc.LayerIndex < 0 || loc.LayerIndex >= len(p.Layers) {
			problems = append(problems, "location has an unsupported OCI digest claim")
			continue
		}
		layer := p.Layers[loc.LayerIndex]
		if loc.LayerDigest != layer.Digest || !localArtifact(loc.CapturedPath) || (loc.CapturedPath != layer.SnapshotArtifact && !strings.HasPrefix(loc.CapturedPath, layer.SnapshotArtifact+"/")) {
			problems = append(problems, "location contradicts its OCI/snapshot association")
		}
	}
	return problems
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}
