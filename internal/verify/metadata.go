package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/model"
)

func checkLocationMetadata(rep *model.Report) []string {
	var problems []string
	for _, loc := range []*model.Location{rep.Visible, rep.Image} {
		if loc == nil {
			continue
		}
		if rep.Schema == model.SchemaReportV3 {
			if loc.CapturedMetadata != nil || loc.OriginalMetadata != nil {
				problems = append(problems, "legacy report contains unsupported location metadata")
			}
			continue
		}
		if captured := loc.CapturedMetadata; captured != nil {
			if !validMetadata(*captured) || captured.Mode != loc.Mode || metadataKind(os.FileMode(captured.ModeBits)) != loc.Type {
				problems = append(problems, "capture metadata contradicts location mode")
			}
		}
		original := loc.OriginalMetadata
		if original == nil {
			continue
		}
		if loc.CapturedMetadata == nil {
			problems = append(problems, "recorded source metadata has no captured metadata counterpart")
		}
		if !validMetadata(original.Metadata) || original.Artifact != "layerclue-acquisition.json" || (original.JournalSchema != "layerclue.acquisition/v1" && original.JournalSchema != "layerclue.acquisition/v2") || !validSHA256(original.JournalSHA256) || !localArtifact(original.SourcePath) || len(original.SourcePath) > 4096 || !utf8.ValidString(original.SourcePath) || original.Scope != model.RecordedMetadataScope {
			problems = append(problems, "invalid recorded source metadata header")
		}
		rawHash, err := hex.DecodeString(original.ObjectSHA256)
		if err != nil || len(rawHash) != sha256.Size || original.ObjectSHA256 != strings.ToLower(original.ObjectSHA256) {
			problems = append(problems, "invalid source metadata object checksum")
		}
		if original.Binding == "file_sha256" {
			if loc.Type != "file" || original.ObjectSHA256 != loc.SHA256 || !os.FileMode(original.Metadata.ModeBits).IsRegular() {
				problems = append(problems, "recorded source metadata contradicts captured file")
			}
		} else if original.Binding == "directory_children_sha256" {
			if loc.Type != "directory" || !os.FileMode(original.Metadata.ModeBits).IsDir() {
				problems = append(problems, "recorded source metadata contradicts captured directory")
			}
		} else {
			problems = append(problems, "unknown source metadata binding")
		}
		var found *model.Fact
		for i := range rep.Facts {
			if rep.Facts[i].ID == original.Evidence {
				found = &rep.Facts[i]
				break
			}
		}
		if found == nil || found.Kind != "source_metadata_record" || found.Strength != model.Observed || found.Source.Artifact != original.Artifact || found.Source.Path != loc.CapturedPath {
			problems = append(problems, "recorded source metadata lacks its journal fact")
			continue
		}
		want, _ := json.Marshal(map[string]any{"journal_sha256": original.JournalSHA256, "source_path": original.SourcePath, "binding": original.Binding, "object_sha256": original.ObjectSHA256, "mode": original.Metadata.Mode, "mode_bits": original.Metadata.ModeBits, "uid": original.Metadata.UID, "gid": original.Metadata.GID, "mtime_ns": strconv.FormatInt(original.Metadata.MtimeNS, 10)})
		got, err := json.Marshal(found.Value)
		if err != nil || !bytes.Equal(want, got) {
			problems = append(problems, "recorded source metadata contradicts its journal fact")
		}
	}
	return problems
}

func validMetadata(m model.FileMetadata) bool {
	mode := os.FileMode(m.ModeBits)
	const known = os.ModeType | os.ModePerm | os.ModeAppend | os.ModeExclusive | os.ModeTemporary | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if mode&^known != 0 || m.Mode != mode.String() {
		return false
	}
	switch mode.Type() {
	case 0, os.ModeDir, os.ModeSymlink, os.ModeDevice, os.ModeDevice | os.ModeCharDevice, os.ModeNamedPipe, os.ModeSocket, os.ModeIrregular:
		return true
	default:
		return false
	}
}

func metadataKind(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	default:
		return "other"
	}
}
