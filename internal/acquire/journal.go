package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

// SourceRecord is the recorded metadata for an output address. These are
// acquisition assertions, never instructions to open Source or restore Mode.
type SourceRecord struct {
	Source         string
	Kind           string
	Mode           uint32
	UID            uint32
	GID            uint32
	MtimeNS        int64
	Size           int64
	SHA256         string
	ChildrenSHA256 string
}

// DecodeJournalMetadata reads the bounded v2 wire format used by Docker.
// The supplied container ID binds the plan to the selected case. Plan and
// record checks establish internal consistency, not authenticity.
func DecodeJournalMetadata(ctx context.Context, data []byte, containerID string) (map[string]SourceRecord, error) {
	if ctx == nil {
		return nil, errors.New("journal requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var j journal
	if err := evidence.DecodeInventoryJSON(data, &j); err != nil {
		return nil, err
	}
	if j.Schema != JournalSchema || len(j.Entries) == 0 || len(j.Entries) > MaxEntries || j.Scope == "" || len(j.Scope) > 4096 {
		return nil, errors.New("invalid acquisition journal header")
	}
	if err := j.Plan.Validate(); err != nil {
		return nil, err
	}
	plan, err := json.Marshal(j.Plan)
	if err != nil {
		return nil, err
	}
	if hash(plan) != j.PlanSHA256 || j.Summary.ContainerID != j.Plan.ContainerID || j.Plan.ContainerID != containerID {
		return nil, errors.New("acquisition journal plan mismatch")
	}
	started, err := time.Parse(time.RFC3339Nano, j.StartedAt)
	if err != nil {
		return nil, errors.New("invalid acquisition start time")
	}
	completed, err := time.Parse(time.RFC3339Nano, j.CompletedAt)
	if err != nil || completed.Before(started) {
		return nil, errors.New("invalid acquisition completion time")
	}
	records := make(map[string]SourceRecord, len(j.Entries))
	for _, e := range j.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !canonical(e.Source) || !canonical(e.Output) {
			return nil, errors.New("invalid acquisition record address")
		}
		if _, duplicate := records[e.Output]; duplicate {
			return nil, errors.New("duplicate acquisition output address")
		}
		mode := os.FileMode(e.Mode)
		if !ValidRecordedMode(mode) {
			return nil, errors.New("acquisition record has unknown mode bits")
		}
		switch e.Kind {
		case "file":
			if !mode.IsRegular() || e.Size < 0 || !validHash(e.SHA256) {
				return nil, errors.New("invalid acquisition file record")
			}
		case "directory":
			if !mode.IsDir() || !validHash(e.ChildrenSHA256) {
				return nil, errors.New("invalid acquisition directory record")
			}
		case "symlink":
			if mode&os.ModeSymlink == 0 {
				return nil, errors.New("invalid acquisition symlink record")
			}
		case "native_whiteout":
			if mode&os.ModeCharDevice == 0 {
				return nil, errors.New("invalid acquisition whiteout record")
			}
		default:
			return nil, errors.New("unknown acquisition record kind")
		}
		records[e.Output] = SourceRecord{Source: e.Source, Kind: e.Kind, Mode: e.Mode, UID: e.UID, GID: e.GID, MtimeNS: e.MtimeNS, Size: e.Size, SHA256: e.SHA256, ChildrenSHA256: e.ChildrenSHA256}
	}
	return records, nil
}

// ValidRecordedMode prevents silently losing unknown bits when a journal's
// numeric Go FileMode is rendered as text. It does not authorize restoring it.
func ValidRecordedMode(mode os.FileMode) bool {
	const known = os.ModeType | os.ModePerm | os.ModeAppend | os.ModeExclusive | os.ModeTemporary | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if mode&^known != 0 {
		return false
	}
	switch mode.Type() {
	case 0, os.ModeDir, os.ModeSymlink, os.ModeDevice, os.ModeDevice | os.ModeCharDevice, os.ModeNamedPipe, os.ModeSocket, os.ModeIrregular:
		return true
	default:
		return false
	}
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
