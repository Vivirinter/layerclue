// Package acquire imports selected artifacts from an offline host-filesystem
// snapshot. It never connects to Docker or creates a live filesystem snapshot.
package acquire

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

const PlanSchema = "layerclue.docker-acquisition/v1"
const JournalSchema = "layerclue.acquisition/v2"
const MaxEntries = 40000

type Mount struct {
	ID       int    `json:"mount_id"`
	Source   string `json:"source"`   // snapshot-relative mounted root, explicitly chosen
	Complete bool   `json:"complete"` // operator assertion, not inferred from copying
}
type Plan struct {
	Schema            string  `json:"schema"`
	ContainerID       string  `json:"container_id"`
	Inspect           string  `json:"inspect"`
	Mountinfo         string  `json:"mountinfo"`
	Method            string  `json:"method"`
	SourceMode        string  `json:"source_mode"`        // read_only_mount or operator_asserted_immutable_copy
	OverlayAttributes string  `json:"overlay_attributes"` // native or capture
	Mounts            []Mount `json:"mounts,omitempty"`
}

func canonical(s string) bool {
	return evidence.Local(s) == nil && path.Clean(s) == s && s != "." && len(s) <= 4096 && len(strings.Split(s, "/")) <= 128 && utf8.ValidString(s)
}
func DecodePlan(b []byte) (Plan, error) {
	var p Plan
	if len(b) > int(evidence.MaxManifestBytes) {
		return p, evidence.ErrLimit
	}
	if err := evidence.DecodeJSON(b, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func (p Plan) Validate() error {
	if p.Schema != PlanSchema || !docker.FullID(p.ContainerID) {
		return errors.New("plan requires its supported schema and a full Docker container_id")
	}
	if !canonical(p.Inspect) || !canonical(p.Mountinfo) {
		return errors.New("inspect and mountinfo must be canonical snapshot-relative paths")
	}
	if p.Method == "" || len(p.Method) > 4096 || !utf8.ValidString(p.Method) || strings.ContainsRune(p.Method, 0) {
		return errors.New("plan requires a bounded acquisition method assertion")
	}
	if p.SourceMode != "read_only_mount" && p.SourceMode != "operator_asserted_immutable_copy" {
		return errors.New("source_mode must explicitly select read_only_mount or operator_asserted_immutable_copy")
	}
	if p.OverlayAttributes != "native" && p.OverlayAttributes != "capture" {
		return errors.New("overlay_attributes must explicitly select native or capture")
	}
	if len(p.Mounts) > 8192 {
		return evidence.ErrLimit
	}
	ids := map[int]bool{}
	for _, m := range p.Mounts {
		if m.ID <= 0 || ids[m.ID] || !canonical(m.Source) {
			return fmt.Errorf("invalid/duplicate mount mapping %d", m.ID)
		}
		ids[m.ID] = true
	}
	return nil
}
