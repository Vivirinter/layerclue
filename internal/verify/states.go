package verify

import (
	"encoding/json"
	"github.com/Vivirinter/layerclue/internal/model"
	"strconv"
)

func checkPathStates(rep *model.Report) []string {
	if rep.Schema == model.SchemaReportV3 {
		if rep.VisibleState != "" || rep.LowerState != "" || rep.Verdict == model.VerdictAbsent {
			return []string{"legacy report contains unsupported path-state fields"}
		}
		return nil
	}
	var problems []string
	for _, view := range []struct {
		name     string
		state    model.PathState
		location *model.Location
	}{{"visible", rep.VisibleState, rep.Visible}, {"lower", rep.LowerState, rep.Image}} {
		if !view.state.Valid() {
			problems = append(problems, "invalid or missing "+view.name+" path state")
			continue
		}
		if view.state == model.PathPresent && view.location == nil || view.state.KnownAbsent() && view.location != nil {
			problems = append(problems, view.name+" path state contradicts its location")
		}
		if view.state == model.PathUnknown && !rep.Incomplete && rep.Verdict != model.VerdictUnknownInsufficient && rep.Verdict != model.VerdictUnsupportedFeature {
			problems = append(problems, "answered report contains an unknown "+view.name+" view")
		}
		if view.state.KnownAbsent() {
			found := 0
			var absence model.Claim
			for _, claim := range rep.Claims {
				if claim.Kind == view.name+"_absence" && claim.Answer == string(view.state) && claim.Strength == model.Derived {
					found++
					absence = claim
				}
			}
			if found != 1 {
				problems = append(problems, view.name+" absence must have one evidence-backed claim")
			} else if !hasAbsenceEvidence(rep.Facts, absence.DependsOn, view.state) {
				problems = append(problems, view.name+" absence claim lacks a matching negative observation")
			}
		}
		for _, claim := range rep.Claims {
			if claim.Kind == view.name+"_absence" && (claim.Answer != string(view.state) || !view.state.KnownAbsent()) {
				problems = append(problems, view.name+" absence claim contradicts its state")
			}
		}
	}
	want := map[model.Verdict]model.PathState{
		model.VerdictAbsent:                model.PathAbsent,
		model.VerdictDeletedByWhiteout:     model.PathWhiteout,
		model.VerdictDeletedByOpaqueParent: model.PathOpaque,
		model.VerdictFromImageLayer:        model.PathPresent,
		model.VerdictFromUpper:             model.PathPresent,
		model.VerdictFromUpperAdded:        model.PathPresent,
		model.VerdictFromUpperModified:     model.PathPresent,
		model.VerdictFromUpperCopyUpSame:   model.PathPresent,
		model.VerdictFromUpperMetadataOnly: model.PathPresent,
		model.VerdictShadowedByMount:       model.PathPresent,
		model.VerdictSymlinkRedirect:       model.PathPresent,
	}
	if state, ok := want[rep.Verdict]; ok && state != rep.VisibleState {
		problems = append(problems, "verdict contradicts visible path state")
	}
	return problems
}

// Inspect each fact once. Reports are untrusted and repeated dependency IDs
// must not turn verification into quadratic work.
func hasAbsenceEvidence(facts []model.Fact, dependencies []string, state model.PathState) bool {
	required := make(map[string]bool, len(dependencies))
	for _, id := range dependencies {
		required[id] = true
	}
	absentMounts, completeMounts := map[string]bool{}, map[string]bool{}
	for _, fact := range facts {
		if !required[fact.ID] || fact.Strength != model.Observed {
			continue
		}
		switch state {
		case model.PathAbsent:
			switch fact.Kind {
			case "overlay_path_absent", "non_directory_parent", "empty_lower_stack":
				return true
			case "mount_path_absent":
				if id := positiveID(fact.Value["mount_id"]); id != "" {
					absentMounts[id] = true
				}
			case "captured_mount_mapping":
				if fact.Value["complete_assertion"] == true {
					if id := positiveID(fact.Value["mount_id"]); id != "" {
						completeMounts[id] = true
					}
				}
			}
		case model.PathWhiteout:
			if fact.Kind == "layer_entry" && fact.Value["whiteout"] == true {
				return true
			}
		case model.PathOpaque:
			if fact.Kind == "layer_entry" && fact.Value["opaque"] == true {
				return true
			}
		}
	}
	for id := range absentMounts {
		if completeMounts[id] {
			return true
		}
	}
	return false
}

func positiveID(value any) string {
	switch value.(type) {
	case int, int64, uint32, uint64, float64, json.Number:
	default:
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 20 {
		return ""
	}
	id, err := strconv.ParseUint(string(encoded), 10, 64)
	if err != nil || id == 0 {
		return ""
	}
	return strconv.FormatUint(id, 10)
}
