package verify

import (
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
)

func TestPathStateContradictionsAreRejectedAfterResealing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Report)
	}{
		{"missing states", func(r *model.Report) { r.VisibleState = "" }},
		{"present without object", func(r *model.Report) { r.Visible = nil }},
		{"absent with object", func(r *model.Report) { r.VisibleState = model.PathAbsent }},
		{"absence without negative observation", func(r *model.Report) {
			r.Visible = nil
			r.VisibleState = model.PathAbsent
			r.Verdict = model.VerdictAbsent
			r.Claims = append(r.Claims, model.Claim{Kind: "visible_absence", Answer: string(model.PathAbsent), Strength: model.Derived, DependsOn: []string{"f2"}})
		}},
		{"whiteout without marker", func(r *model.Report) {
			r.Visible = nil
			r.VisibleState = model.PathWhiteout
			r.Verdict = model.VerdictDeletedByWhiteout
			r.Claims = append(r.Claims, model.Claim{Kind: "visible_absence", Answer: string(model.PathWhiteout), Strength: model.Derived, DependsOn: []string{"f2"}})
		}},
		{"unknown answered view", func(r *model.Report) { r.LowerState = model.PathUnknown }},
		{"legacy with explicit states", func(r *model.Report) { r.Schema = model.SchemaReportV3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sample(t)
			tc.change(r)
			if err := r.Seal(); err != nil {
				t.Fatal(err)
			}
			if problems := Report(r); len(problems) == 0 {
				t.Fatal("accepted a contradictory report with a recomputed checksum")
			}
		})
	}
}

func TestV3ReportsRemainVerifiableWithoutInventingStates(t *testing.T) {
	r := sample(t)
	r.Schema = model.SchemaReportV3
	r.VisibleState, r.LowerState = "", ""
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := Report(r); len(problems) != 0 {
		t.Fatal(problems)
	}
	r.Visible.CapturedMetadata = &model.FileMetadata{Mode: "-rw-------"}
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := Report(r); len(problems) == 0 {
		t.Fatal("accepted v4 metadata in a v3 envelope")
	}
}

func TestMountAbsenceNeedsCompleteMapping(t *testing.T) {
	r := sample(t)
	r.Visible, r.VisibleState, r.Verdict = nil, model.PathAbsent, model.VerdictAbsent
	r.Facts = append(r.Facts,
		model.Fact{ID: "mapping", Kind: "captured_mount_mapping", Source: model.Source{Artifact: "case.json"}, Strength: model.Observed, Value: map[string]any{"mount_id": 1, "complete_assertion": false}},
		model.Fact{ID: "absence", Kind: "mount_path_absent", Source: model.Source{Artifact: "mount_source"}, Strength: model.Observed, Value: map[string]any{"mount_id": 1}},
	)
	r.Claims = []model.Claim{{Kind: "visible_absence", Answer: string(model.PathAbsent), Strength: model.Derived, DependsOn: []string{"mapping", "absence"}}}
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := Report(r); len(problems) == 0 {
		t.Fatal("partial capture proved absence")
	}
	r.Facts[len(r.Facts)-2].Value["complete_assertion"] = true
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := Report(r); len(problems) != 0 {
		t.Fatal(problems)
	}
}
