package verify

import (
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
)

func sample(t *testing.T) *model.Report {
	t.Helper()
	rep := &model.Report{
		Schema:       model.SchemaReport,
		Analysis:     &model.AnalysisConfig{EngineVersion: "test", MaxFileBytes: 256 << 20},
		Path:         "/usr/bin/helper",
		Verdict:      model.VerdictFromImageLayer,
		VisibleState: model.PathPresent,
		LowerState:   model.PathPresent,
		Visible:      &model.Location{Provider: "overlay_layer", Logical: "/usr/bin/helper", Type: "file"},
		Image:        &model.Location{Provider: "overlay_layer", Logical: "/usr/bin/helper", Type: "file"},
		Explanation:  "the object comes from image layer 1/2",
		Facts: []model.Fact{
			{
				ID:       "f1",
				Kind:     "mountinfo_entry",
				Source:   model.Source{Artifact: "host/proc/4242/mountinfo", Line: 2},
				Strength: model.Observed,
			},
			{
				ID:       "f2",
				Kind:     "layer_entry",
				Source:   model.Source{Artifact: "layer", Path: "host/var/lib/containerd/snapshots/5/fs/usr/bin/helper"},
				Strength: model.Observed,
			},
		},
		Claims: []model.Claim{
			{
				Kind:      "visible_provider",
				Answer:    "layer:1",
				DependsOn: []string{"f1", "f2"},
				Strength:  model.Observed,
			},
		},
	}
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestSealedReportPasses(t *testing.T) {
	if problems := Report(sample(t)); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	rep := sample(t)
	rep.Verdict = model.VerdictFromUpperModified

	problems := Report(rep)
	if len(problems) == 0 {
		t.Fatal("a modified verdict must be detected")
	}
	if !contains(problems, "digest mismatch") {
		t.Fatalf("expected a digest mismatch, got %v", problems)
	}
}

func TestClaimOnMissingFactIsDetected(t *testing.T) {
	rep := sample(t)
	rep.Claims[0].DependsOn = append(rep.Claims[0].DependsOn, "f9")
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}

	problems := Report(rep)
	if !contains(problems, "unknown fact f9") {
		t.Fatalf("expected an unknown-fact problem, got %v", problems)
	}
}

func TestClaimWithoutEvidenceIsDetected(t *testing.T) {
	rep := sample(t)
	rep.Claims[0].DependsOn = nil
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}

	problems := Report(rep)
	if !contains(problems, "rests on no facts") {
		t.Fatalf("expected a no-evidence problem, got %v", problems)
	}
}

func TestUnsealedReportIsDetected(t *testing.T) {
	rep := sample(t)
	rep.SHA256 = ""

	problems := Report(rep)
	if !contains(problems, "not sealed") {
		t.Fatalf("expected a seal problem, got %v", problems)
	}
}

func contains(problems []string, needle string) bool {
	for _, p := range problems {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
