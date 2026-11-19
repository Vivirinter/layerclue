package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
)

// sampleReport contains invented paths and digests, not captured file identities.
func sampleReport() *model.Report {
	return &model.Report{
		Schema:      model.SchemaReport,
		Path:        "/usr/bin/helper",
		Verdict:     model.VerdictShadowedByMount,
		Explanation: "the path is served by a mount",
		Visible: &model.Location{
			Provider:    "mount",
			Logical:     "/usr/bin/helper",
			MountPoint:  "/usr/bin",
			MountSource: "/var/lib/k8s/vol/bin",
			Type:        "file",
			SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Image: &model.Location{
			Provider:   "overlay_layer",
			Logical:    "/usr/bin/helper",
			LayerIndex: 0,
			LayerTotal: 2,
			Type:       "file",
			SHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		Trace: []model.Step{
			{Kind: model.StepMountSelect, Path: "/usr/bin", Detail: "served by mount"},
			{Kind: model.StepSymlink, Path: "/opt/link", Detail: "-> /etc/passwd"},
		},
		Facts: []model.Fact{
			{ID: "f1", Kind: "mountinfo_entry", Source: model.Source{Artifact: "host/proc/1/mountinfo", Line: 2}, Strength: model.Observed},
		},
		Claims: []model.Claim{
			{Kind: "visible_provider", Answer: "mount:/usr/bin:/var/lib/k8s/vol/bin", DependsOn: []string{"f1"}, Strength: model.Observed},
		},
		Missing: []string{"a lower layer was not captured"},
	}
}

func TestTerminalPutsTheAnswerFirst(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, sampleReport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	pathAt := strings.Index(out, "/usr/bin/helper")
	verdictAt := strings.Index(out, string(model.VerdictShadowedByMount))
	if pathAt < 0 || verdictAt < 0 {
		t.Fatalf("output lacks path or verdict:\n%s", out)
	}
	if verdictAt < pathAt {
		t.Fatal("the verdict must appear after the path and before the evidence")
	}
	if strings.Contains(out, "trace:") {
		t.Fatal("trace must be hidden unless requested")
	}
	if !strings.Contains(out, "missing evidence") {
		t.Fatal("missing evidence must be shown by default")
	}
}

func TestTerminalTraceSection(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, sampleReport(), true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"trace:", "facts:", "f1", "mountinfo_entry", "host/proc/1/mountinfo:2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestJSONRoundTrips(t *testing.T) {
	rep := sampleReport()
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := JSON(&buf, rep); err != nil {
		t.Fatal(err)
	}

	var back model.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.SHA256 != rep.SHA256 || back.Verdict != rep.Verdict {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Fatal("JSON output must be indented for humans")
	}
}

func TestTerminalEscapesArtifactControls(t *testing.T) {
	rep := sampleReport()
	rep.Path = "/file\x1b[2J\nforged"
	rep.Explanation = "\x1b]0;title\a"
	var buf bytes.Buffer
	if err := Terminal(&buf, rep, true); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\a") || strings.Contains(buf.String(), "\nforged") {
		t.Fatalf("unescaped terminal controls: %q", buf.String())
	}
}

func TestTerminalDoesNotConflateUnknownWithAbsence(t *testing.T) {
	for _, tc := range []struct {
		state model.PathState
		want  string
	}{
		{model.PathUnknown, "unknown (insufficient evidence)"},
		{model.PathAbsent, "absent in captured view"},
		{model.PathWhiteout, "blocked by a captured whiteout"},
		{model.PathOpaque, "hidden by a captured opaque directory"},
		{"", "unknown (state not recorded)"},
	} {
		rep := sampleReport()
		rep.Visible, rep.Image = nil, nil
		rep.VisibleState, rep.LowerState = tc.state, tc.state
		var buf bytes.Buffer
		if err := Terminal(&buf, rep, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), tc.want) || strings.Contains(buf.String(), "nothing") || strings.Contains(buf.String(), "no entry") {
			t.Fatalf("misleading state output: %s", buf.String())
		}
	}
}

func TestTerminalSeparatesCaptureAndRecordedMetadata(t *testing.T) {
	rep := sampleReport()
	rep.VisibleState = model.PathPresent
	rep.Visible.CapturedMetadata = &model.FileMetadata{Mode: "-rw-------", UID: 1000, GID: 1000, MtimeNS: 1700000000123456789}
	rep.Visible.OriginalMetadata = &model.OriginalMetadata{Metadata: model.FileMetadata{Mode: "-rwxr-xr-x", UID: 0, GID: 0, MtimeNS: 1600000000123456789}, Artifact: "layerclue-acquisition.json", Scope: model.RecordedMetadataScope, Binding: "file_sha256"}
	var buf bytes.Buffer
	if err := Terminal(&buf, rep, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"visible capture metadata: mode=-rw------- uid=1000", "visible recorded source:  mode=-rwxr-xr-x uid=0", model.RecordedMetadataScope} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing metadata distinction %q: %s", want, buf.String())
		}
	}
}
