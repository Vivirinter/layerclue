package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/verify"
)

func TestPermuteMovesPathBehindFlags(t *testing.T) {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	caseDir := fs.String("case", "", "")
	trace := fs.Bool("trace", false, "")

	got := permute(fs, []string{"/usr/bin/helper", "--json", "--case", "dir", "--trace"})
	want := []string{"--json", "--case", "dir", "--trace", "--", "/usr/bin/helper"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if err := fs.Parse(got); err != nil {
		t.Fatal(err)
	}
	if !*asJSON || !*trace || *caseDir != "dir" {
		t.Fatalf("flags not parsed: json=%v trace=%v case=%q", *asJSON, *trace, *caseDir)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "/usr/bin/helper" {
		t.Fatalf("positional args = %v", fs.Args())
	}
}

func TestPermuteKeepsInlineValues(t *testing.T) {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	caseDir := fs.String("case", "", "")

	got := permute(fs, []string{"/a", "--case=/tmp/x"})
	want := []string{"--case=/tmp/x", "--", "/a"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if err := fs.Parse(got); err != nil {
		t.Fatal(err)
	}
	if *caseDir != "/tmp/x" {
		t.Fatalf("case = %q", *caseDir)
	}
}

func TestPermuteHonoursDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	_ = fs.Bool("json", false, "")

	got := permute(fs, []string{"--json", "--", "-weird-path"})
	if len(got) != 3 || got[0] != "--json" || got[1] != "--" || got[2] != "-weird-path" {
		t.Fatalf("got %v", got)
	}
}

func sealedReport(t *testing.T) *model.Report {
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
		Explanation:  "from image layer 1/1",
		Facts: []model.Fact{{
			ID:       "f1",
			Kind:     "layer_entry",
			Source:   model.Source{Artifact: "layer", Path: "host/l1/usr/bin/helper"},
			Strength: model.Observed,
		}},
		Claims: []model.Claim{{
			Kind:      "visible_provider",
			Answer:    "layer:1",
			DependsOn: []string{"f1"},
			Strength:  model.Observed,
		}},
	}
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}
	return rep
}

func writeReport(t *testing.T, name string, rep *model.Report) {
	t.Helper()
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyExitCodes(t *testing.T) {
	dir := t.TempDir()

	intact := filepath.Join(dir, "intact.json")
	writeReport(t, intact, sealedReport(t))
	if code := run([]string{"verify", intact}); code != exitOK {
		t.Fatalf("intact report exit = %d, want %d", code, exitOK)
	}

	tampered := sealedReport(t)
	tampered.Verdict = model.VerdictFromUpperAdded
	tamperedPath := filepath.Join(dir, "tampered.json")
	writeReport(t, tamperedPath, tampered)
	if code := run([]string{"verify", tamperedPath}); code != exitStrict {
		t.Fatalf("tampered report exit = %d, want %d", code, exitStrict)
	}
}

func demoCase(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	writeFile := func(rel, body string) {
		name := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeFile("host/var/lib/containerd/snapshots/5/fs/usr/bin/helper", "A")
	writeFile("host/var/lib/k8s/vol/bin/helper", "B")
	if err := os.MkdirAll(filepath.Join(root, "host/var/lib/containerd/snapshots/9/fs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile("host/proc/1/mountinfo",
		"10 1 0:9 / / rw - overlay overlay rw,"+
			"lowerdir=/var/lib/containerd/snapshots/5/fs,"+
			"upperdir=/var/lib/containerd/snapshots/9/fs,userxattr\n"+
			"11 10 8:1 / /usr/bin rw - ext4 /var/lib/k8s/vol/bin rw\n")
	writeFile("case.json", `{"schema":"layerclue.case/v1","mounts":[{"mount_id":11,"artifact":"host/var/lib/k8s/vol/bin","complete":true}]}`)
	return root
}

func TestExplainEndToEnd(t *testing.T) {
	dir := demoCase(t)

	out, code := captureRun(t,
		[]string{"explain", "/usr/bin/helper", "--case", dir, "--json"},
	)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}

	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, out)
	}
	if rep.Verdict != model.VerdictShadowedByMount {
		t.Fatalf("verdict = %s, want shadowed_by_mount", rep.Verdict)
	}
	if rep.SHA256 == "" {
		t.Fatal("report is not sealed")
	}
	if problems := verify.Report(&rep); len(problems) != 0 {
		t.Fatalf("emitted report does not verify: %v", problems)
	}
}

func TestExplainStrictAcceptsEstablishedAbsence(t *testing.T) {
	dir := demoCase(t)
	_, code := captureRun(t,
		[]string{"explain", "/nope", "--case", dir, "--strict"},
	)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "_identity-worker" {
		os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func run(args []string) int {
	return Run(args, io.Discard, io.Discard)
}

func captureRun(t *testing.T, args []string) (string, int) {
	t.Helper()
	var stdout bytes.Buffer
	code := Run(args, &stdout, io.Discard)
	return stdout.String(), code
}
