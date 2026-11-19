package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
)

func TestReplayBudgetRequiresExplicitPermission(t *testing.T) {
	dir := demoCase(t)
	out, code := captureRun(t,
		[]string{"explain", "/usr/bin/helper", "--case", dir, "--json", "--max-file-bytes", "536870912"},
	)
	if code != exitOK {
		t.Fatal(code)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(report, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := captureRun(t, []string{"verify", report, "--case", dir}); code != exitStrict {
		t.Fatalf("automatically expanded replay budget: %d", code)
	}
	if _, code := captureRun(t, []string{"verify", report, "--case", dir, "--max-file-bytes", "536870912"}); code != exitOK {
		t.Fatalf("explicit budget rejected: %d", code)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	rep.Analysis.EngineVersion = "different-engine"
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}
	writeReport(t, report, &rep)
	if _, code := captureRun(t, []string{"verify", report, "--case", dir, "--max-file-bytes", "536870912"}); code != exitStrict {
		t.Fatalf("silently replayed a different engine: %d", code)
	}
}
