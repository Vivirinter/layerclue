package analysis_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/analysis"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"github.com/Vivirinter/layerclue/internal/verify"
)

// In-process reading is limited to these trusted synthetic fixtures. Production
// CLI calls use the bounded subprocess reader in internal/cli.
func fixtureIdentity(ctx context.Context, c *casefile.Case) (*casefile.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Identity()
}

func TestIdentityTransportFailureMakesReportIncomplete(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	c, err := casefile.Open(f.Root)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	report, err := analysis.BuildReport(context.Background(), c, "/opt/tool", analysis.Options{
		MaxFileBytes: evidence.DefaultHashBytes,
		ReadIdentity: func(context.Context, *casefile.Case) (*casefile.Identity, error) {
			calls++
			return nil, errors.New("synthetic transport failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || report.Complete() || !strings.Contains(strings.Join(report.Missing, "\n"), "synthetic transport failure") {
		t.Fatalf("transport failure was lost: calls=%d report=%+v", calls, report)
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := verify.Report(report); len(problems) != 0 {
		t.Fatal(problems)
	}
}

func TestCompareDetectsChangedCapturedBytesWithoutCLI(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	c, err := casefile.Open(f.Root)
	if err != nil {
		t.Fatal(err)
	}
	options := analysis.Options{MaxFileBytes: evidence.DefaultHashBytes, ReadIdentity: fixtureIdentity}
	compare := func() string {
		t.Helper()
		result, err := analysis.Compare(context.Background(), c, "/opt/tool", f.ContentRoot, f.ManifestDigest, options)
		if err != nil {
			t.Fatal(err)
		}
		if problems := verify.Report(result.Captured); len(problems) != 0 {
			t.Fatal(problems)
		}
		return result.Status
	}
	if status := compare(); status != "matching_bytes" {
		t.Fatal(status)
	}
	testfixture.Write(t, filepath.Join(f.Root, "host/snapshots/2/fs/opt/tool"), []byte("changed captured bytes"))
	if status := compare(); status != "different_bytes" {
		t.Fatal(status)
	}
}

func TestReportRejectsMissingDependencies(t *testing.T) {
	reader := analysis.Options{MaxFileBytes: evidence.DefaultHashBytes, ReadIdentity: fixtureIdentity}
	for _, tc := range []struct {
		ctx     context.Context
		capture *casefile.Case
		options analysis.Options
	}{
		{nil, &casefile.Case{}, reader},
		{context.Background(), nil, reader},
		{context.Background(), &casefile.Case{}, analysis.Options{MaxFileBytes: evidence.DefaultHashBytes}},
		{context.Background(), &casefile.Case{}, analysis.Options{ReadIdentity: fixtureIdentity}},
		{context.Background(), &casefile.Case{}, analysis.Options{MaxFileBytes: 9 << 30, ReadIdentity: fixtureIdentity}},
	} {
		if report, err := analysis.BuildReport(tc.ctx, tc.capture, "/opt/tool", tc.options); err == nil || report != nil {
			t.Fatalf("invalid analysis dependencies accepted: report=%+v err=%v", report, err)
		}
	}
}

func TestCompareEstablishedAbsence(t *testing.T) {
	for _, tc := range []struct {
		target, status string
		remove         bool
	}{
		{"/opt/missing", "both_absent", false},
		{"/opt/tool", "absent_in_capture", true},
	} {
		t.Run(tc.status, func(t *testing.T) {
			f := testfixture.NewProvenanceCase(t)
			if tc.remove {
				if err := os.Remove(filepath.Join(f.Root, "host/snapshots/2/fs/opt/tool")); err != nil {
					t.Fatal(err)
				}
			}
			c, err := casefile.Open(f.Root)
			if err != nil {
				t.Fatal(err)
			}
			result, err := analysis.Compare(context.Background(), c, tc.target, f.ContentRoot, f.ManifestDigest, analysis.Options{MaxFileBytes: evidence.DefaultHashBytes, ReadIdentity: fixtureIdentity})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.status || !result.Captured.Complete() || result.Captured.VisibleState != "absent" {
				t.Fatalf("unexpected comparison: %+v", result)
			}
			if problems := verify.Report(result.Captured); len(problems) != 0 {
				t.Fatal(problems)
			}
		})
	}
}
