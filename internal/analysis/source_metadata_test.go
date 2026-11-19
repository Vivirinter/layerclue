package analysis_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/analysis"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"github.com/Vivirinter/layerclue/internal/verify"
)

func collectedCase(t *testing.T) string {
	t.Helper()
	return collectedCaseMode(t, 0755)
}

func collectedCaseMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	f := testfixture.NewProvenanceCase(t)
	name := filepath.Join(f.Root, "host/snapshots/2/fs/opt/tool")
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1700000000, 123456789)
	if err := os.Chtimes(name, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.Root, "host/snapshots/1/fs/empty"), 0750); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	if err := custody.Collect(context.Background(), f.Root, output, "synthetic source metadata test", custody.DefaultLimits(), nil); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(output, "case")
}

func TestSourceSetIDModesAreRecordedButNeverRestored(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeSetuid | 0755, os.ModeSetgid | 0755} {
		report := metadataReport(t, collectedCaseMode(t, mode), "/opt/tool")
		if !report.Complete() {
			t.Fatal(report.Missing)
		}
		if report.Visible.OriginalMetadata.Metadata.ModeBits != uint32(mode) {
			t.Fatal("lost recorded source set-ID flag")
		}
		if report.Visible.CapturedMetadata.ModeBits != 0600 {
			t.Fatal("restored a dangerous source mode")
		}
	}
}

func metadataReport(t *testing.T, root, target string) *model.Report {
	t.Helper()
	c, err := casefile.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analysis.BuildReport(context.Background(), c, target, analysis.Options{MaxFileBytes: evidence.DefaultHashBytes, ReadIdentity: fixtureIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := verify.Report(report); len(problems) > 0 {
		t.Fatal(problems)
	}
	return report
}

func TestSourceMetadataSeparatesOriginalFromSafeCopy(t *testing.T) {
	root := collectedCase(t)
	before, err := custody.Scan(context.Background(), root, custody.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report := metadataReport(t, root, "/opt/tool")
	for _, loc := range []*model.Location{report.Visible, report.Image} {
		if loc.CapturedMetadata == nil || loc.CapturedMetadata.Mode != "-rw-------" || loc.Mode != "-rw-------" {
			t.Fatalf("safe copy mode lost: %+v", loc)
		}
		original := loc.OriginalMetadata
		if original == nil || original.Metadata.Mode != "-rwxr-xr-x" || original.Metadata.MtimeNS != 1700000000123456789 || original.Binding != "file_sha256" || original.ObjectSHA256 != loc.SHA256 || original.Scope != model.RecordedMetadataScope {
			t.Fatalf("original record lost: %+v", original)
		}
	}
	if !report.Complete() {
		t.Fatal(report.Missing)
	}
	// Nanosecond timestamps must survive common JSON consumers without a float
	// round-trip through arbitrary fact values changing the sealed document.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if problems := verify.Report(&decoded); len(problems) > 0 {
		t.Fatal(problems)
	}
	after, err := custody.Scan(context.Background(), root, custody.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("analysis modified captured evidence")
	}
}

func TestSourceDirectoryMetadataBinding(t *testing.T) {
	root := collectedCase(t)
	for _, target := range []string{"/opt", "/empty"} {
		report := metadataReport(t, root, target)
		if !report.Complete() || report.Visible.OriginalMetadata == nil || report.Visible.OriginalMetadata.Binding != "directory_children_sha256" {
			t.Fatalf("directory record not bound for %s: %+v %v", target, report.Visible, report.Missing)
		}
	}
}

func rewriteSourceInventory(t *testing.T, root string, change func(*custody.Seal)) {
	t.Helper()
	name := filepath.Join(root, custody.AcquisitionFile)
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		t.Fatal(err)
	}
	var seal custody.Seal
	if err := json.Unmarshal(outer["source_inventory"], &seal); err != nil {
		t.Fatal(err)
	}
	change(&seal)
	data, err = json.Marshal(seal.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	seal.SHA256 = hex.EncodeToString(sum[:])
	outer["source_inventory"], err = json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSourceJournalCannotSupplyOriginalMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, string)
	}{
		{"different selected bytes", func(t *testing.T, root string) {
			rewriteSourceInventory(t, root, func(s *custody.Seal) {
				for i := range s.Inventory.Entries {
					if strings.HasSuffix(s.Inventory.Entries[i].Path, "/opt/tool") {
						s.Inventory.Entries[i].SHA256 = strings.Repeat("a", 64)
					}
				}
			})
		}},
		{"duplicate record", func(t *testing.T, root string) {
			rewriteSourceInventory(t, root, func(s *custody.Seal) { s.Inventory.Entries = append(s.Inventory.Entries, s.Inventory.Entries[0]) })
		}},
		{"unknown mode bits", func(t *testing.T, root string) {
			rewriteSourceInventory(t, root, func(s *custody.Seal) { s.Inventory.Entries[0].Mode |= 1 << 18 })
		}},
		{"escaping record", func(t *testing.T, root string) {
			rewriteSourceInventory(t, root, func(s *custody.Seal) { s.Inventory.Entries[len(s.Inventory.Entries)-1].Path = "../outside" })
		}},
		{"different control artifact", func(t *testing.T, root string) {
			testfixture.Write(t, filepath.Join(root, "mountinfo"), []byte("100 1 0:52 / / rw - overlay overlay rw,lowerdir=/snapshots/2/fs:/snapshots/1/fs,upperdir=/snapshots/3/fs,workdir=/snapshots/3/work,userxattr\n\n"))
		}},
		{"duplicate JSON field", func(t *testing.T, root string) {
			testfixture.Write(t, filepath.Join(root, custody.AcquisitionFile), []byte(`{"schema":"layerclue.acquisition/v1","schema":"layerclue.acquisition/v1"}`))
		}},
		{"symlink journal", func(t *testing.T, root string) {
			name := filepath.Join(root, custody.AcquisitionFile)
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "private")
			testfixture.Write(t, outside, []byte("outside-sentinel-must-not-be-read"))
			if err := os.Symlink(outside, name); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized journal", func(t *testing.T, root string) {
			if err := os.Truncate(filepath.Join(root, custody.AcquisitionFile), custody.MaxInventoryBytes+1); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := collectedCase(t)
			tc.change(t, root)
			report := metadataReport(t, root, "/opt/tool")
			if report.Complete() || len(report.Missing) == 0 || report.Visible.OriginalMetadata != nil || report.Image.OriginalMetadata != nil {
				t.Fatalf("unbound journal trusted: %+v", report)
			}
			data, _ := json.Marshal(report)
			if strings.Contains(string(data), "outside-sentinel-must-not-be-read") {
				t.Fatal("followed journal symlink")
			}
		})
	}
}

func TestJournalFailureCannotPartiallyAttachMetadata(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	testfixture.Write(t, filepath.Join(f.Root, "host/snapshots/3/fs/opt/tool"), []byte("different upper bytes"))
	output := filepath.Join(t.TempDir(), "bundle")
	if err := custody.Collect(context.Background(), f.Root, output, "synthetic mixed record test", custody.DefaultLimits(), nil); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(output, "case")
	rewriteSourceInventory(t, root, func(s *custody.Seal) {
		for i := range s.Inventory.Entries {
			if s.Inventory.Entries[i].Path == "host/snapshots/2/fs/opt/tool" {
				s.Inventory.Entries[i].SHA256 = strings.Repeat("b", 64)
			}
		}
	})
	report := metadataReport(t, root, "/opt/tool")
	if report.Complete() || report.Visible.OriginalMetadata != nil || report.Image.OriginalMetadata != nil {
		t.Fatal("partially trusted a failed journal binding")
	}
}

func TestSourceMetadataCannotContradictItsFactAfterResealing(t *testing.T) {
	report := metadataReport(t, collectedCase(t), "/opt/tool")
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*model.OriginalMetadata)
	}{
		{"owner", func(m *model.OriginalMetadata) { m.Metadata.UID++ }},
		{"missing fact", func(m *model.OriginalMetadata) { m.Evidence = "not-present" }},
		{"path escape", func(m *model.OriginalMetadata) { m.SourcePath = "../outside" }},
		{"wrong binding", func(m *model.OriginalMetadata) { m.Binding = "directory_children_sha256" }},
		{"false trust scope", func(m *model.OriginalMetadata) { m.Scope = "authenticated source" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var changed model.Report
			if err := evidence.DecodeJSON(data, &changed); err != nil {
				t.Fatal(err)
			}
			tc.change(changed.Visible.OriginalMetadata)
			if err := changed.Seal(); err != nil {
				t.Fatal(err)
			}
			if problems := verify.Report(&changed); len(problems) == 0 {
				t.Fatal("accepted detached source metadata")
			}
		})
	}
}
