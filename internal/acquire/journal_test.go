package acquire

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

func TestDecodeSourceJournalRejectsAmbiguousRecords(t *testing.T) {
	source, plan := fixture(t)
	output := filepath.Join(t.TempDir(), "bundle")
	if _, err := Docker(context.Background(), Options{Source: source, Output: output, Plan: plan, Limits: custody.DefaultLimits()}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "case", custody.AcquisitionFile))
	if err != nil {
		t.Fatal(err)
	}
	records, err := DecodeJournalMetadata(context.Background(), data, plan.ContainerID)
	if err != nil || len(records) == 0 {
		t.Fatalf("valid journal rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*journal)
	}{
		{"duplicate output", func(j *journal) { j.Entries = append(j.Entries, j.Entries[0]) }},
		{"escaping source", func(j *journal) { j.Entries[0].Source = "../outside" }},
		{"escaping output", func(j *journal) { j.Entries[0].Output = "../outside" }},
		{"invalid plan checksum", func(j *journal) { j.PlanSHA256 = "invalid" }},
		{"type mismatch", func(j *journal) { j.Entries[0].Kind = "file" }},
		{"unknown mode bits", func(j *journal) { j.Entries[0].Mode |= 1 << 18 }},
		{"impossible type bits", func(j *journal) { j.Entries[0].Mode |= uint32(os.ModeSymlink) }},
		{"unknown schema", func(j *journal) { j.Schema = "layerclue.acquisition/v999" }},
		{"invalid time", func(j *journal) { j.CompletedAt = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var j journal
			if err := evidence.DecodeInventoryJSON(data, &j); err != nil {
				t.Fatal(err)
			}
			tc.change(&j)
			changed, err := json.Marshal(j)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeJournalMetadata(context.Background(), changed, plan.ContainerID); err == nil {
				t.Fatal("accepted ambiguous journal")
			}
		})
	}
	if _, err := DecodeJournalMetadata(context.Background(), data, "other-container"); err == nil {
		t.Fatal("accepted another container's journal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeJournalMetadata(ctx, data, plan.ContainerID); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func FuzzDecodeJournalMetadata(f *testing.F) {
	p := Plan{Schema: PlanSchema, ContainerID: strings.Repeat("a", 64), Inspect: "inspect.json", Mountinfo: "mountinfo", Method: "synthetic journal fuzz seed", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "capture"}
	plan, err := json.Marshal(p)
	if err != nil {
		f.Fatal(err)
	}
	j := journal{Schema: JournalSchema, Scope: "synthetic", StartedAt: "2020-01-01T00:00:00Z", CompletedAt: "2020-01-01T00:00:00Z", Plan: p, PlanSHA256: hash(plan), Summary: Summary{ContainerID: p.ContainerID}, Entries: []sourceEntry{{Source: "snapshot/diff", Output: "host/diff", Kind: "directory", Mode: uint32(os.ModeDir | 0700), ChildrenSHA256: hash([]byte("null"))}}}
	seed, err := json.Marshal(j)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema":"layerclue.acquisition/v2","schema":"duplicate"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		_, _ = DecodeJournalMetadata(context.Background(), data, p.ContainerID)
	})
}
