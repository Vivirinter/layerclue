package resolve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/verify"
	"github.com/Vivirinter/layerclue/internal/xattr"
)

func TestPathStatesDistinguishAbsenceAndUnavailableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		prepare      func(*testing.T, *fixture, *Resolver)
		state        model.PathState
		verdict      model.Verdict
		incomplete   bool
	}{
		{name: "ordinary absent path", target: "/not-captured-because-absent", state: model.PathAbsent, verdict: model.VerdictAbsent},
		{name: "complete mount", target: "/usr/bin/absent", state: model.PathAbsent, verdict: model.VerdictAbsent},
		{name: "partial mount", target: "/usr/bin/absent", state: model.PathUnknown, verdict: model.VerdictUnknownInsufficient, incomplete: true,
			prepare: func(t *testing.T, f *fixture, r *Resolver) {
				source := r.opts.MountSources[121]
				source.Complete = false
				r.opts.MountSources[121] = source
			}},
		{name: "missing mount root despite complete assertion", target: "/usr/bin/helper", state: model.PathUnknown, verdict: model.VerdictUnknownInsufficient, incomplete: true,
			prepare: func(t *testing.T, f *fixture, r *Resolver) {
				if err := os.RemoveAll(f.bind); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "unmapped mount", target: "/usr/bin/helper", state: model.PathUnknown, verdict: model.VerdictUnknownInsufficient, incomplete: true,
			prepare: func(t *testing.T, f *fixture, r *Resolver) { r.opts.MountSources = nil }},
		{name: "non-directory parent", target: "/etc/passwd/child", state: model.PathAbsent, verdict: model.VerdictAbsent},
		{name: "non-directory before dotdot", target: "/etc/passwd/../shadow", state: model.PathAbsent, verdict: model.VerdictAbsent},
		{name: "dangling logical symlink", target: "/dangling", state: model.PathAbsent, verdict: model.VerdictAbsent,
			prepare: func(t *testing.T, f *fixture, r *Resolver) {
				if err := os.Symlink("/etc/not-present", filepath.Join(f.base, "dangling")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "whiteout", target: "/etc/shadow", state: model.PathWhiteout, verdict: model.VerdictDeletedByWhiteout,
			prepare: func(t *testing.T, f *fixture, r *Resolver) {
				name := filepath.Join(f.upper, "etc/shadow")
				mustWrite(t, name, "")
				if err := xattr.Set(name, "user.overlay.whiteout", nil); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "opaque parent", target: "/etc/passwd", state: model.PathOpaque, verdict: model.VerdictDeletedByOpaqueParent,
			prepare: func(t *testing.T, f *fixture, r *Resolver) {
				name := filepath.Join(f.upper, "etc")
				mustMkdir(t, name)
				if err := xattr.Set(name, "user.overlay.opaque", []byte("y")); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			r := f.resolver(t)
			if tc.prepare != nil {
				tc.prepare(t, f, r)
			}
			out, err := r.Resolve(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if out.VisibleState != tc.state || out.Verdict != tc.verdict || out.Incomplete != tc.incomplete {
				t.Fatalf("unexpected outcome: %+v", out)
			}
			if out.Visible != nil {
				t.Fatal("absence/unknown was emitted as an existing object")
			}
			rep := &model.Report{Schema: model.SchemaReport, Analysis: &model.AnalysisConfig{EngineVersion: "test", MaxFileBytes: 256 << 20}, Path: tc.target, Verdict: out.Verdict, Explanation: out.Explanation,
				Visible: out.Visible, Image: out.Image, VisibleState: out.VisibleState, LowerState: out.LowerState, Trace: out.Trace, Facts: out.Facts, Claims: out.Claims, Missing: out.Missing, Incomplete: out.Incomplete}
			if err := rep.Seal(); err != nil {
				t.Fatal(err)
			}
			if problems := verify.Report(rep); len(problems) != 0 {
				t.Fatal(problems)
			}
			if rep.Complete() == tc.incomplete {
				t.Fatalf("strict completeness=%t, incomplete=%t", rep.Complete(), tc.incomplete)
			}
		})
	}
}
