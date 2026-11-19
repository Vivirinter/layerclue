package cli

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Vivirinter/layerclue/internal/analysis"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/render"
	"github.com/Vivirinter/layerclue/internal/verify"
)

func (a *application) cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	strict := fs.Bool("strict", false, "also fail on incomplete or unsupported analysis")
	caseDir := fs.String("case", "", "re-run analysis against this captured case")
	maxBytes := fs.Int64("max-file-bytes", evidence.DefaultHashBytes, "maximum permitted per-file replay budget")
	timeout := fs.Duration("timeout", 30*time.Second, "replay deadline")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.stderr, "layerclue verify: exactly one report is required")
		return exitUsage
	}
	if *maxBytes <= 0 || *maxBytes > 8<<30 || *timeout <= 0 || *timeout > 10*time.Minute {
		fmt.Fprintln(a.stderr, "invalid replay limits")
		return exitUsage
	}

	name, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return exitUsage
	}
	data, err := evidence.ReadFile(filepath.Dir(name), name, evidence.MaxReportBytes)
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}
	var rep model.Report
	if err := evidence.DecodeJSON(data, &rep); err != nil {
		fmt.Fprintln(a.stderr, "layerclue: parse report:", render.Safe(err.Error()))
		return exitCase
	}

	problems := verify.Report(&rep)
	if len(problems) == 0 && *caseDir != "" {
		if rep.Schema != model.SchemaReport {
			problems = append(problems, "report schema predates explicit path states; regenerate it with this build before replay")
		}
		if rep.Analysis.EngineVersion != version {
			problems = append(problems, "report engine version differs; regenerate it with this build")
		}
		if rep.Analysis.MaxFileBytes > *maxBytes {
			problems = append(problems, "report requests a larger replay budget; raise --max-file-bytes explicitly after reviewing it")
		}
	}
	if *strict && !rep.Complete() {
		problems = append(problems, "report is incomplete, unsupported or rests on an unverified premise")
	}
	if len(problems) == 0 && *caseDir != "" {
		c, err := casefile.Open(*caseDir)
		if err != nil {
			fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
			return exitCase
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		expected, err := analysis.BuildReport(ctx, c, rep.Path, analysis.Options{MaxFileBytes: rep.Analysis.MaxFileBytes, ReadIdentity: readIdentity})
		if err != nil {
			fmt.Fprintln(a.stderr, "layerclue: reanalysis:", render.Safe(err.Error()))
			return exitCase
		}
		if err := expected.Seal(); err != nil {
			return exitCase
		}
		if expected.SHA256 != rep.SHA256 {
			problems = append(problems, "report does not match fresh analysis of the supplied case")
		}
	}
	for _, p := range problems {
		fmt.Fprintln(a.stderr, "problem:", render.Safe(p))
	}
	if len(problems) > 0 {
		return exitStrict
	}

	scope := "report structure and checksum only"
	if *caseDir != "" {
		scope = "matches fresh analysis of supplied case"
	}
	fmt.Fprintf(a.stdout, "ok  %s  %s  (%s)\n", render.Safe(rep.Path), rep.SHA256, scope)
	return exitOK
}
