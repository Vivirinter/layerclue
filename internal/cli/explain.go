package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/Vivirinter/layerclue/internal/analysis"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/overlay"
	"github.com/Vivirinter/layerclue/internal/render"
)

func (a *application) cmdExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	caseDir := fs.String("case", "", "case directory")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	showTrace := fs.Bool("trace", false, "include the resolution trace and facts")
	strict := fs.Bool("strict", false, "fail on incomplete or unsupported analysis")
	timeout := fs.Duration("timeout", 30*time.Second, "maximum analysis duration")
	maxBytes := fs.Int64("max-file-bytes", evidence.DefaultHashBytes, "maximum bytes hashed per file")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.stderr, "layerclue explain: exactly one path is required")
		return exitUsage
	}
	if *timeout <= 0 || *timeout > 10*time.Minute || *maxBytes <= 0 || *maxBytes > 8<<30 {
		fmt.Fprintln(a.stderr, "invalid analysis limits")
		return exitUsage
	}

	c, err := openCase(*caseDir)
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rep, err := analysis.BuildReport(ctx, c, fs.Arg(0), analysis.Options{MaxFileBytes: *maxBytes, ReadIdentity: readIdentity})
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		if errors.Is(err, overlay.ErrUnsupported) {
			return exitUnsupported
		}
		return exitCase
	}
	if err := rep.Seal(); err != nil {
		fmt.Fprintln(a.stderr, "layerclue: seal:", render.Safe(err.Error()))
		return exitCase
	}

	if *asJSON {
		err = render.JSON(a.stdout, rep)
	} else {
		err = render.Terminal(a.stdout, rep, *showTrace)
	}
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}

	if rep.Verdict == model.VerdictUnsupportedFeature {
		return exitUnsupported
	}
	if *strict && !rep.Complete() {
		return exitStrict
	}
	return exitOK
}
