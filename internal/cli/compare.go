package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/Vivirinter/layerclue/internal/analysis"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/oci"
	"github.com/Vivirinter/layerclue/internal/render"
)

func (a *application) cmdCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	root := fs.String("case", "", "case directory")
	content := fs.String("content-root", "", "case-relative OCI content directory")
	digest := fs.String("manifest", "", "explicit platform manifest sha256 digest")
	asJSON := fs.Bool("json", false, "emit comparison JSON (distinct from explain report)")
	timeout := fs.Duration("timeout", time.Minute, "maximum duration (up to 10m)")
	maxBytes := fs.Int64("max-file-bytes", evidence.DefaultHashBytes, "captured-file hash budget")
	if fs.Parse(permute(fs, args)) != nil || fs.NArg() != 1 || *content == "" || !oci.ValidDigest(*digest) || evidence.Local(*content) != nil || *timeout <= 0 || *timeout > 10*time.Minute || *maxBytes <= 0 || *maxBytes > 8<<30 {
		return exitUsage
	}
	c, err := openCase(*root)
	if err != nil {
		fmt.Fprintln(a.stderr, render.Safe(err.Error()))
		return exitCase
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	out, err := analysis.Compare(ctx, c, fs.Arg(0), *content, *digest, analysis.Options{MaxFileBytes: *maxBytes, ReadIdentity: readIdentity})
	if err != nil {
		fmt.Fprintln(a.stderr, render.Safe(err.Error()))
		if errors.Is(err, oci.ErrUnsupportedPath) {
			return exitUnsupported
		}
		return exitCase
	}
	if *asJSON {
		err = json.NewEncoder(a.stdout).Encode(out)
	} else {
		_, err = fmt.Fprintf(a.stdout, "comparison  %s\nimage       %s\n%s\n", out.Status, *digest, out.Scope)
	}
	if err != nil {
		fmt.Fprintln(a.stderr, render.Safe(err.Error()))
		return exitCase
	}
	if out.Status != "matching_bytes" {
		return exitStrict
	}
	return exitOK
}
