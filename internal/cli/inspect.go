package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/render"
)

func (a *application) cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	caseDir := fs.String("case", "", "case directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "inspect accepts --case DIR, not positional arguments")
		return exitUsage
	}

	c, err := openCase(*caseDir)
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}
	table, err := c.MountTable()
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}

	fmt.Fprintf(a.stdout, "case        %s\n", render.Safe(c.Root))
	fmt.Fprintf(a.stdout, "mountinfo   %s\n", render.Safe(c.MountinfoRef))
	if c.MetadataRef != "" || c.DockerInspect != "" {
		fmt.Fprintf(a.stdout, "metadata    %s\n", render.Safe(c.MetadataRef+c.DockerInspect))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		switch id, err := readIdentity(ctx, c); {
		case err != nil:
			fmt.Fprintf(a.stdout, "identity    error: %s\n", render.Safe(err.Error()))
		case id == nil:
			fmt.Fprintf(a.stdout, "identity    none\n")
		case id.ContainerID != "":
			fmt.Fprintf(a.stdout, "identity    %s\n", render.Safe(id.ContainerID))
			if id.ImageRef != "" {
				fmt.Fprintf(a.stdout, "image       %s\n", render.Safe(id.ImageRef))
			}
			if id.ImageDigest != "" {
				fmt.Fprintf(a.stdout, "digest      %s\n", render.Safe(id.ImageDigest))
			}
			if id.PodName != "" {
				fmt.Fprintf(a.stdout, "pod         %s/%s\n", render.Safe(id.PodNamespace), render.Safe(id.PodName))
			}
			if id.Snapshotter != "" {
				fmt.Fprintf(a.stdout, "snapshotter %s\n", render.Safe(id.Snapshotter))
			}
		default:
			fmt.Fprintf(a.stdout, "identity    ambiguous, %d containers\n", len(id.Candidates))
			for i, candidate := range id.Candidates {
				if i >= 10 {
					break
				}
				fmt.Fprintf(a.stdout, "  %s\n", render.Safe(candidate))
			}
		}
	} else {
		fmt.Fprintf(a.stdout, "metadata    none\n")
	}
	if c.ContainerID != "" {
		fmt.Fprintf(a.stdout, "container   %s\n", render.Safe(c.ContainerID))
	}
	fmt.Fprintf(a.stdout, "mounts      %d\n", len(table))

	stack, missing, err := c.Stack(table)
	switch {
	case errors.Is(err, casefile.ErrNoOverlay):
		fmt.Fprintf(a.stdout, "overlay     none\n")
	case err != nil:
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	default:
		fmt.Fprintf(a.stdout, "overlay     %d layers\n", stack.Len())
		for _, l := range stack.Layers {
			role := "lower"
			switch {
			case l.Upper:
				role = "upper"
			case l.Missing:
				role = "lower (missing)"
			}
			fmt.Fprintf(a.stdout, "  %d/%d  %-14s %s\n", l.Index+1, stack.Len(), role, render.Safe(l.Root))
		}
		for _, m := range missing {
			fmt.Fprintf(a.stdout, "  missing: %s\n", render.Safe(m))
		}
	}
	return exitOK
}
