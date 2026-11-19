// Package analysis assembles evidence-backed reports without CLI or process I/O.
// Identity reading is provided by its caller; the CLI uses an isolated worker.
package analysis

import (
	"context"
	"errors"
	"fmt"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/containerd"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/resolve"
	appversion "github.com/Vivirinter/layerclue/internal/version"
)

// Options supplies the per-file budget and the identity transport boundary.
// ReadIdentity must respect the supplied context and capture trust model.
type Options struct {
	MaxFileBytes int64
	ReadIdentity func(context.Context, *casefile.Case) (*casefile.Identity, error)
}

// BuildReport resolves a path and attaches captured runtime/image associations.
// It returns an unsealed report; the caller seals the final document.
func BuildReport(ctx context.Context, c *casefile.Case, target string, options Options) (*model.Report, error) {
	if ctx == nil || c == nil || options.ReadIdentity == nil {
		return nil, errors.New("analysis requires a context, case and identity reader")
	}
	maxBytes := options.MaxFileBytes
	if maxBytes <= 0 || maxBytes > 8<<30 {
		return nil, errors.New("invalid analysis byte budget")
	}

	table, err := c.MountTable()
	if err != nil {
		return nil, err
	}
	stack, missing, err := c.Stack(table)
	if err != nil {
		return nil, err
	}
	overlayMount, _ := c.OverlayMount(table)
	sources := make(map[int]resolve.MountSource)
	for id, m := range c.MountSources {
		sources[id] = resolve.MountSource{Root: m.Root, Artifact: m.Artifact, Complete: m.Complete}
	}

	resolver := resolve.New(resolve.Options{
		CaseRoot:          c.Root,
		HostRoot:          c.HostRoot,
		MountinfoArtifact: c.MountinfoRef,
		Mounts:            table,
		Stack:             stack,
		OverlayPoint:      overlayMount.Point,
		ContainerID:       c.ContainerID,
		MountSources:      sources,
		Context:           ctx,
		MaxFileBytes:      maxBytes,
	})

	out, err := resolver.Resolve(target)
	if err != nil {
		return nil, err
	}

	allMissing := make([]string, 0, len(missing)+len(out.Missing))
	allMissing = append(allMissing, missing...)
	allMissing = append(allMissing, out.Missing...)

	rep := &model.Report{
		Schema:       model.SchemaReport,
		Analysis:     &model.AnalysisConfig{EngineVersion: appversion.Version, MaxFileBytes: maxBytes},
		Path:         target,
		ContainerID:  c.ContainerID,
		Verdict:      out.Verdict,
		Explanation:  out.Explanation,
		Visible:      out.Visible,
		Image:        out.Image,
		VisibleState: out.VisibleState,
		LowerState:   out.LowerState,
		Trace:        out.Trace,
		Facts:        out.Facts,
		Claims:       out.Claims,
		Missing:      allMissing,
		Incomplete:   out.Incomplete || len(allMissing) > 0,
	}

	var identity *casefile.Identity
	switch id, err := options.ReadIdentity(ctx, c); {
	case errors.Is(err, containerd.ErrUnsupportedFormat):
		rep.Missing = append(rep.Missing, "containerd metadata uses an unsupported layout; container identity was not read")
	case err != nil:
		rep.Missing = append(rep.Missing, "runtime metadata could not be read: "+err.Error())
	case id != nil && id.ContainerID != "":
		identity = id
		rep.ContainerID = id.ContainerID
		rep.Runtime = id.Runtime
		rep.ImageRef = id.ImageRef
		rep.ImageDigest = id.ImageDigest
		rep.PodName = id.PodName
		rep.PodNamespace = id.PodNamespace
	case id != nil && len(id.Candidates) > 0:
		rep.Missing = append(rep.Missing, fmt.Sprintf(
			"container identity is ambiguous (%d containers in the metadata database); set container_id in case.json",
			len(id.Candidates)))
	}

	attachImageProvenance(ctx, c, identity, stack, overlayMount, rep)
	attachDockerIdentity(c, identity, overlayMount, rep)
	rep.Incomplete = rep.Incomplete || len(rep.Missing) > 0
	return rep, nil
}
