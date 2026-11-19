// Package resolve turns a captured case and a logical path into a trace, a
// set of facts and a verdict.
//
// Resolution runs in three ordered stages, and the order is the product:
//
//  1. the mount namespace decides whether the path is served by a mount at
//     all — a bind mount makes the overlay stack irrelevant;
//  2. the overlay stack decides which layer provides the object;
//  3. symbolic links are expanded in namespace order, because an absolute
//     link inside a bind mount restarts at the container root.
//
// Every stage records facts, and every conclusion names the facts it rests on.
package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/overlay"
)

// Providers name the view an object was found through.
const (
	ProviderOverlay = "overlay_layer"
	ProviderMount   = "mount"
)

// ErrSymlinkLoop is returned when symbolic links exceed the resolution limit.
var ErrSymlinkLoop = errors.New("too many symbolic links")

// Options configures a Resolver.
type Options struct {
	// CaseRoot is the absolute case directory. Fact paths are made relative
	// to it so a report is portable across machines.
	CaseRoot string
	// HostRoot is the absolute prefix that mirrors the captured host.
	HostRoot string
	// MountinfoArtifact is the mount table path relative to CaseRoot.
	MountinfoArtifact string
	// Mounts is the captured mount table.
	Mounts mounts.Table
	// Stack is the overlay stack reconstructed from that table.
	Stack overlay.Stack
	// OverlayPoint is the mount point of the overlay mount.
	OverlayPoint string
	// ContainerID is copied into the report.
	ContainerID string
	// MaxSymlinks bounds link expansion. Zero means 40.
	MaxSymlinks  int
	MountSources map[int]MountSource
	Context      context.Context
	MaxFileBytes int64
}

// MountSource is an explicit capture of the namespace mount root. Root is
// an artifact address inside CaseRoot, never mountinfo's source field.
type MountSource struct {
	Root     string
	Artifact string
	Complete bool
}

type hashRecord struct {
	Sum  string
	Fact string
	Info os.FileInfo
}

// Resolver answers provenance questions for one case.
type Resolver struct {
	opts       Options
	trace      []model.Step
	facts      []model.Fact
	missing    []string
	seq        int
	hops       int
	incomplete bool
	hashes     map[string]hashRecord
	view       string
}

// New returns a Resolver for the given case.
func New(o Options) *Resolver {
	if o.MaxSymlinks <= 0 {
		o.MaxSymlinks = 40
	}
	if o.OverlayPoint == "" {
		o.OverlayPoint = "/"
	}
	if o.Context == nil {
		o.Context = context.Background()
	}
	o.Stack.Context = o.Context
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = evidence.DefaultHashBytes
	}
	return &Resolver{opts: o, hashes: map[string]hashRecord{}}
}

// Outcome is everything the resolver learned about one path.
type Outcome struct {
	Verdict     model.Verdict
	Explanation string
	Visible     *model.Location
	Image       *model.Location
	Trace       []model.Step
	Facts       []model.Fact
	Claims      []model.Claim
	Missing     []string
	Incomplete  bool
}

type located struct {
	Logical    string
	Provider   string
	Kind       overlay.Kind
	Mode       os.FileMode
	Size       int64
	LinkTarget string
	HostPath   string
	Layer      int
	Mount      mounts.Entry
	MetaCopy   bool
	Deleted    bool
	DeletedBy  overlay.Entry
	Opaque     bool
	Missing    bool
	Evidence   []string
	sha        string
	Info       os.FileInfo
}

// Resolve explains what is visible at p and why.
func (r *Resolver) Resolve(p string) (*Outcome, error) {
	r.trace = nil
	r.facts = nil
	r.missing = nil
	r.seq = 0
	r.hops = 0
	r.incomplete = false
	r.hashes = map[string]hashRecord{}
	r.view = "visible"

	if !strings.HasPrefix(p, "/") || len(p) > 4096 || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
		return nil, errors.New("container path must be absolute, valid UTF-8, NUL-free and at most 4096 bytes")
	}
	clean := p

	visible, err := r.walk(clean)
	if err != nil {
		if errors.Is(err, overlay.ErrUnsupported) {
			return r.unsupported(err), nil
		}
		return nil, err
	}
	image, err := r.imageLookup(clean)
	if err != nil {
		if errors.Is(err, overlay.ErrUnsupported) {
			return r.unsupported(err), nil
		}
		return nil, err
	}

	for _, l := range []*located{visible, image} {
		if l == nil || l.Deleted || l.Missing || l.Kind != overlay.KindFile || l.MetaCopy {
			continue
		}
		if _, err := r.hash(l); err != nil {
			return nil, err
		}
	}

	verdict, explanation := r.decide(clean, visible, image)

	return &Outcome{
		Verdict:     verdict,
		Explanation: explanation,
		Visible:     r.location(visible),
		Image:       r.location(image),
		Trace:       r.trace,
		Facts:       r.facts,
		Claims:      r.claims(visible, image),
		Missing:     r.missing,
		Incomplete:  r.incomplete,
	}, nil
}

// walk resolves p component by component, expanding symbolic links as the
// kernel would: an absolute target restarts at the namespace root, a relative
// one at the directory of the link.
func (r *Resolver) walk(p string) (*located, error) {
	pending := strings.Split(p, "/")
	var components []string
	var last *located
	steps := 0
	for len(pending) > 0 {
		if err := r.opts.Context.Err(); err != nil {
			return nil, err
		}
		steps++
		if steps > 1024 || len(components) > 256 {
			return nil, evidence.ErrLimit
		}
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(components) > 0 {
				components = components[:len(components)-1]
			}
			last = nil
			continue
		}
		next := "/" + strings.Join(append(append([]string(nil), components...), part), "/")
		loc, err := r.lookupOne(next)
		if err != nil {
			return nil, err
		}
		if loc == nil {
			return &located{Logical: next, Missing: true}, nil
		}
		if loc.Missing || loc.Deleted {
			return loc, nil
		}
		if loc.Kind == overlay.KindSymlink {
			r.hops++
			if r.hops > r.opts.MaxSymlinks {
				return nil, fmt.Errorf("%w: %s", ErrSymlinkLoop, next)
			}
			if loc.LinkTarget == "" || len(loc.LinkTarget) > 4096 || !utf8.ValidString(loc.LinkTarget) || strings.ContainsRune(loc.LinkTarget, 0) {
				return nil, errors.New("invalid symlink target")
			}
			if strings.HasPrefix(loc.LinkTarget, "/") {
				components = nil
			}
			pending = append(strings.Split(loc.LinkTarget, "/"), pending...)
			r.step(model.StepSymlink, next, "-> "+loc.LinkTarget, loc.Evidence...)
			last = nil
			continue
		}
		if len(pending) > 0 && loc.Kind != overlay.KindDir {
			return &located{Logical: next, Missing: true}, nil
		}
		components = append(components, part)
		last = loc
	}
	if last != nil {
		return last, nil
	}
	return r.lookupOne("/" + strings.Join(components, "/"))
}

func (r *Resolver) unsupported(err error) *Outcome {
	r.step(model.StepUnsupported, "", err.Error())
	return &Outcome{Verdict: model.VerdictUnsupportedFeature, Explanation: err.Error(), Trace: r.trace, Facts: r.facts, Incomplete: true, Missing: []string{err.Error()}}
}

func (r *Resolver) lookupOne(logical string) (*located, error) {
	m, rel, err := r.opts.Mounts.Select(logical)
	if err != nil {
		return nil, fmt.Errorf("mount selection: %w", err)
	}
	if m.FSType == "overlay" {
		if m.Point != r.opts.OverlayPoint {
			return nil, fmt.Errorf("%w: nested overlay at %s", overlay.ErrUnsupported, m.Point)
		}
		return r.lookupOverlay(logical, rel, m)
	}
	return r.lookupMount(logical, rel, m)
}

func (r *Resolver) lookupOverlay(logical, rel string, m mounts.Entry) (*located, error) {
	res, err := r.opts.Stack.Lookup(rel)
	if err != nil {
		return nil, err
	}
	if res.Incomplete {
		r.incomplete = true
		r.note("a lower layer of the overlay stack was not captured")
	}

	ev := r.fact("mountinfo_entry", r.mountSource(m), model.Observed, map[string]any{
		"mount_point": m.Point,
		"fstype":      m.FSType,
		"root":        m.Root,
	})

	switch res.State {
	case overlay.StateDeleted:
		e := res.DeletedBy
		fev := r.layerFact(e)
		kind := model.StepWhiteout
		if e.Opaque {
			kind = model.StepOpaque
		}
		r.step(kind, logical, "blocking entry in layer "+layerLabel(e.Layer, r.opts.Stack), ev, fev)
		return &located{
			Logical:   logical,
			Provider:  ProviderOverlay,
			Deleted:   true,
			DeletedBy: e,
			Layer:     e.Layer,
			Opaque:    e.Opaque,
			Evidence:  []string{ev, fev},
		}, nil

	case overlay.StateFound:
		e := res.Entry
		fev := r.layerFact(e)
		label := "layer " + layerLabel(e.Layer, r.opts.Stack)
		if e.Opaque {
			r.step(model.StepOpaque, logical, "opaque directory in "+label, ev, fev)
		}
		if e.MetaCopy {
			r.step(model.StepMetaCopy, logical, "metacopy in "+label, ev, fev)
		}
		r.step(model.StepOverlayHit, logical, e.Kind.String()+" in "+label, ev, fev)
		return &located{
			Logical:    logical,
			Provider:   ProviderOverlay,
			Kind:       e.Kind,
			Mode:       e.Mode,
			Size:       e.Size,
			LinkTarget: e.LinkTarget,
			HostPath:   e.HostPath,
			Layer:      e.Layer,
			MetaCopy:   e.MetaCopy,
			Evidence:   []string{ev, fev},
			Info:       e.Info,
		}, nil

	default:
		r.step(model.StepOverlayMiss, logical, "no layer provides the path", ev)
		return nil, nil
	}
}

func (r *Resolver) lookupMount(logical, rel string, m mounts.Entry) (*located, error) {
	ev := r.fact("mountinfo_entry", r.mountSource(m), model.Observed, map[string]any{"mount_id": m.ID, "mount_point": m.Point, "fstype": m.FSType, "root": m.Root, "source": m.Source})
	r.step(model.StepMountSelect, logical, "covered by mount "+m.Point, ev)
	source, ok := r.opts.MountSources[m.ID]
	if !ok {
		r.incomplete = true
		r.note("no captured source mapping for mount " + strconv.Itoa(m.ID) + " at " + m.Point)
		return &located{Logical: logical, Provider: ProviderMount, Mount: m, Missing: true, Evidence: []string{ev}}, nil
	}
	hostPath := filepath.Join(source.Root, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
	fi, err := evidence.Lstat(r.opts.CaseRoot, hostPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.incomplete = true
			if source.Complete {
				r.note("path is absent from captured mount " + strconv.Itoa(m.ID))
			} else {
				r.note("mount capture is incomplete: " + strconv.Itoa(m.ID))
			}
			return &located{Logical: logical, Provider: ProviderMount, Mount: m, Missing: true, Evidence: []string{ev}}, nil
		}
		return nil, err
	}
	fev := r.fact("mount_file", model.Source{Artifact: "mount_source", Path: r.relPath(hostPath)}, model.Observed, map[string]any{"kind": kindOf(fi.Mode()).String(), "mode": fi.Mode().String(), "size": fi.Size(), "mount_id": m.ID, "mapping": source.Artifact})
	loc := &located{Logical: logical, Provider: ProviderMount, Kind: kindOf(fi.Mode()), Mode: fi.Mode(), Size: fi.Size(), HostPath: hostPath, Layer: -1, Mount: m, Evidence: []string{ev, fev}, Info: fi}
	if loc.Kind == overlay.KindSymlink {
		loc.LinkTarget, err = evidence.Readlink(r.opts.CaseRoot, hostPath)
		if err != nil {
			return nil, err
		}
	}
	return loc, nil
}

// imageStack returns the stack without its writable layer.
func (r *Resolver) imageStack() overlay.Stack {
	s := r.opts.Stack
	if n := len(s.Layers); n > 0 && s.Layers[n-1].Upper {
		s.Layers = s.Layers[:n-1]
		return s
	}
	return s
}

// imageLookup answers the same question ignoring mounts and ignoring the
// writable layer: what does the image itself provide at this path.
//
// Including the writable layer here would make every file found in it look
// like an unchanged copy-up, because the entry would be compared with itself.
func (r *Resolver) imageLookup(p string) (*located, error) {
	image := r.imageStack()
	if image.Len() == 0 {
		return nil, nil
	}
	saved := r.opts
	savedHops := r.hops
	savedView := r.view
	defer func() { r.opts = saved; r.hops = savedHops; r.view = savedView }()
	root, _, err := saved.Mounts.Select("/")
	if err != nil {
		return nil, err
	}
	root.ParentID = 0
	r.opts.Mounts = mounts.Table{root}
	r.opts.Stack = image
	r.hops = 0
	r.view = "lower"
	return r.walk(p)
}

func (r *Resolver) decide(p string, vis, img *located) (model.Verdict, string) {
	if r.incomplete {
		return model.VerdictUnknownInsufficient, "Some required evidence is missing; the provider of " + p + " cannot be established completely."
	}
	if vis == nil || vis.Missing {
		return model.VerdictUnknownInsufficient, "The captured evidence does not determine what is visible at " + p + "."
	}
	if vis.Deleted {
		if vis.Opaque {
			return model.VerdictDeletedByOpaqueParent, "A captured opaque directory hides the lower entry at " + p + "."
		}
		return model.VerdictDeletedByWhiteout, "A captured whiteout removes " + p + "."
	}
	if vis.Provider == ProviderMount {
		return model.VerdictShadowedByMount, "Mount " + vis.Mount.Point + " provides this path through an explicit captured-source mapping; it overlays the underlying container filesystem."
	}
	if vis.Layer >= 0 && vis.Layer < len(r.opts.Stack.Layers) && r.opts.Stack.Layers[vis.Layer].Upper {
		if img == nil || img.Missing || img.Deleted {
			return model.VerdictFromUpperAdded, "The writable layer provides this path; no entry was found in the captured lower view."
		}
		if vis.Kind != overlay.KindFile || img.Kind != overlay.KindFile {
			return model.VerdictFromUpper, "The writable layer provides the object's metadata; no content-change history is inferred."
		}
		if vis.sha != "" && vis.sha == img.sha {
			return model.VerdictFromUpperCopyUpSame, "The writable-layer bytes match the captured lower view. This does not establish how or when they were created."
		}
		return model.VerdictFromUpperModified, "The writable-layer bytes differ from the captured lower view."
	}
	return model.VerdictFromImageLayer, "The captured lower layer " + layerLabel(vis.Layer, r.opts.Stack) + " provides this object; OCI layer identity is reported only when mapped."
}

func (r *Resolver) claims(vis, img *located) []model.Claim {
	var out []model.Claim

	if vis != nil && !vis.Missing && !vis.Deleted && !r.incomplete && len(vis.Evidence) > 0 {
		out = append(out, model.Claim{
			Kind:      "visible_provider",
			Answer:    providerAnswer(vis),
			DependsOn: vis.Evidence,
			Strength:  model.Derived,
		})
	}
	if img != nil && !img.Missing && !img.Deleted && !r.incomplete && len(img.Evidence) > 0 {
		out = append(out, model.Claim{
			Kind:      "lower_provider",
			Answer:    providerAnswer(img),
			DependsOn: img.Evidence,
			Strength:  model.Derived,
		})
	}
	if vis != nil && img != nil && vis.sha != "" && img.sha != "" {
		deps := make([]string, 0, len(vis.Evidence)+len(img.Evidence))
		deps = append(deps, vis.Evidence...)
		deps = append(deps, img.Evidence...)
		if len(deps) > 0 {
			out = append(out, model.Claim{
				Kind:      "content_equality",
				Answer:    strconv.FormatBool(vis.sha == img.sha),
				DependsOn: deps,
				Strength:  model.Derived,
			})
		}
	}
	if vis != nil && vis.Deleted && !r.incomplete {
		out = append(out, model.Claim{Kind: "path_blocked", Answer: providerAnswer(vis), DependsOn: vis.Evidence, Strength: model.Derived})
	}
	return out
}

func (r *Resolver) location(l *located) *model.Location {
	if l == nil || l.Missing || l.Deleted {
		return nil
	}
	loc := &model.Location{
		CapturedPath: r.relPath(l.HostPath),
		Provider:     l.Provider,
		Logical:      l.Logical,
		Type:         l.Kind.String(),
		Mode:         l.Mode.String(),
		Size:         l.Size,
		SHA256:       l.sha,
		LinkTarget:   l.LinkTarget,
		MetaCopy:     l.MetaCopy,
	}
	if l.Provider == ProviderMount {
		loc.MountPoint = l.Mount.Point
		loc.MountSource = l.Mount.Source
		return loc
	}
	loc.LayerIndex = l.Layer
	loc.LayerTotal = r.opts.Stack.Len()
	if l.Layer >= 0 && l.Layer < r.opts.Stack.Len() {
		loc.LayerDigest = r.opts.Stack.Layers[l.Layer].Digest
	}
	return loc
}

func (r *Resolver) hash(l *located) (string, error) {
	if cached, ok := r.hashes[l.HostPath]; ok {
		current, err := evidence.Lstat(r.opts.CaseRoot, l.HostPath)
		if err != nil {
			return "", err
		}
		if !evidence.SameState(cached.Info, current) || l.Info != nil && !evidence.SameState(l.Info, current) {
			return "", errors.New("artifact changed before cached hash reuse")
		}
		l.sha = cached.Sum
		l.Evidence = append(l.Evidence, cached.Fact)
		return cached.Sum, nil
	}
	f, err := evidence.OpenRegular(r.opts.CaseRoot, l.HostPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", err
	}
	if l.Info != nil && !evidence.SameState(l.Info, before) {
		return "", errors.New("artifact changed between lookup and hashing")
	}
	if before.Size() > r.opts.MaxFileBytes {
		return "", fmt.Errorf("%w: file exceeds hash budget", evidence.ErrLimit)
	}
	h := sha256.New()
	n, err := evidence.Copy(r.opts.Context, h, f, r.opts.MaxFileBytes)
	if err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil {
		return "", err
	}
	if n != before.Size() || !evidence.SameState(before, after) {
		return "", errors.New("artifact changed while hashing")
	}
	current, err := evidence.Lstat(r.opts.CaseRoot, l.HostPath)
	if err != nil {
		return "", err
	}
	if !evidence.SameState(after, current) {
		return "", errors.New("artifact path changed while hashing")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	l.sha = sum
	id := r.fact("file_content", model.Source{Artifact: "file", Path: r.relPath(l.HostPath)}, model.Observed, map[string]any{"sha256": sum, "size": n})
	l.Evidence = append(l.Evidence, id)
	r.hashes[l.HostPath] = hashRecord{Sum: sum, Fact: id, Info: after}
	return sum, nil
}

func (r *Resolver) fact(kind string, src model.Source, strength model.Strength, value map[string]any) string {
	r.seq++
	id := "f" + strconv.Itoa(r.seq)
	r.facts = append(r.facts, model.Fact{
		ID:       id,
		Kind:     kind,
		Source:   src,
		Strength: strength,
		Value:    value,
	})
	return id
}

func (r *Resolver) layerFact(e overlay.Entry) string {
	return r.fact("layer_entry", model.Source{
		Artifact: "layer",
		Path:     r.relPath(e.HostPath),
	}, model.Observed, map[string]any{
		"layer":               layerLabel(e.Layer, r.opts.Stack),
		"kind":                e.Kind.String(),
		"attribute_namespace": r.opts.Stack.AttrPrefix,
	})
}

func (r *Resolver) step(kind model.StepKind, p, detail string, evidence ...string) {
	r.trace = append(r.trace, model.Step{
		View:     r.view,
		Kind:     kind,
		Path:     p,
		Detail:   detail,
		Evidence: evidence,
	})
}

func (r *Resolver) note(message string) {
	for _, existing := range r.missing {
		if existing == message {
			return
		}
	}
	r.missing = append(r.missing, message)
}

func (r *Resolver) mountSource(m mounts.Entry) model.Source {
	return model.Source{Artifact: r.opts.MountinfoArtifact, Line: m.Line}
}

func (r *Resolver) relPath(hostPath string) string {
	if r.opts.CaseRoot == "" {
		return hostPath
	}
	rel, err := filepath.Rel(r.opts.CaseRoot, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		// Live mode: the artifact lives outside the case root.
		return filepath.ToSlash(filepath.Clean(hostPath))
	}
	return filepath.ToSlash(rel)
}

func layerLabel(idx int, s overlay.Stack) string {
	return strconv.Itoa(idx+1) + "/" + strconv.Itoa(s.Len())
}

func providerAnswer(l *located) string {
	if l.Provider == ProviderMount {
		return "mount:" + l.Mount.Point + ":" + l.Mount.Source
	}
	return "layer:" + strconv.Itoa(l.Layer+1)
}

func kindOf(m os.FileMode) overlay.Kind {
	switch {
	case m&os.ModeSymlink != 0:
		return overlay.KindSymlink
	case m.IsDir():
		return overlay.KindDir
	case m.IsRegular():
		return overlay.KindFile
	default:
		return overlay.KindOther
	}
}

func splitPath(p string) []string {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func within(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	return candidate == root || strings.HasPrefix(candidate, root+string(filepath.Separator))
}
