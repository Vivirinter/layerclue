// Package casefile opens a directory of captured container artifacts.
//
// A case is self-contained and portable: every path inside it is relative to
// the case root, which is what makes a report reproducible on a different
// machine.
package casefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/oci"
	"github.com/Vivirinter/layerclue/internal/overlay"
)

// SchemaCase is the wire schema of a case manifest.
const SchemaCase = "layerclue.case/v1"

var (
	// ErrNoCase means the directory does not look like a layerclue case.
	ErrNoCase = errors.New("not a layerclue case")
	// ErrNoMountinfo means no captured mount table was found.
	ErrNoMountinfo = errors.New("case has no mountinfo artifact")
	// ErrNoOverlay means the captured mount table has no overlay mount.
	ErrNoOverlay = errors.New("case has no overlay mount")
)

type manifest struct {
	Schema          string                 `json:"schema"`
	HostRoot        string                 `json:"host_root"`
	Mountinfo       string                 `json:"mountinfo"`
	Metadata        string                 `json:"containerd_metadata"`
	DockerInspect   string                 `json:"docker_inspect,omitempty"`
	DockerAliasRoot string                 `json:"docker_alias_root,omitempty"`
	ContainerID     string                 `json:"container_id"`
	PID             int                    `json:"pid"`
	Mounts          []CapturedMount        `json:"mounts,omitempty"`
	XattrNamespace  string                 `json:"overlay_xattr_namespace,omitempty"`
	ImageProvenance *ImageProvenanceConfig `json:"image_provenance,omitempty"`
}

type ImageProvenanceConfig struct {
	ManifestDigest      string `json:"manifest_digest"`
	ContentRoot         string `json:"content_root"`
	SnapshotterMetadata string `json:"snapshotter_metadata"`
	SnapshotterRoot     string `json:"snapshotter_root"`
}

// CapturedMount maps a namespace mount ID to the captured root of that mount.
// Artifact is case-relative, never a path inferred from mountinfo's source.
// Complete asserts that missing descendants represent absence, not a partial copy.
type CapturedMount struct {
	ID       int    `json:"mount_id"`
	Artifact string `json:"artifact"`
	Complete bool   `json:"complete"`
	Root     string `json:"-"`
}

// Case is an opened case directory.
type Case struct {
	// Root is the absolute path of the case directory.
	Root string
	// HostRoot is the absolute prefix that mirrors the captured host.
	HostRoot string
	// Mountinfo is the absolute path of the captured mount table.
	Mountinfo string
	// MountinfoRef is the path of the mount table relative to Root, used in
	// report facts so reports stay portable.
	MountinfoRef string
	// Metadata is the absolute path of the containerd metadata database, or
	// empty when the case does not carry one.
	Metadata string
	// MetadataRef is that path relative to Root.
	MetadataRef     string
	DockerInspect   string
	DockerAliasRoot string
	ContainerID     string
	PID             int
	MountSources    map[int]CapturedMount
	XattrNamespace  string
	ImageProvenance *ImageProvenanceConfig
}

// Open reads a case directory. When case.json is absent the layout is
// discovered: host/proc/<pid>/mountinfo, or proc/<pid>/mountinfo.
func Open(dir string) (*Case, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrNoCase, root)
	}

	var m manifest
	switch b, err := evidence.ReadFile(root, filepath.Join(root, "case.json"), evidence.MaxManifestBytes); {
	case err == nil:
		if err := evidence.DecodeJSON(b, &m); err != nil {
			return nil, fmt.Errorf("case.json: %w", err)
		}
		if m.Schema != SchemaCase {
			return nil, fmt.Errorf("unsupported case schema %q", m.Schema)
		}
	case errors.Is(err, os.ErrNotExist):
		// Discovery below.
	default:
		return nil, err
	}

	c := &Case{Root: root, ContainerID: m.ContainerID, PID: m.PID, MountSources: make(map[int]CapturedMount)}
	if m.DockerAliasRoot != "" {
		if m.DockerInspect == "" {
			return nil, errors.New("docker_alias_root requires docker_inspect")
		}
		if err := evidence.Local(m.DockerAliasRoot); err != nil {
			return nil, err
		}
		c.DockerAliasRoot = m.DockerAliasRoot
	}
	if m.DockerInspect != "" {
		if err := evidence.Local(m.DockerInspect); err != nil {
			return nil, err
		}
		if m.Metadata != "" || m.ImageProvenance != nil {
			return nil, errors.New("docker_inspect cannot be combined with containerd metadata/provenance")
		}
		if m.ContainerID == "" {
			return nil, errors.New("docker_inspect requires an explicit full container_id")
		}
		c.DockerInspect = m.DockerInspect
		if _, err := evidence.ReadFile(root, m.DockerInspect, evidence.MaxManifestBytes); err != nil {
			return nil, fmt.Errorf("docker_inspect: %w", err)
		}
	}
	if m.XattrNamespace != "" && m.XattrNamespace != "capture" {
		return nil, errors.New("overlay_xattr_namespace may only select the explicit capture export format")
	}
	c.XattrNamespace = m.XattrNamespace
	c.ImageProvenance = m.ImageProvenance
	if m.ImageProvenance != nil {
		p := m.ImageProvenance
		if !oci.ValidDigest(p.ManifestDigest) {
			return nil, errors.New("image_provenance requires an explicit sha256 platform manifest digest")
		}
		for _, name := range []string{p.ContentRoot, p.SnapshotterMetadata, p.SnapshotterRoot} {
			if err := evidence.Local(name); err != nil {
				return nil, err
			}
		}
		if m.ContainerID == "" {
			return nil, errors.New("image_provenance requires an explicit container_id")
		}
	}
	if m.PID < 0 {
		return nil, errors.New("pid must not be negative")
	}

	hostRel := m.HostRoot
	if hostRel == "" {
		hostRel = "host"
	}
	if err := evidence.Local(hostRel); err != nil {
		return nil, fmt.Errorf("host_root: %w", err)
	}
	c.HostRoot = filepath.Join(root, filepath.FromSlash(hostRel))
	st, hostErr := evidence.Lstat(root, c.HostRoot)
	if errors.Is(hostErr, os.ErrNotExist) && m.HostRoot == "" {
		c.HostRoot = root
	} else if hostErr != nil {
		return nil, hostErr
	} else if !st.IsDir() {
		return nil, errors.New("host_root must be a captured directory, not a symlink")
	}

	mountRel := m.Mountinfo
	if mountRel == "" {
		found, err := discoverMountinfo(root, m.PID)
		if err != nil {
			return nil, err
		}
		mountRel = found
	}
	if err := evidence.Local(mountRel); err != nil {
		return nil, err
	}
	c.Mountinfo = filepath.Join(root, filepath.FromSlash(mountRel))
	if fi, err := evidence.Lstat(root, c.Mountinfo); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNoMountinfo, c.Mountinfo)
	}
	if rel, err := filepath.Rel(root, c.Mountinfo); err == nil {
		c.MountinfoRef = filepath.ToSlash(rel)
	} else {
		c.MountinfoRef = filepath.ToSlash(c.Mountinfo)
	}

	metaRel := m.Metadata
	if metaRel == "" && c.DockerInspect == "" {
		var err error
		metaRel, err = discoverMetadata(root)
		if err != nil {
			return nil, err
		}
	}
	if metaRel != "" {
		if err := evidence.Local(metaRel); err != nil {
			return nil, err
		}
		c.Metadata = filepath.Join(root, filepath.FromSlash(metaRel))
		if fi, err := evidence.Lstat(root, c.Metadata); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("metadata artifact is missing or not a regular file: %q", metaRel)
		}
	}
	if c.Metadata != "" {
		if rel, err := filepath.Rel(root, c.Metadata); err == nil {
			c.MetadataRef = filepath.ToSlash(rel)
		} else {
			c.MetadataRef = filepath.ToSlash(c.Metadata)
		}
	}
	for _, captured := range m.Mounts {
		if captured.ID <= 0 {
			return nil, errors.New("mount_id must be positive")
		}
		if _, ok := c.MountSources[captured.ID]; ok {
			return nil, fmt.Errorf("duplicate mount mapping %d", captured.ID)
		}
		if err := evidence.Local(captured.Artifact); err != nil {
			return nil, err
		}
		captured.Root = filepath.Join(root, filepath.FromSlash(captured.Artifact))
		c.MountSources[captured.ID] = captured
	}
	if c.ImageProvenance != nil && c.Metadata == "" {
		return nil, errors.New("image_provenance requires captured containerd metadata")
	}
	return c, nil
}

// MountTable parses the captured mount table.
func (c *Case) MountTable() (mounts.Table, error) {
	b, err := evidence.ReadFile(c.Root, c.Mountinfo, evidence.MaxMountinfoBytes)
	if err != nil {
		return nil, err
	}
	table, err := mounts.Parse(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	ids := make(map[int]bool, len(table))
	for _, entry := range table {
		ids[entry.ID] = true
	}
	for id := range c.MountSources {
		if !ids[id] {
			return nil, fmt.Errorf("captured mount %d is absent from mountinfo", id)
		}
	}
	return table, nil
}

// HostPath maps a path from the captured host namespace into the case.
func (c *Case) HostPath(hostPath string) (string, error) {
	if !strings.HasPrefix(hostPath, "/") {
		return "", fmt.Errorf("captured host path is not absolute: %q", hostPath)
	}
	rel := strings.TrimPrefix(hostPath, "/")
	if rel == "" {
		rel = "."
	}
	if err := evidence.Local(rel); err != nil {
		return "", err
	}
	return filepath.Join(c.HostRoot, filepath.FromSlash(rel)), nil
}

// OverlayMount returns the visible namespace-root overlay. Other snapshotters
// and nested overlays are not guessed from an arbitrary entry in the table.
func (c *Case) OverlayMount(t mounts.Table) (mounts.Entry, bool) {
	chosen, _, err := t.Select("/")
	return chosen, err == nil && chosen.FSType == "overlay"
}

// Stack reconstructs the overlay stack described by the captured mount table.
//
// Layers are returned bottom first, which is the order the resolver needs.
// Directories that were not captured are kept in the stack and marked
// missing: dropping them would silently change the answer.
func (c *Case) Stack(t mounts.Table) (overlay.Stack, []string, error) {
	if _, _, err := t.Select("/"); err != nil {
		return overlay.Stack{}, nil, fmt.Errorf("invalid mount context: %w", err)
	}
	chosen, ok := c.OverlayMount(t)
	if !ok {
		return overlay.Stack{}, nil, ErrNoOverlay
	}
	if chosen.Root != "/" {
		return overlay.Stack{}, nil, fmt.Errorf("%w: shifted OverlayFS root %q", overlay.ErrUnsupported, chosen.Root)
	}
	for _, option := range chosen.SuperOptions {
		key, _, _ := strings.Cut(option, "=")
		if key == "lowerdir+" || key == "datadir+" {
			return overlay.Stack{}, nil, fmt.Errorf("%w: lowerdir+/datadir+ mount encoding", overlay.ErrUnsupported)
		}
	}

	upper := chosen.SuperValue("upperdir")
	lowers := chosen.LowerDirs()
	layerCount := len(lowers)
	if upper != "" {
		layerCount++
	}
	if layerCount > overlay.MaxLayers {
		return overlay.Stack{}, nil, evidence.ErrLimit
	}
	for _, lower := range lowers {
		if lower == "" {
			return overlay.Stack{}, nil, fmt.Errorf("%w: data-only or empty lowerdir", overlay.ErrUnsupported)
		}
	}
	if upper == "" && len(lowers) == 0 {
		return overlay.Stack{}, nil, ErrNoOverlay
	}

	var (
		stack   = overlay.Stack{Boundary: c.Root}
		missing []string
	)
	for _, option := range append(append([]string(nil), chosen.Options...), chosen.SuperOptions...) {
		if option == "userxattr" {
			stack.AttrPrefix = "user.overlay."
		}
	}
	if c.XattrNamespace == "capture" {
		stack.AttrPrefix = "user.layerclue.overlay."
	}
	for i := len(lowers) - 1; i >= 0; i-- {
		name, err := c.HostPath(lowers[i])
		if err != nil {
			return overlay.Stack{}, nil, err
		}
		layer := overlay.Layer{Root: name}
		fi, err := evidence.Lstat(c.Root, layer.Root)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return overlay.Stack{}, nil, err
		}
		if err != nil {
			layer.Missing = true
			missing = append(missing, lowers[i])
		} else if !fi.IsDir() {
			return overlay.Stack{}, nil, fmt.Errorf("layer must be a captured directory: %q", lowers[i])
		}
		stack.Layers = append(stack.Layers, layer)
	}
	if upper != "" {
		name, err := c.HostPath(upper)
		if err != nil {
			return overlay.Stack{}, nil, err
		}
		layer := overlay.Layer{Root: name, Upper: true}
		fi, err := evidence.Lstat(c.Root, layer.Root)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return overlay.Stack{}, nil, err
		}
		if err != nil {
			layer.Missing = true
			missing = append(missing, upper)
		} else if !fi.IsDir() {
			return overlay.Stack{}, nil, fmt.Errorf("upper must be a captured directory: %q", upper)
		}
		stack.Layers = append(stack.Layers, layer)
	}
	for i := range stack.Layers {
		stack.Layers[i].Index = i
	}
	return stack, missing, nil
}

func discoverMountinfo(root string, pid int) (string, error) {
	var found []string
	for _, parent := range []string{"host/proc", "proc"} {
		dir, err := evidence.OpenDir(root, filepath.Join(root, parent))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		count := 0
		for {
			entries, readErr := dir.ReadDir(128)
			for _, entry := range entries {
				count++
				if count > 4096 {
					_ = dir.Close()
					return "", evidence.ErrLimit
				}
				if !entry.IsDir() {
					continue
				}
				if pid > 0 && entry.Name() != strconv.Itoa(pid) {
					continue
				}
				rel := filepath.Join(parent, entry.Name(), "mountinfo")
				if fi, err := evidence.Lstat(root, filepath.Join(root, rel)); err == nil && fi.Mode().IsRegular() {
					found = append(found, filepath.ToSlash(rel))
					if len(found) > 1 {
						_ = dir.Close()
						return "", errors.New("multiple process mount tables; select mountinfo explicitly in case.json")
					}
				} else if err != nil && !errors.Is(err, os.ErrNotExist) {
					_ = dir.Close()
					return "", err
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = dir.Close()
				return "", readErr
			}
		}
		_ = dir.Close()
	}
	if len(found) == 1 {
		return found[0], nil
	}
	return "", ErrNoMountinfo
}

func discoverMetadata(root string) (string, error) {
	var found string
	for _, rel := range []string{"containerd/meta.db", "evidence/containerd/meta.db", "host/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"} {
		fi, err := evidence.Lstat(root, filepath.Join(root, rel))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("metadata artifact is not a regular file: %q", rel)
		}
		if found != "" {
			return "", errors.New("multiple metadata databases; select containerd_metadata explicitly")
		}
		found = rel
	}
	return found, nil
}
