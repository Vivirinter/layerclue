package acquire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"golang.org/x/sys/unix"
)

type Owner struct{ UID, GID int }
type Options struct {
	Source, Output string
	Plan           Plan
	Limits         custody.Limits
	SigningKey     ed25519.PrivateKey
	Owner          *Owner
}
type Summary struct {
	ContainerID      string `json:"container_id"`
	LayerRoots       int    `json:"layer_roots"`
	CapturedMounts   int    `json:"captured_mounts"`
	UncapturedMounts int    `json:"uncaptured_namespace_mounts"`
	SourceReadOnly   bool   `json:"source_read_only_mount_observed"`
	SourceMode       string `json:"source_mode"`
}
type omittedMount struct {
	ID     int    `json:"mount_id"`
	Point  string `json:"mount_point"`
	FSType string `json:"filesystem"`
}
type aliasCapture struct{ Source, Name, Target string }
type tree struct{ Source, Output, Prefix string }

type journal struct {
	Schema        string         `json:"schema"`
	Scope         string         `json:"scope"`
	StartedAt     string         `json:"acquisition_started_at"`
	CompletedAt   string         `json:"acquisition_completed_at"`
	Plan          Plan           `json:"plan"`
	PlanSHA256    string         `json:"canonical_plan_sha256"`
	Summary       Summary        `json:"summary"`
	Entries       []sourceEntry  `json:"source_entries"`
	Aliases       []docker.Alias `json:"aliases,omitempty"`
	Omitted       []omittedMount `json:"uncaptured_mounts,omitempty"`
	Discrepancies []string       `json:"inspect_mount_discrepancies,omitempty"`
}

// Docker imports one classic overlay2 container from an operator-selected
// offline host snapshot. A read-only mount observation is NOT proof that a
// snapshot was atomic or immutable through every other storage access path.
func Docker(ctx context.Context, o Options) (*Summary, error) {
	if ctx == nil {
		return nil, errors.New("acquisition requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := o.Plan.Validate(); err != nil {
		return nil, err
	}
	if o.Limits.FileBytes <= 0 || o.Limits.FileBytes > 8<<30 || o.Limits.TotalBytes <= 0 || o.Limits.TotalBytes > 32<<30 {
		return nil, evidence.ErrLimit
	}
	if len(o.SigningKey) != 0 && len(o.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	if o.Owner != nil && (o.Owner.UID < 0 || o.Owner.GID < 0 || uint64(o.Owner.UID) > 1<<31-1 || uint64(o.Owner.GID) > 1<<31-1) {
		return nil, errors.New("invalid output owner")
	}
	if o.Owner != nil {
		if err := validateOwner(*o.Owner); err != nil {
			return nil, err
		}
	}
	source, err := filepath.Abs(o.Source)
	if err != nil {
		return nil, err
	}
	if source == "/" {
		return nil, errors.New("acquisition refuses the live filesystem root; select an offline snapshot")
	}
	output, err := filepath.Abs(o.Output)
	if err != nil {
		return nil, err
	}
	if err := custody.Outside(source, output); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("output exists or cannot be checked")
	}
	readOnly, err := evidence.FilesystemReadOnly(source)
	if err != nil {
		return nil, err
	}
	if o.Plan.SourceMode == "read_only_mount" && !readOnly {
		return nil, errors.New("source is writable; use an actual read-only snapshot mount or explicitly declare an immutable working copy in the plan")
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	p := o.Plan
	inspectData, err := evidence.ReadFile(source, p.Inspect, evidence.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	mountData, err := evidence.ReadFile(source, p.Mountinfo, evidence.MaxMountinfoBytes)
	if err != nil {
		return nil, err
	}
	record, err := docker.Read(source, p.Inspect, p.ContainerID)
	if err != nil {
		return nil, err
	}
	if record.SHA256 != "sha256:"+hash(inspectData) {
		return nil, errors.New("inspect changed during preparation")
	}
	table, err := mounts.Parse(bytes.NewReader(mountData))
	if err != nil {
		return nil, err
	}
	root, _, err := table.Select("/")
	if err != nil {
		return nil, err
	}
	if root.FSType != "overlay" || root.Root != "/" {
		return nil, errors.New("acquisition requires a complete root OverlayFS mount")
	}
	prefix := "trusted.overlay."
	for _, v := range append(append([]string(nil), root.Options...), root.SuperOptions...) {
		if v == "userxattr" {
			prefix = "user.overlay."
		}
	}
	if p.OverlayAttributes == "capture" {
		prefix = "user.layerclue.overlay."
	}
	if prefix == "trusted.overlay." {
		if err := trustedReadContext(); err != nil {
			return nil, err
		}
	}
	var aliases []aliasCapture
	if err := record.CheckStackWithAliases(root, func(address, wanted string) error {
		name, err := docker.AliasName(record.GraphDriver.Data["UpperDir"], address)
		if err != nil {
			return err
		}
		ref := strings.TrimPrefix(address, "/")
		target, err := evidence.Readlink(source, ref)
		if err != nil {
			return err
		}
		if err := docker.CheckAliasTarget(record.GraphDriver.Data["UpperDir"], address, wanted, target); err != nil {
			return err
		}
		aliases = append(aliases, aliasCapture{Source: ref, Name: name, Target: target})
		return nil
	}); err != nil {
		return nil, err
	}
	// Sources come from validated inspect addresses. Destinations mirror the
	// mountinfo addresses, materialising lower aliases as real captured trees.
	var trees []tree
	lowers := strings.Split(record.GraphDriver.Data["LowerDir"], ":")
	for i, address := range root.LowerDirs() {
		trees = append(trees, tree{Source: strings.TrimPrefix(lowers[i], "/"), Output: "host/" + strings.TrimPrefix(address, "/"), Prefix: prefix})
	}
	upper := record.GraphDriver.Data["UpperDir"]
	trees = append(trees, tree{Source: strings.TrimPrefix(upper, "/"), Output: "host/" + strings.TrimPrefix(upper, "/"), Prefix: prefix})
	summary := Summary{ContainerID: p.ContainerID, LayerRoots: len(trees), CapturedMounts: len(p.Mounts), SourceReadOnly: readOnly, SourceMode: p.SourceMode}
	mapped := map[int]bool{root.ID: true}
	byID := map[int]mounts.Entry{}
	for _, m := range table {
		byID[m.ID] = m
	}
	var captured []casefile.CapturedMount
	for _, m := range p.Mounts {
		if m.ID == root.ID {
			return nil, errors.New("root overlay is captured through layers, not a mount-source override")
		}
		if _, ok := byID[m.ID]; !ok {
			return nil, fmt.Errorf("mount %d is absent from captured mountinfo", m.ID)
		}
		artifact := "mounts/" + strconv.Itoa(m.ID)
		trees = append(trees, tree{Source: m.Source, Output: artifact})
		captured = append(captured, casefile.CapturedMount{ID: m.ID, Artifact: artifact, Complete: m.Complete})
		mapped[m.ID] = true
	}
	for _, t := range trees {
		if !canonical(t.Source) || !canonical(t.Output) {
			return nil, errors.New("invalid source or output artifact root")
		}
		st, err := evidence.Lstat(source, t.Source)
		if err != nil {
			return nil, err
		}
		if t.Prefix != "" && !st.IsDir() {
			return nil, errors.New("overlay source root must be a physical captured directory")
		}
		if t.Prefix == "" && !st.IsDir() && !st.Mode().IsRegular() {
			return nil, errors.New("captured mount root must be a regular file or directory")
		}
	}
	// No copied logical symlink can become an ancestor of a later output root.
	if err := disjoint(trees); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".layerclue-acquire-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	dst := filepath.Join(stage, "case")
	if err := os.Mkdir(dst, 0700); err != nil {
		return nil, err
	}
	copier := treeCopy{ctx: ctx, root: source, dst: dst, limits: o.Limits, links: map[[2]uint64]string{}}
	for _, t := range trees {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, t.Output)), 0700); err != nil {
			return nil, err
		}
		if err := copier.copy(t.Source, t.Output, t.Prefix, 0); err != nil {
			return nil, fmt.Errorf("copy %q: %w", t.Source, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dst, "docker-links"), 0700); err != nil {
		return nil, err
	}
	j := journal{Schema: JournalSchema, StartedAt: started, Plan: p, Summary: summary, Entries: copier.entries, Scope: "selected offline Docker overlay2 layer roots and explicitly mapped mount roots; source type/content/mode/owner/mtime/internal hardlinks and active OverlayFS markers recorded; symlink xattrs, unrelated xattrs, source authenticity, true snapshot atomicity and whole-container completeness are not proven; output permissions/owners/timestamps transformed, no devices/capabilities/execution bits recreated"}
	for _, alias := range aliases {
		artifact := "docker-links/" + alias.Name
		if err := os.Symlink(alias.Target, filepath.Join(dst, artifact)); err != nil {
			return nil, err
		}
		j.Aliases = append(j.Aliases, docker.Alias{Artifact: artifact, Address: "/" + alias.Source, Target: alias.Target})
	}
	for _, m := range table {
		if !mapped[m.ID] {
			j.Omitted = append(j.Omitted, omittedMount{ID: m.ID, Point: m.Point, FSType: m.FSType})
		}
	}
	for _, m := range record.Mounts {
		visible, _, err := table.Select(m.Destination)
		if err != nil || visible.Point != m.Destination {
			j.Discrepancies = append(j.Discrepancies, "inspect destination is not a visible namespace mount: "+m.Destination)
		}
	}
	summary.UncapturedMounts = len(j.Omitted)
	j.Summary = summary
	planData, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	j.PlanSHA256 = hash(planData)
	if err := writeFile(filepath.Join(dst, "mountinfo"), mountData); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(dst, "docker-inspect.json"), inspectData); err != nil {
		return nil, err
	}
	manifest := struct {
		Schema        string                   `json:"schema"`
		HostRoot      string                   `json:"host_root"`
		Mountinfo     string                   `json:"mountinfo"`
		ContainerID   string                   `json:"container_id"`
		DockerInspect string                   `json:"docker_inspect"`
		DockerAliases string                   `json:"docker_alias_root"`
		Attributes    string                   `json:"overlay_xattr_namespace"`
		Mounts        []casefile.CapturedMount `json:"mounts,omitempty"`
	}{casefile.SchemaCase, "host", "mountinfo", p.ContainerID, "docker-inspect.json", "docker-links", "capture", captured}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(dst, "case.json"), data); err != nil {
		return nil, err
	}
	if err := copier.recheck(); err != nil {
		return nil, err
	}
	for _, alias := range aliases {
		target, err := evidence.Readlink(source, alias.Source)
		if err != nil {
			return nil, err
		}
		if target != alias.Target {
			return nil, errors.New("source alias changed during acquisition")
		}
	}
	for ref, original := range map[string][]byte{p.Inspect: inspectData, p.Mountinfo: mountData} {
		current, err := evidence.ReadFile(source, ref, max(evidence.MaxMountinfoBytes, evidence.MaxManifestBytes))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, original) {
			return nil, errors.New("source control artifact changed during acquisition")
		}
	}
	readOnlyNow, err := evidence.FilesystemReadOnly(source)
	if err != nil {
		return nil, err
	}
	if readOnlyNow != readOnly {
		return nil, errors.New("source mount write policy changed during acquisition")
	}
	j.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	data, err = json.Marshal(j)
	if err != nil {
		return nil, err
	}
	if len(data) > custody.MaxInventoryBytes {
		return nil, evidence.ErrLimit
	}
	if err := writeFile(filepath.Join(dst, custody.AcquisitionFile), data); err != nil {
		return nil, err
	}
	c, err := casefile.Open(dst)
	if err != nil {
		return nil, err
	}
	if _, err := c.Identity(); err != nil {
		return nil, fmt.Errorf("assembled case identity: %w", err)
	}
	if o.Owner != nil {
		if err := assignOwner(dst, *o.Owner); err != nil {
			return nil, err
		}
	}
	seal, err := custody.New(ctx, dst, p.Method, o.Limits, o.SigningKey)
	if err != nil {
		return nil, err
	}
	data, err = json.Marshal(seal)
	if err != nil {
		return nil, err
	}
	if _, err := custody.Decode(data); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(stage, "inventory.json"), data); err != nil {
		return nil, err
	}
	if o.Owner != nil {
		if err := os.Chown(filepath.Join(stage, "inventory.json"), o.Owner.UID, o.Owner.GID); err != nil {
			return nil, err
		}
	}
	var pub ed25519.PublicKey
	if len(o.SigningKey) > 0 {
		pub = o.SigningKey.Public().(ed25519.PublicKey)
	}
	if err := custody.Verify(ctx, dst, seal, o.Limits, pub); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.Owner != nil {
		if err := os.Chown(stage, o.Owner.UID, o.Owner.GID); err != nil {
			return nil, err
		}
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return nil, err
	}
	return &summary, nil
}
func writeFile(name string, data []byte) error {
	// #nosec G304 -- Only fixed generated metadata destinations inside the new private import stage.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
func assignOwner(root string, o Owner) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return fs.WalkDir(dir.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return dir.Lchown(p, o.UID, o.GID)
	})
}

func disjoint(trees []tree) error {
	roots := map[string]bool{}
	for _, t := range trees {
		if roots[t.Output] {
			return errors.New("duplicate output artifact root")
		}
		roots[t.Output] = true
	}
	for _, t := range trees {
		for parent := path.Dir(t.Output); parent != "." && parent != "/"; parent = path.Dir(parent) {
			if roots[parent] {
				return errors.New("overlapping output artifact roots")
			}
		}
	}
	return nil
}

func validateOwner(o Owner) error {
	if o.UID == os.Geteuid() {
		if o.GID == os.Getegid() {
			return nil
		}
		groups, err := os.Getgroups()
		if err != nil {
			return err
		}
		for _, g := range groups {
			if o.GID == g {
				return nil
			}
		}
	}
	if os.Geteuid() != 0 {
		return errors.New("foreign output ownership requires root with CHOWN and DAC_OVERRIDE capabilities")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	needed := uint32((1 << unix.CAP_CHOWN) | (1 << unix.CAP_DAC_OVERRIDE))
	if caps[0].Effective&needed != needed {
		return errors.New("foreign output ownership requires CHOWN and DAC_OVERRIDE capabilities")
	}
	return nil
}

// A capability in a subordinate user namespace does not authorise trusted.*
// attributes on a host-owned filesystem. These are necessary guards, not proof
// of a filesystem's owning namespace or the truth of acquisition assertions.
func trustedReadContext() error {
	if !evidence.CanReadTrusted() {
		return errors.New("native trusted OverlayFS metadata requires authorised read capability; export it in a controlled acquisition environment")
	}
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	if !initialStyleUIDMap(data) {
		return errors.New("native trusted attribute export refuses subordinate UID mappings; use an authorised filesystem namespace or a portable capture")
	}
	return nil
}

func initialStyleUIDMap(data []byte) bool {
	fields := strings.Fields(string(data))
	return len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}
