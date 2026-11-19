//go:build linux

package lab

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/verify"
)

// This explicitly opted-in lab uses only new unnamed objects and local scratch
// image bytes. It never pulls images, touches pre-existing containers or prunes.
func TestDockerOverlay2(t *testing.T) {
	if os.Getenv("LAYERCLUE_DOCKER_TEST") != "1" {
		t.Skip("opt in with LAYERCLUE_DOCKER_TEST=1; requires a local classic overlay2 Docker daemon")
	}
	if host := os.Getenv("DOCKER_HOST"); host != "" && !strings.HasPrefix(host, "unix://") {
		t.Fatal("Docker lab requires a local Unix-socket daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dockerCmd := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker %v: %v: %s", args, err, out)
		}
		return out
	}
	endpoint := strings.TrimSpace(string(dockerCmd("context", "inspect", "--format", `{{(index .Endpoints "docker").Host}}`)))
	if !strings.HasPrefix(endpoint, "unix://") {
		t.Fatal("Docker lab refuses a non-local context")
	}
	if driver := strings.TrimSpace(string(dockerCmd("info", "--format", "{{.Driver}}"))); driver != "overlay2" {
		t.Fatalf("requires classic overlay2, got %q", driver)
	}
	root := t.TempDir()
	helper := filepath.Join(root, "labfixture")
	cli := filepath.Join(root, "layerclue")
	for dst, pkg := range map[string]string{helper: "../../tools/labfixture", cli: "../../cmd/layerclue"} {
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", dst, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v %s", err, out)
		}
	}
	application, err := os.ReadFile(cli)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	tw := tar.NewWriter(&input)
	for _, dir := range []string{"opt/", "capture/"} {
		if err := tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string][]byte{"lab": binary, "layerclue": application, "opt/unchanged": []byte("base unchanged\n"), "opt/modified": []byte("base modified\n"), "opt/deleted": []byte("base deleted\n"), "opt/bound": []byte("image bound\n")} {
		mode := int64(0644)
		if name == "lab" || name == "layerclue" {
			mode = 0755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", "import", "-")
	cmd.Stdin = &input
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("import: %v %s", err, raw)
	}
	image := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(image, "sha256:") || len(image) != 71 {
		t.Fatalf("unexpected import identity %q", image)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(c, "docker", "image", "rm", image).CombinedOutput(); err != nil {
			t.Errorf("cleanup own image: %v %s", err, out)
		}
	})
	capture := filepath.Join(root, "capture")
	if err := os.Mkdir(capture, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(capture, 0777); err != nil {
		t.Fatal(err)
	}
	bound := filepath.Join(root, "bound")
	if err := os.WriteFile(bound, []byte("bind bytes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	target := strings.TrimSpace(string(dockerCmd("create", "--network", "none", "--pids-limit", "32", "--memory", "128m", "--mount", "type=bind,src="+capture+",dst=/capture", "--mount", "type=bind,src="+bound+",dst=/opt/bound,readonly", image, "/lab", "serve")))
	if !docker.FullID(target) {
		t.Fatal("invalid owned container identity")
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(c, "docker", "rm", "-f", target).CombinedOutput(); err != nil {
			t.Errorf("cleanup own container: %v %s", err, out)
		}
	})
	dockerCmd("start", target)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(capture, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lab startup timeout: %s", dockerCmd("logs", target))
		}
		time.Sleep(100 * time.Millisecond)
	}
	dockerCmd("pause", target) // only our new fixture, never a user workload
	raw = dockerCmd("inspect", target)
	var records []docker.Record
	if err := json.Unmarshal(raw, &records); err != nil || len(records) != 1 {
		t.Fatalf("inspect: %v", err)
	}
	r := records[0]
	caseRoot := filepath.Join(capture, "case")
	if err := os.Mkdir(caseRoot, 0700); err != nil {
		t.Fatal(err)
	}
	mi, err := os.ReadFile(filepath.Join(capture, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseRoot, "mountinfo"), mi, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseRoot, "docker.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	type mapping struct {
		Source   string `json:"source"`
		Artifact string `json:"artifact"`
	}
	var mappings []mapping
	table, err := mounts.Parse(bytes.NewReader(mi))
	if err != nil {
		t.Fatal(err)
	}
	rootMount, _, err := table.Select("/")
	if err != nil {
		t.Fatal(err)
	}
	sources := append(rootMount.LowerDirs(), r.GraphDriver.Data["UpperDir"], bound)
	var aliasNames []string
	aliasParent := ""
	for _, lower := range rootMount.LowerDirs() {
		if filepath.Base(filepath.Dir(lower)) == "l" {
			aliasParent = filepath.Dir(lower)
			aliasNames = append(aliasNames, filepath.Base(lower))
		}
	}
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--pids-limit", "32", "--memory", "256m", "--cpus", "1", "--cap-drop", "ALL", "--cap-add", "SYS_ADMIN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges", "--mount", "type=bind,src=" + capture + ",dst=/capture"}
	for i, src := range sources {
		if !strings.HasPrefix(src, "/") || strings.Contains(src, ",") {
			t.Fatal("unsupported lab source address")
		}
		dest := fmt.Sprintf("/sources/%d", i)
		args = append(args, "--mount", "type=bind,src="+src+",dst="+dest+",readonly")
		artifact := "host/" + strings.TrimPrefix(src, "/")
		if i == len(sources)-1 {
			artifact = "mounts/bound"
		}
		mappings = append(mappings, mapping{dest, artifact})
	}
	if aliasParent != "" {
		args = append(args, "--mount", "type=bind,src="+aliasParent+",dst=/aliases,readonly")
	}
	plan, _ := json.Marshal(struct {
		UID, GID   int
		Mappings   []mapping
		AliasNames []string
	}{os.Getuid(), os.Getgid(), mappings, aliasNames})
	if err := os.WriteFile(filepath.Join(capture, "plan.json"), plan, 0644); err != nil {
		t.Fatal(err)
	}
	args = append(args, image, "/lab", "copy")
	dockerCmd(args...)
	// Source mappings are explicit and derived from our fixture acquisition.
	entry, _, err := table.Select("/opt/bound")
	if err != nil || entry.Point != "/opt/bound" {
		t.Fatalf("bind mapping: %v", err)
	}
	manifest := fmt.Sprintf(`{"schema":"layerclue.case/v1","host_root":"host","mountinfo":"mountinfo","container_id":%q,"docker_inspect":"docker.json","docker_alias_root":"docker-links","overlay_xattr_namespace":"capture","mounts":[{"mount_id":%d,"artifact":"mounts/bound","complete":true}]}`, target, entry.ID)
	if err := os.WriteFile(filepath.Join(caseRoot, "case.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path    string
		verdict model.Verdict
	}{{"/opt/unchanged", model.VerdictFromImageLayer}, {"/opt/modified", model.VerdictFromUpperModified}, {"/opt/added", model.VerdictFromUpperAdded}, {"/opt/deleted", model.VerdictDeletedByWhiteout}, {"/opt/bound", model.VerdictShadowedByMount}} {
		t.Run(tc.path, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, cli, "explain", tc.path, "--case", caseRoot, "--json", "--strict")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("explain: %v %s", err, out)
			}
			var rep model.Report
			if err := json.Unmarshal(out, &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Runtime != "docker" || rep.ContainerID != target || rep.Verdict != tc.verdict {
				t.Fatalf("wrong provenance: %+v", rep)
			}
			if p := verify.Report(&rep); len(p) > 0 {
				t.Fatal(p)
			}
		})
	}
	bundle := filepath.Join(root, "bundle")
	for _, args := range [][]string{
		{"collect", "--case", caseRoot, "--output", bundle, "--method", "disposable Docker fixture paused before layer export"},
		{"verify-case", "--case", filepath.Join(bundle, "case"), "--inventory", filepath.Join(bundle, "inventory.json")},
		{"explain", "/opt/bound", "--case", filepath.Join(bundle, "case"), "--strict"},
	} {
		cmd := exec.CommandContext(ctx, cli, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bundle round trip: %v %s", err, out)
		}
	}
	// Re-export into a host-shaped snapshot, then exercise the production importer.
	// This is an explicit portable export; no claim of raw snapshot authenticity.
	snapshotMappings := append([]mapping(nil), mappings...)
	lowerSources := strings.Split(r.GraphDriver.Data["LowerDir"], ":")
	for i := range lowerSources {
		snapshotMappings[i].Artifact = strings.TrimPrefix(lowerSources[i], "/")
	}
	snapshotMappings[len(snapshotMappings)-2].Artifact = strings.TrimPrefix(r.GraphDriver.Data["UpperDir"], "/")
	snapshotMappings[len(snapshotMappings)-1].Artifact = "saved-mounts/bound"
	aliasRoot := "docker-links"
	if aliasParent != "" {
		aliasRoot = strings.TrimPrefix(aliasParent, "/")
	}
	rawPlan, _ := json.Marshal(struct {
		UID, GID          int
		Mappings          []mapping
		AliasNames        []string
		Output, AliasRoot string
	}{os.Getuid(), os.Getgid(), snapshotMappings, aliasNames, "snapshot", aliasRoot})
	if err := os.WriteFile(filepath.Join(capture, "plan.json"), rawPlan, 0644); err != nil {
		t.Fatal(err)
	}
	dockerCmd(args...)
	snapshot := filepath.Join(capture, "snapshot")
	if err := os.Mkdir(filepath.Join(snapshot, "metadata"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "metadata/inspect.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "metadata/mountinfo"), mi, 0600); err != nil {
		t.Fatal(err)
	}
	acquisition := acquire.Plan{Schema: acquire.PlanSchema, ContainerID: target, Inspect: "metadata/inspect.json", Mountinfo: "metadata/mountinfo", Method: "disposable paused Docker fixture exported to a portable working copy", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "capture", Mounts: []acquire.Mount{{ID: entry.ID, Source: "saved-mounts/bound", Complete: true}}}
	acquisitionFile := filepath.Join(root, "acquisition.json")
	encoded, _ := json.Marshal(acquisition)
	if err := os.WriteFile(acquisitionFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	private, public := filepath.Join(root, "private.hex"), filepath.Join(root, "public.hex")
	acquired := filepath.Join(root, "acquired")
	for _, arguments := range [][]string{
		{"keygen", "--private-key", private, "--public-key", public},
		{"acquire-docker", "--source", snapshot, "--plan", acquisitionFile, "--output", acquired, "--sign-key", private},
		{"verify-case", "--case", filepath.Join(acquired, "case"), "--inventory", filepath.Join(acquired, "inventory.json"), "--public-key", public},
	} {
		cmd := exec.CommandContext(ctx, cli, arguments...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("production snapshot importer: %v %s", err, out)
		}
	}
	for _, tc := range []struct {
		path    string
		verdict model.Verdict
	}{{"/opt/unchanged", model.VerdictFromImageLayer}, {"/opt/modified", model.VerdictFromUpperModified}, {"/opt/deleted", model.VerdictDeletedByWhiteout}, {"/opt/bound", model.VerdictShadowedByMount}} {
		cmd := exec.CommandContext(ctx, cli, "explain", tc.path, "--case", filepath.Join(acquired, "case"), "--json", "--strict")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("imported provenance: %v %s", err, out)
		}
		var rep model.Report
		if err := json.Unmarshal(out, &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Runtime != "docker" || rep.Verdict != tc.verdict {
			t.Fatalf("wrong imported result: %+v", rep)
		}
	}
	// Native-marker source and foreign output ownership are exercised under the
	// controlled helper's real filesystem authority. Only this fixture may create
	// a 0:0 whiteout; the product importer must convert it without device I/O.
	nativePlan, _ := json.Marshal(struct {
		UID, GID          int
		Mappings          []mapping
		AliasNames        []string
		Output, AliasRoot string
		Raw               bool
	}{os.Getuid(), os.Getgid(), snapshotMappings, aliasNames, "raw-snapshot", aliasRoot, true})
	if err := os.WriteFile(filepath.Join(capture, "plan.json"), nativePlan, 0644); err != nil {
		t.Fatal(err)
	}
	helperArgs := append([]string(nil), args[:len(args)-3]...)
	rawExportArgs := append(append([]string(nil), helperArgs...), "--cap-add", "MKNOD", image, "/lab", "copy")
	dockerCmd(rawExportArgs...)
	nativeSource := filepath.Join(capture, "raw-snapshot")
	if err := os.Mkdir(filepath.Join(nativeSource, "metadata"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativeSource, "metadata/inspect.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativeSource, "metadata/mountinfo"), mi, 0600); err != nil {
		t.Fatal(err)
	}
	nativeAcquisition := acquisition
	nativeAcquisition.OverlayAttributes = "native"
	nativeAcquisition.Method = "controlled native-marker fixture based on a paused Docker container, not an authenticated storage snapshot"
	data, _ := json.Marshal(nativeAcquisition)
	if err := os.WriteFile(filepath.Join(capture, "native-plan.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(capture, "test-private.hex"), seed, 0600); err != nil {
		t.Fatal(err)
	}
	nativeImportArgs := append(append([]string(nil), helperArgs...), image, "/layerclue", "acquire-docker", "--source", "/capture/raw-snapshot", "--plan", "/capture/native-plan.json", "--output", "/capture/native-acquired", "--sign-key", "/capture/test-private.hex", "--owner", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()))
	dockerCmd(nativeImportArgs...)
	nativeBundle := filepath.Join(capture, "native-acquired")
	for _, arguments := range [][]string{
		{"verify-case", "--case", filepath.Join(nativeBundle, "case"), "--inventory", filepath.Join(nativeBundle, "inventory.json"), "--public-key", public},
		{"explain", "/opt/deleted", "--case", filepath.Join(nativeBundle, "case"), "--strict"},
		{"explain", "/opt/bound", "--case", filepath.Join(nativeBundle, "case"), "--strict"},
	} {
		cmd := exec.CommandContext(ctx, cli, arguments...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native import and ownership: %v %s", err, out)
		}
	}
	t.Log("native trusted-marker import, foreign ownership and unprivileged signed-case verification passed")

	t.Log("production importer: real Docker portable snapshot, signed inventory and imported provenance passed")

	if len(aliasNames) > 0 {
		name := filepath.Join(caseRoot, "docker-links", aliasNames[0])
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../wrong/diff", name); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, cli, "explain", "/opt/unchanged", "--case", caseRoot, "--json", "--strict")
		out, err := cmd.CombinedOutput()
		var rep model.Report
		if decodeErr := json.Unmarshal(out, &rep); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err == nil || !rep.Incomplete || rep.Runtime != "" {
			t.Fatalf("corrupt alias was accepted: %s", out)
		}
	}

	if !t.Failed() {
		t.Log("real Docker overlay2 case passed; imported image and target container are cleaned by exact IDs")
	}
}
