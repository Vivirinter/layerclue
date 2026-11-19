package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/analysis"

	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"github.com/Vivirinter/layerclue/internal/verify"
)

func TestDockerMetadataWorkerAndStrictMismatch(t *testing.T) {
	root := demoCase(t)
	id := strings.Repeat("a", 64)
	mi, err := os.ReadFile(filepath.Join(root, "host/proc/1/mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	// Read the fixture's actual captured overlay paths; bind mappings stay explicit.
	c, err := openCase(root)
	if err != nil {
		t.Fatal(err)
	}
	table, err := c.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	mount, ok := c.OverlayMount(table)
	if !ok {
		t.Fatal("missing root")
	}
	inspect := fmt.Sprintf(`[{"Id":%q,"Image":%q,"Config":{"Image":"example:tag","Env":["SECRET=not-for-report"]},"GraphDriver":{"Name":"overlay2","Data":{"LowerDir":%q,"UpperDir":%q}},"Mounts":[]}]`, id, "sha256:"+strings.Repeat("b", 64), strings.Join(mount.LowerDirs(), ":"), mount.SuperValue("upperdir"))
	if err := os.WriteFile(filepath.Join(root, "docker.json"), []byte(inspect), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "case.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["docker_inspect"] = "docker.json"
	manifest["container_id"] = id
	b, _ = json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(root, "case.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"explain", "/usr/bin/helper", "--case", root, "--json", "--strict"})
	if code != exitOK {
		t.Fatalf("Docker explain: %d %s", code, out)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Runtime != "docker" || rep.ContainerID != id || rep.ImageDigest != "" || strings.Contains(out, "not-for-report") {
		t.Fatalf("wrong Docker identity/scope: %s", out)
	}
	if p := verify.Report(&rep); len(p) > 0 {
		t.Fatal(p)
	}
	mi = []byte(strings.Replace(string(mi), mount.SuperValue("upperdir"), "/wrong-upper", 1))
	if err := os.WriteFile(filepath.Join(root, "host/proc/1/mountinfo"), mi, 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := captureRun(t, []string{"explain", "/usr/bin/helper", "--case", root, "--json", "--strict"}); code != exitStrict {
		t.Fatalf("accepted Docker stack mismatch: %d", code)
	}
}
func TestCompareDetectsUnpackedFileMutation(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	args := []string{"compare", "/opt/tool", "--case", f.Root, "--content-root", "oci", "--manifest", f.ManifestDigest, "--json"}
	out, code := captureRun(t, args)
	if code != exitOK {
		t.Fatalf("compare: %d %s", code, out)
	}
	var result analysis.Comparison
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "matching_bytes" {
		t.Fatal(out)
	}
	testfixture.Write(t, filepath.Join(f.Root, "host/snapshots/2/fs/opt/tool"), []byte("tampered unpacked bytes"))
	out, code = captureRun(t, args)
	if code != exitStrict {
		t.Fatalf("missed unpacked mutation: %d %s", code, out)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "different_bytes" || result.Captured.ImageProvenance.Status != "verified_metadata_association" {
		t.Fatal(out)
	}
}
func TestCustodyCLIKeysSealVerifyCollect(t *testing.T) {
	root := demoCase(t)
	out := t.TempDir()
	private, public := filepath.Join(out, "private.hex"), filepath.Join(out, "public.hex")
	if _, code := captureRun(t, []string{"keygen", "--private-key", private, "--public-key", public}); code != exitOK {
		t.Fatalf("keygen: %d", code)
	}
	inventory := filepath.Join(out, "inventory.json")
	if _, code := captureRun(t,
		[]string{"seal", "--case", root, "--output", inventory, "--method", "synthetic test capture", "--sign-key", private},
	); code != exitOK {
		t.Fatalf("seal: %d", code)
	}
	verifyArgs := []string{"verify-case", "--case", root, "--inventory", inventory, "--public-key", public}
	if _, code := captureRun(t, verifyArgs); code != exitOK {
		t.Fatalf("verify-case: %d", code)
	}
	bundle := filepath.Join(out, "bundle")
	if _, code := captureRun(t,
		[]string{"collect", "--case", root, "--output", bundle, "--method", "synthetic test capture", "--sign-key", private},
	); code != exitOK {
		t.Fatalf("collect: %d", code)
	}
	if _, code := captureRun(t,
		[]string{"explain", "/usr/bin/helper", "--case", filepath.Join(bundle, "case"), "--json", "--strict"},
	); code != exitOK {
		t.Fatalf("collected case regression: %d", code)
	}
	testfixture.Write(t, filepath.Join(root, "extra"), []byte("new evidence"))
	if _, code := captureRun(t, verifyArgs); code != exitStrict {
		t.Fatalf("missed extra path: %d", code)
	}
}

func TestPrivateKeyPermissionsAndPhysicalLink(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "private.hex")
	if err := os.WriteFile(name, []byte(strings.Repeat("a", 64)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile(name, true); err == nil {
		t.Fatal("accepted group/other-readable private seed")
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile(name, true); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile(link, true); err == nil {
		t.Fatal("followed key symlink")
	}
	evidence := demoCase(t)
	output := filepath.Join(evidence, "inventory.json")
	if _, code := captureRun(t, []string{"seal", "--case", evidence, "--output", output, "--method", "test"}); code != exitCase {
		t.Fatalf("accepted inventory inside evidence: %d", code)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("in-case output was created")
	}
}
