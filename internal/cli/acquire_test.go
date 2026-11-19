package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"github.com/Vivirinter/layerclue/internal/verify"
)

func TestAcquireDockerCLI(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	id := strings.Repeat("c", 64)
	inspect := fmt.Sprintf(`[{"Id":%q,"Image":%q,"Config":{"Image":"synthetic:fixture"},"GraphDriver":{"Name":"overlay2","Data":{"LowerDir":"/host/snapshots/2/fs:/host/snapshots/1/fs","UpperDir":"/host/snapshots/3/fs"}}}]`, id, f.ConfigDigest)
	testfixture.Write(t, filepath.Join(f.Root, "docker.json"), []byte(inspect))
	testfixture.Write(t, filepath.Join(f.Root, "docker-mountinfo"), []byte("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/host/snapshots/2/fs:/host/snapshots/1/fs,upperdir=/host/snapshots/3/fs,userxattr\n"))
	plan := acquire.Plan{Schema: acquire.PlanSchema, ContainerID: id, Inspect: "docker.json", Mountinfo: "docker-mountinfo", Method: "synthetic CLI fixture", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "native"}
	base := t.TempDir()
	name := filepath.Join(base, "plan.json")
	data, _ := json.Marshal(plan)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	priv, pub := filepath.Join(base, "private.hex"), filepath.Join(base, "public.hex")
	if _, code := captureRun(t, []string{"keygen", "--private-key", priv, "--public-key", pub}); code != exitOK {
		t.Fatal(code)
	}
	bundle := filepath.Join(base, "bundle")
	if out, code := captureRun(t,
		[]string{"acquire-docker", "--source", f.Root, "--plan", name, "--output", bundle, "--sign-key", priv},
	); code != exitOK {
		t.Fatalf("acquire: %d %s", code, out)
	}
	if _, code := captureRun(t,
		[]string{"verify-case", "--case", filepath.Join(bundle, "case"), "--inventory", filepath.Join(bundle, "inventory.json"), "--public-key", pub},
	); code != exitOK {
		t.Fatal(code)
	}
	out, code := captureRun(t,
		[]string{"explain", "/opt/tool", "--case", filepath.Join(bundle, "case"), "--json", "--strict"},
	)
	if code != exitOK {
		t.Fatalf("explain: %d %s", code, out)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Runtime != "docker" || rep.ContainerID != id || rep.Verdict != model.VerdictFromImageLayer {
		t.Fatalf("wrong result: %+v", rep)
	}
	if p := verify.Report(&rep); len(p) > 0 {
		t.Fatal(p)
	}
	if _, code := captureRun(t,
		[]string{"acquire-docker", "--source", f.Root, "--plan", name, "--output", bundle},
	); code != exitCase {
		t.Fatal("overwrote existing bundle")
	}
	if _, code := captureRun(t,
		[]string{"acquire-docker", "--source", f.Root, "--plan", name, "--output", filepath.Join(base, "bad"), "--owner", "not-numeric"},
	); code != exitUsage {
		t.Fatal("accepted malformed owner")
	}
}
