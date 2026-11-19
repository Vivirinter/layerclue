package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
	bolt "go.etcd.io/bbolt"
)

func TestStrictRejectsUncapturedFileMount(t *testing.T) {
	dir := demoCase(t)
	mi := filepath.Join(dir, "host/proc/1/mountinfo")
	b, err := os.ReadFile(mi)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte("12 11 8:1 /file /usr/bin/helper rw - ext4 /dev/synthetic rw\n")...)
	if err := os.WriteFile(mi, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"explain", "/usr/bin/helper", "--case", dir, "--json", "--strict"})
	if code != exitStrict {
		t.Fatalf("strict exit=%d", code)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Incomplete || rep.Verdict != model.VerdictUnknownInsufficient {
		t.Fatalf("confident missing mount: %+v", rep)
	}
}

func TestVerifyCaseDetectsEvidenceChange(t *testing.T) {
	dir := demoCase(t)
	out, code := captureRun(t, []string{"explain", "/usr/bin/helper", "--case", dir, "--json"})
	if code != exitOK {
		t.Fatalf("explain exit %d", code)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(report, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := captureRun(t, []string{"verify", report, "--case", dir, "--strict"}); code != exitOK {
		t.Fatalf("fresh case exit %d", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "host/var/lib/k8s/vol/bin/helper"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := captureRun(t, []string{"verify", report, "--case", dir}); code != exitStrict {
		t.Fatalf("missed evidence change: exit %d", code)
	}
	if _, code := captureRun(t, []string{"verify", report}); code != exitOK {
		t.Fatalf("checksum-only validation should still pass: %d", code)
	}
}

func TestMetadataWorkerEndToEnd(t *testing.T) {
	dir := demoCase(t)
	meta := filepath.Join(dir, "containerd/meta.db")
	if err := os.MkdirAll(filepath.Dir(meta), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(meta, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		v, err := tx.CreateBucket([]byte("v1"))
		if err != nil {
			return err
		}
		ns, err := v.CreateBucket([]byte("test"))
		if err != nil {
			return err
		}
		cs, err := ns.CreateBucket([]byte("containers"))
		if err != nil {
			return err
		}
		c, err := cs.CreateBucket([]byte("worker-container"))
		if err != nil {
			return err
		}
		return c.Put([]byte("snapshotter"), []byte("overlayfs"))
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, code := captureRun(t, []string{"inspect", "--case", dir})
	if code != exitOK || !strings.Contains(out, "worker-container") || strings.Contains(out, "identity    error") {
		t.Fatalf("worker failed: %d %s", code, out)
	}
}
