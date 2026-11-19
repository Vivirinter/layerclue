package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/testfixture"
	"github.com/Vivirinter/layerclue/internal/verify"
	bolt "go.etcd.io/bbolt"
)

func explainProof(t *testing.T, dir string) (*model.Report, int) {
	t.Helper()
	out, code := captureRun(t, []string{"explain", "/opt/tool", "--case", dir, "--json", "--strict"})
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid report (exit %d): %v %s", code, err, out)
	}
	return &rep, code
}

func TestImageProvenanceEndToEnd(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	rep, code := explainProof(t, f.Root)
	if code != exitOK {
		t.Fatalf("proof failed: %d %+v", code, rep.Missing)
	}
	if rep.ImageProvenance == nil || rep.ImageProvenance.Status != "verified_metadata_association" {
		t.Fatalf("missing verified association: %+v", rep.ImageProvenance)
	}
	if len(rep.ImageProvenance.Layers) != 2 || rep.ImageProvenance.Layers[1].SnapshotID != "2" || rep.Visible.LayerDigest != f.Layers[1].Digest || rep.Visible.LayerAssociation != "captured_metadata" {
		t.Fatalf("incorrect layer binding: %+v", rep)
	}
	if problems := verify.Report(rep); len(problems) > 0 {
		t.Fatalf("generated proof does not verify: %v", problems)
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	writeReport(t, reportPath, rep)
	if _, code := captureRun(t, []string{"verify", reportPath, "--case", f.Root, "--strict"}); code != exitOK {
		t.Fatalf("proof replay exit %d", code)
	}
	corrupt := append([]byte(nil), f.Layers[0].Blob...)
	corrupt[0] ^= 1
	testfixture.Write(t, filepath.Join(f.Root, "oci/blobs/sha256", f.Layers[0].Digest[7:]), corrupt)
	if _, code := captureRun(t, []string{"verify", reportPath, "--case", f.Root}); code != exitStrict {
		t.Fatalf("image tampering missed: %d", code)
	}
	failed, code := explainProof(t, f.Root)
	if code != exitStrict || failed.ImageProvenance.Status != "unverified" || failed.Visible.LayerDigest != "" {
		t.Fatalf("partial proof leaked layer digest: %d %+v", code, failed)
	}
}

func TestSnapshotGraphsMustAgree(t *testing.T) {
	for _, mode := range []string{"logical-cycle", "storage-parent", "invalid-id", "invalid-kind", "wrong-path", "different-reference"} {
		t.Run(mode, func(t *testing.T) {
			f := testfixture.NewProvenanceCase(t)
			switch mode {
			case "different-reference":
				testfixture.DB(t, filepath.Join(f.Root, "containerd/meta.db"), func(tx *bolt.Tx) error {
					b, err := testfixture.Bucket(tx, "v1", "k8s.io", "images", "demo:latest", "target")
					if err != nil {
						return err
					}
					return b.Put([]byte("digest"), []byte(testfixture.Sum([]byte("another manifest"))))
				})
			case "logical-cycle":
				testfixture.DB(t, filepath.Join(f.Root, "containerd/meta.db"), func(tx *bolt.Tx) error {
					b, err := testfixture.Bucket(tx, "v1", "k8s.io", "snapshots", "overlayfs", "ctr")
					if err != nil {
						return err
					}
					return b.Put([]byte("parent"), []byte("ctr"))
				})
			case "storage-parent", "invalid-id", "invalid-kind":
				testfixture.DB(t, filepath.Join(f.Root, "snapshotter/metadata.db"), func(tx *bolt.Tx) error {
					b, err := testfixture.Bucket(tx, "v1", "snapshots", "k8s.io/2/backend")
					if err != nil {
						return err
					}
					switch mode {
					case "storage-parent":
						return b.Put([]byte("parent"), []byte("missing-backend"))
					case "invalid-id":
						return b.Put([]byte("id"), []byte{0x81, 0})
					default:
						return b.Put([]byte("kind"), []byte{0})
					}
				})
			case "wrong-path":
				name := filepath.Join(f.Root, "mountinfo")
				data, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				testfixture.Write(t, name, []byte(strings.ReplaceAll(string(data), "/snapshots/2/fs:/snapshots/1/fs", "/snapshots/1/fs:/snapshots/2/fs")))
			}
			rep, code := explainProof(t, f.Root)
			if code != exitStrict || rep.ImageProvenance == nil || rep.ImageProvenance.Status != "unverified" {
				t.Fatalf("invalid chain accepted: %d %+v", code, rep)
			}
			if rep.Visible != nil && rep.Visible.LayerDigest != "" {
				t.Fatal("associated layer before the complete proof succeeded")
			}
		})
	}
}

func TestReadOnlySnapshotViewAssociation(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	name := filepath.Join(f.Root, "mountinfo")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	testfixture.Write(t, name, []byte(strings.ReplaceAll(string(data), ",upperdir=/snapshots/3/fs,workdir=/snapshots/3/work", "")))
	testfixture.DB(t, filepath.Join(f.Root, "snapshotter/metadata.db"), func(tx *bolt.Tx) error {
		b, err := testfixture.Bucket(tx, "v1", "snapshots", "k8s.io/3/backend")
		if err != nil {
			return err
		}
		return b.Put([]byte("kind"), []byte{1})
	})
	rep, code := explainProof(t, f.Root)
	if code != exitOK || rep.ImageProvenance.Status != "verified_metadata_association" || rep.Visible.LayerDigest != f.Layers[1].Digest {
		t.Fatalf("read-only view rejected: %d %+v", code, rep.Missing)
	}
}

func TestImageProofStructureRejectsRelabelledLocation(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	rep, code := explainProof(t, f.Root)
	if code != exitOK {
		t.Fatal(rep.Missing)
	}
	rep.Visible.LayerDigest = f.Layers[0].Digest
	if err := rep.Seal(); err != nil {
		t.Fatal(err)
	}
	if problems := verify.Report(rep); len(problems) == 0 {
		t.Fatal("checksum disguised a mismatched layer association")
	}
}

func TestMetadataAssociationDoesNotCertifyUnpackedBytes(t *testing.T) {
	f := testfixture.NewProvenanceCase(t)
	testfixture.Write(t, filepath.Join(f.Root, "host/snapshots/2/fs/opt/tool"), []byte("modified unpacked bytes"))
	rep, code := explainProof(t, f.Root)
	if code != exitOK || rep.ImageProvenance.Status != "verified_metadata_association" || rep.Visible.LayerAssociation != "captured_metadata" {
		t.Fatalf("incorrect scope: %d %+v", code, rep)
	}
	if !strings.Contains(rep.ImageProvenance.Scope, "unpacked file equivalence") {
		t.Fatal("missing distinction between metadata and file equivalence")
	}
	if rep.Visible.SHA256 != strings.TrimPrefix(testfixture.Sum([]byte("modified unpacked bytes")), "sha256:") {
		t.Fatal("hid modified snapshot bytes")
	}
}
