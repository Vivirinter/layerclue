package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/testfixture"
	bolt "go.etcd.io/bbolt"
)

func TestIndexReferenceMustBindSelectedPlatformManifest(t *testing.T) {
	for _, mode := range []string{"valid", "missing-member", "wrong-size", "wrong-architecture", "duplicate-member", "corrupt-index"} {
		t.Run(mode, func(t *testing.T) {
			f := testfixture.NewProvenanceCase(t)
			manifest, err := os.ReadFile(filepath.Join(f.Root, "oci/blobs/sha256", f.ManifestDigest[7:]))
			if err != nil {
				t.Fatal(err)
			}
			desc := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": f.ManifestDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}
			entries := []any{desc}
			switch mode {
			case "missing-member":
				desc["digest"] = testfixture.Sum([]byte("other"))
			case "wrong-size":
				desc["size"] = len(manifest) + 1
			case "wrong-architecture":
				desc["platform"] = map[string]any{"os": "linux", "architecture": "arm64"}
			case "duplicate-member":
				entries = append(entries, desc)
			}
			data, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries})
			if err != nil {
				t.Fatal(err)
			}
			indexDigest := testfixture.PutBlob(t, f.Root, "oci", data)
			testfixture.DB(t, filepath.Join(f.Root, "containerd/meta.db"), func(tx *bolt.Tx) error {
				b, err := testfixture.Bucket(tx, "v1", "k8s.io", "images", "demo:latest", "target")
				if err != nil {
					return err
				}
				return b.Put([]byte("digest"), []byte(indexDigest))
			})
			if mode == "corrupt-index" {
				testfixture.Write(t, filepath.Join(f.Root, "oci/blobs/sha256", indexDigest[7:]), []byte("changed index"))
			}
			rep, code := explainProof(t, f.Root)
			if mode == "valid" {
				if code != exitOK || rep.ImageProvenance.ReferenceKind != "index_member" || rep.ImageProvenance.ReferenceDigest != indexDigest {
					t.Fatalf("valid index rejected: %d %+v", code, rep.Missing)
				}
			} else if code != exitStrict || rep.ImageProvenance.Status != "unverified" || rep.Visible.LayerDigest != "" {
				t.Fatalf("invalid index accepted: %d %+v", code, rep)
			}
		})
	}
}
