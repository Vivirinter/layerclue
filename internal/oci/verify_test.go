package oci

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/testfixture"
)

func TestVerifyCompressedAndRawImages(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "gzip"}[compressed], func(t *testing.T) {
			f := testfixture.NewImage(t, t.TempDir(), compressed)
			image, err := Verify(context.Background(), f.Root, f.ContentRoot, f.ManifestDigest, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if len(image.Layers) != 2 || image.ConfigDigest != f.ConfigDigest {
				t.Fatalf("unexpected image: %+v", image)
			}
			for i, layer := range image.Layers {
				if layer.Digest != f.Layers[i].Digest || layer.DiffID != f.Layers[i].DiffID || layer.ChainID != f.Layers[i].ChainID {
					t.Fatalf("layer identities differ: %+v", layer)
				}
				if compressed && layer.Digest == layer.DiffID {
					t.Fatal("confused compressed digest and diffID")
				}
			}
		})
	}
}

func editManifest(t *testing.T, f *testfixture.Image, edit func(map[string]any)) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.Root, f.ContentRoot, "blobs/sha256", f.ManifestDigest[7:]))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	data, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return testfixture.PutBlob(t, f.Root, f.ContentRoot, data)
}

func TestExpandedAndAggregateBudgets(t *testing.T) {
	f := testfixture.NewImage(t, t.TempDir(), true)
	for _, name := range []string{"expanded", "aggregate-expanded", "blob", "aggregate-blob"} {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			switch name {
			case "expanded":
				limits.ExpandedBytes = 1
			case "aggregate-expanded":
				limits.TotalExpandedBytes = int64(len(f.Layers[0].Raw))
			case "blob":
				limits.BlobBytes = 1
			case "aggregate-blob":
				limits.TotalBlobBytes = int64(len(f.Layers[0].Blob))
			}
			if _, err := Verify(context.Background(), f.Root, f.ContentRoot, f.ManifestDigest, limits); !errors.Is(err, evidence.ErrLimit) {
				t.Fatalf("budget not enforced: %v", err)
			}
		})
	}
}

func TestCorruptBlobAndDescriptorSize(t *testing.T) {
	f := testfixture.NewImage(t, t.TempDir(), true)
	digest := editManifest(t, f, func(m map[string]any) { m["layers"].([]any)[0].(map[string]any)["size"] = 1 })
	if _, err := Verify(context.Background(), f.Root, f.ContentRoot, digest, DefaultLimits()); err == nil {
		t.Fatal("accepted incorrect descriptor size")
	}
	blob := append([]byte(nil), f.Layers[0].Blob...)
	blob[len(blob)/2] ^= 0x40
	testfixture.Write(t, filepath.Join(f.Root, f.ContentRoot, "blobs/sha256", f.Layers[0].Digest[7:]), blob)
	if _, err := Verify(context.Background(), f.Root, f.ContentRoot, f.ManifestDigest, DefaultLimits()); err == nil {
		t.Fatal("accepted corrupt compressed layer")
	}
}

func TestWrongDiffIDAndUnsupportedCompression(t *testing.T) {
	f := testfixture.NewImage(t, t.TempDir(), true)
	newConfig := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":["sha256:` + strings.Repeat("0", 64) + `","` + f.Layers[1].DiffID + `"]}}`)
	configDigest := testfixture.PutBlob(t, f.Root, f.ContentRoot, newConfig)
	manifestDigest := editManifest(t, f, func(m map[string]any) {
		c := m["config"].(map[string]any)
		c["digest"] = configDigest
		c["size"] = len(newConfig)
	})
	if _, err := Verify(context.Background(), f.Root, f.ContentRoot, manifestDigest, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "diffID") {
		t.Fatalf("wrong diffID accepted: %v", err)
	}
	manifestDigest = editManifest(t, f, func(m map[string]any) {
		m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.oci.image.layer.v1.tar+zstd"
	})
	if _, err := Verify(context.Background(), f.Root, f.ContentRoot, manifestDigest, DefaultLimits()); err == nil {
		t.Fatal("silently interpreted unsupported compression")
	}
}

func TestBlobPathsAndCancellation(t *testing.T) {
	f := testfixture.NewImage(t, t.TempDir(), true)
	for _, bad := range []string{"sha256:../../outside", strings.Repeat("a", 64), "sha512:" + strings.Repeat("0", 128)} {
		if _, err := Verify(context.Background(), f.Root, f.ContentRoot, bad, DefaultLimits()); err == nil {
			t.Fatal("accepted invalid digest")
		}
	}
	if _, err := Verify(context.Background(), f.Root, "../outside", f.ManifestDigest, DefaultLimits()); err == nil {
		t.Fatal("accepted escaping content root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, f.Root, f.ContentRoot, f.ManifestDigest, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
	name := filepath.Join(f.Root, f.ContentRoot, "blobs/sha256", f.ManifestDigest[7:])
	outside := filepath.Join(t.TempDir(), "manifest")
	if err := os.Rename(name, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, name); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), f.Root, f.ContentRoot, f.ManifestDigest, DefaultLimits()); err == nil {
		t.Fatal("followed an artifact symlink")
	}
}

func FuzzGzipLayer(f *testing.F) {
	var encoded bytes.Buffer
	gz := gzip.NewWriter(&encoded)
	_, _ = gz.Write(bytes.Repeat([]byte("x"), 8192))
	_ = gz.Close()
	f.Add(encoded.Bytes())
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 64<<10 {
			t.Skip()
		}
		root := t.TempDir()
		name := "layer"
		testfixture.Write(t, filepath.Join(root, name), data)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		limits := Limits{BlobBytes: 64 << 10, ExpandedBytes: 4096, TotalBlobBytes: 64 << 10, TotalExpandedBytes: 4096}
		_, _ = verifyLayer(ctx, root, name, descriptor{Digest: testfixture.Sum(data), Size: int64(len(data)), MediaType: GzipType}, testfixture.Sum(nil), limits, 0)
	})
}
