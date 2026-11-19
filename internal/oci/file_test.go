package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/testfixture"
)

type tarEntry struct {
	name, body, link string
	kind             byte
}

func archive(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		typ := e.kind
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(e.body))
		if typ != tar.TypeReg {
			size = 0
		}
		if err := w.WriteHeader(&tar.Header{Name: e.name, Linkname: e.link, Typeflag: typ, Size: size, Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func customImage(t *testing.T, compressed bool, layers ...[]byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	var desc []map[string]any
	var diffs []string
	for _, raw := range layers {
		blob := raw
		media := TarType
		if compressed {
			var out bytes.Buffer
			w := gzip.NewWriter(&out)
			if _, err := w.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			blob = out.Bytes()
			media = GzipType
		}
		digest := testfixture.PutBlob(t, root, "oci", blob)
		diffs = append(diffs, testfixture.Sum(raw))
		desc = append(desc, map[string]any{"mediaType": media, "digest": digest, "size": len(blob)})
	}
	config, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}})
	cd := testfixture.PutBlob(t, root, "oci", config)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ManifestType, "config": map[string]any{"mediaType": ConfigType, "digest": cd, "size": len(config)}, "layers": desc})
	return root, testfixture.PutBlob(t, root, "oci", manifest)
}
func TestSelectFileMergedLayers(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "tar", true: "gzip"}[compressed], func(t *testing.T) {
			root, digest := customImage(t, compressed,
				archive(t, tarEntry{name: "same", body: "original"}, tarEntry{name: "deleted", body: "old"}, tarEntry{name: "d/old", body: "old"}, tarEntry{name: "dir/nested", kind: tar.TypeDir}, tarEntry{name: "dir/value", body: "right"}, tarEntry{name: "value", body: "wrong"}, tarEntry{name: "jump", kind: tar.TypeSymlink, link: "dir/nested"}),
				archive(t, tarEntry{name: "same", body: "new"}, tarEntry{name: ".wh.deleted"}, tarEntry{name: "d/new", body: "new directory"}, tarEntry{name: "d/.wh..wh..opq"}, tarEntry{name: "hard", kind: tar.TypeLink, link: "same"}),
			)
			for _, tc := range []struct{ path, body, status string }{{"/same", "new", "present"}, {"/deleted", "", "absent"}, {"/d/old", "", "absent"}, {"/d/new", "new directory", "present"}, {"/jump/../value", "right", "present"}, {"/missing", "", "absent"}} {
				got, err := SelectFile(context.Background(), root, "oci", digest, tc.path, DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				if got.Status != tc.status {
					t.Fatalf("%s: %+v", tc.path, got)
				}
				if tc.status == "present" && got.SHA256 != strings.TrimPrefix(testfixture.Sum([]byte(tc.body)), "sha256:") {
					t.Fatalf("%s: wrong hash: %+v", tc.path, got)
				}
			}
			if _, err := SelectFile(context.Background(), root, "oci", digest, "/hard", DefaultLimits()); !errors.Is(err, ErrUnsupportedPath) {
				t.Fatalf("hardlink must fail closed: %v", err)
			}
		})
	}
}
func TestWhiteoutOnlyAffectsInheritedEntries(t *testing.T) {
	root, digest := customImage(t, false, archive(t, tarEntry{name: "x", body: "old"}, tarEntry{name: "old/child", body: "old"}), archive(t, tarEntry{name: "x", body: "replacement"}, tarEntry{name: ".wh.x"}, tarEntry{name: "old", body: "now regular"}))
	got, err := SelectFile(context.Background(), root, "oci", digest, "/x", DefaultLimits())
	if err != nil || got == nil || got.SHA256 != strings.TrimPrefix(testfixture.Sum([]byte("replacement")), "sha256:") {
		t.Fatalf("whiteout incorrectly removed same-layer entry: %+v %v", got, err)
	}
	if _, err := SelectFile(context.Background(), root, "oci", digest, "/old/child", DefaultLimits()); err == nil {
		t.Fatal("traversed replaced regular parent")
	}
}
func TestSelectRejectsAmbiguousOrUnsafeTar(t *testing.T) {
	for _, tc := range []string{"duplicate", "traversal", "absolute", "non-directory-parent", "padding", "invalid-whiteout", "symlink-loop"} {
		t.Run(tc, func(t *testing.T) {
			var raw []byte
			target := "/tool"
			switch tc {
			case "duplicate":
				raw = archive(t, tarEntry{name: "tool", body: "a"}, tarEntry{name: "./tool", body: "b"})
			case "traversal":
				raw = archive(t, tarEntry{name: "../tool", body: "x"})
			case "absolute":
				raw = archive(t, tarEntry{name: "/tool", body: "x"})
			case "non-directory-parent":
				raw = archive(t, tarEntry{name: "x", body: "file"}, tarEntry{name: "x/tool", body: "x"})
			case "padding":
				raw = append(archive(t, tarEntry{name: "tool", body: "x"}), []byte("another archive")...)
			case "invalid-whiteout":
				raw = archive(t, tarEntry{name: ".wh.tool", body: "not empty"})
			case "symlink-loop":
				raw = archive(t, tarEntry{name: "tool", kind: tar.TypeSymlink, link: "tool"})
			}
			root, digest := customImage(t, false, raw)
			if _, err := SelectFile(context.Background(), root, "oci", digest, target, DefaultLimits()); err == nil {
				t.Fatal("accepted ambiguous/unsafe tar")
			}
		})
	}
}
func TestTarInterpretationRechecksDigest(t *testing.T) {
	root, digest := customImage(t, false, archive(t, tarEntry{name: "tool", body: "old"}))
	image, err := Verify(context.Background(), root, "oci", digest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	layer := image.Layers[0]
	changed := archive(t, tarEntry{name: "tool", body: "new"})
	if err := os.WriteFile(filepath.Join(root, layer.Artifact), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readChanges(context.Background(), root, layer, DefaultLimits(), 0); err == nil {
		t.Fatal("trusted earlier verification after changing parsed bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := apply(ctx, map[string]node{"x": {kind: "file"}}, &changes{nodes: map[string]node{}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("apply cancellation: %v", err)
	}
}
func FuzzTarChanges(f *testing.F) {
	// Fuzz a raw serialized layer under budgets, never extract to the filesystem.
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	_ = w.WriteHeader(&tar.Header{Name: "tool", Size: 1, Mode: 0600})
	_, _ = w.Write([]byte("x"))
	_ = w.Close()
	f.Add(b.Bytes())
	f.Add([]byte("not tar"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 || len(raw) > 64<<10 {
			return
		}
		root := t.TempDir()
		testfixture.Write(t, filepath.Join(root, "blob"), raw)
		hash := testfixture.Sum(raw)
		layer := Layer{MediaType: TarType, Artifact: "blob", Digest: hash, DiffID: hash, Size: int64(len(raw)), ExpandedSize: int64(len(raw))}
		limits := Limits{BlobBytes: 64 << 10, ExpandedBytes: 1 << 20, TotalBlobBytes: 64 << 10, TotalExpandedBytes: 1 << 20}
		c, err := readChanges(context.Background(), root, layer, limits, 0)
		if err == nil {
			err = apply(context.Background(), map[string]node{"": {kind: "directory"}}, c)
		}
		if errors.Is(err, evidence.ErrLimit) {
			return
		}
	})
}

func TestOpaqueMarkerCreatesMissingDirectory(t *testing.T) {
	root, digest := customImage(t, false, archive(t, tarEntry{name: "empty/.wh..wh..opq"}))
	got, err := SelectFile(context.Background(), root, "oci", digest, "/empty", DefaultLimits())
	if err != nil || got == nil || got.Status != "present" || got.Kind != "directory" {
		t.Fatalf("missing opaque parent: %+v %v", got, err)
	}
}

func TestPAXSparseFileFailsClosed(t *testing.T) {
	// Writer intentionally filters GNU.sparse keys. Emit equal-length vendor
	// placeholders, then change only the PAX payload; header sizes/checksums stay
	// valid. The reader recognises a one-byte extent in a four-byte sparse file.
	var encoded bytes.Buffer
	w := tar.NewWriter(&encoded)
	h := &tar.Header{Name: "tool", Typeflag: tar.TypeReg, Size: 1, Mode: 0600, PAXRecords: map[string]string{
		"FOO.sparse.major": "0", "FOO.sparse.minor": "1", "FOO.sparse.numblocks": "1", "FOO.sparse.map": "0,1", "FOO.sparse.size": "4",
	}}
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := bytes.ReplaceAll(encoded.Bytes(), []byte("FOO.sparse."), []byte("GNU.sparse."))
	// Confirm that this is recognised sparse metadata, not just malformed tar.
	reader := tar.NewReader(bytes.NewReader(raw))
	parsed, err := reader.Next()
	if err != nil || parsed.Size != 4 || parsed.PAXRecords["GNU.sparse.map"] != "0,1" {
		t.Fatalf("invalid sparse fixture: %+v %v", parsed, err)
	}
	root, digest := customImage(t, false, raw)
	if _, err := SelectFile(context.Background(), root, "oci", digest, "/tool", DefaultLimits()); !errors.Is(err, ErrUnsupportedPath) {
		t.Fatalf("sparse semantics were not refused: %v", err)
	}
}
