package distribution

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
	appversion "github.com/Vivirinter/layerclue/internal/version"
	"golang.org/x/sys/unix"
)

func put(t *testing.T, root, name string, b []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := canonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fakeCandidate(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	root := t.TempDir()
	source := SourceManifest{Schema: "layerclue.source-inputs/v1", Files: map[string]string{}}
	for _, name := range rootFiles {
		source.Files[name] = digest([]byte(name))
	}
	rawSource := encode(t, source)
	put(t, root, "SOURCE_MANIFEST.json", rawSource)
	manifest := Manifest{Schema: ManifestSchema, Version: appversion.Version, SourceManifest: "SOURCE_MANIFEST.json", SourceManifestSHA256: digest(rawSource), SourceArchive: "layerclue_source.tar.gz", Products: []Product{}}
	// Opaque payloads intentionally are NOT tar archives/executables. Verification
	// must hash them without parsing or executing anything supplied by a publisher.
	put(t, root, manifest.SourceArchive, []byte("opaque source payload"))
	for _, arch := range []string{"amd64", "arm64"} {
		target := Target{OS: "linux", Arch: arch}
		p := Product{Target: target, Archive: "layerclue_linux_" + arch + ".tar.gz", BinarySHA256: digest([]byte("binary" + arch)), SBOM: "SBOM_linux_" + arch + ".cdx.json", Provenance: "PROVENANCE_linux_" + arch + ".json"}
		put(t, root, p.Archive, []byte("opaque download payload: never execute"))
		info := BuildInfo{Version: manifest.Version, GoVersion: "go1.27.4", Modules: []Module{{Path: "example.org/library", Version: "v1.0.0", Sum: "h1:module-checksum"}}}
		bom, err := generateBOM(info, target, map[string]string{"go:stdlib": "BSD-3-Clause", "example.org/library": "MIT"})
		if err != nil {
			t.Fatal(err)
		}
		put(t, root, p.SBOM, encode(t, bom))
		prov := Provenance{Schema: ProvenanceSchema, Version: manifest.Version, Target: target, Scope: "test self-report", SourceManifestSHA256: manifest.SourceManifestSHA256, BinarySHA256: p.BinarySHA256, GoVersion: info.GoVersion, BuildSettings: map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch, "-trimpath": "true"}}
		put(t, root, p.Provenance, encode(t, prov))
		manifest.Products = append(manifest.Products, p)
	}
	put(t, root, "release-manifest.json", encode(t, manifest))
	if err := createChecksums(context.Background(), root, key); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestReleaseSignatureExternalTrustAndTamper(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	root := fakeCandidate(t, key)
	result, err := Verify(context.Background(), root, pub)
	if err != nil || !result.Authenticated || result.Files != 9 {
		t.Fatalf("signed verification: %+v %v", result, err)
	}
	result, err = Verify(context.Background(), root, nil)
	if err != nil || result.Authenticated {
		t.Fatalf("integrity-only mode claimed trust: %+v %v", result, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(context.Background(), root, other); err == nil {
		t.Fatal("accepted wrong trust key")
	}
	name := "layerclue_linux_amd64.tar.gz"
	replacement := []byte("attacker payload")
	put(t, root, name, replacement)
	if _, err := Verify(context.Background(), root, pub); err == nil {
		t.Fatal("accepted changed artifact")
	}
	sums, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	var rewritten []string
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		if strings.HasSuffix(line, "  "+name) {
			line = digest(replacement) + "  " + name
		}
		rewritten = append(rewritten, line+"\n")
	}
	put(t, root, "SHA256SUMS", []byte(strings.Join(rewritten, "")))
	if _, err := Verify(context.Background(), root, pub); err == nil {
		t.Fatal("recomputed checksums bypassed the signature")
	}
	if result, err := Verify(context.Background(), root, nil); err != nil || result.Authenticated {
		t.Fatalf("untrusted consistency mode: %+v %v", result, err)
	}
}
func TestReleaseRejectsUnsignedDomainConfusionAndUnsafeFiles(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, mode := range []string{"unsigned", "wrong-domain", "extra-file", "symlink", "fifo", "duplicate-checksum", "signature-duplicate-key"} {
		t.Run(mode, func(t *testing.T) {
			signingKey := key
			if mode == "unsigned" {
				signingKey = nil
			}
			root := fakeCandidate(t, signingKey)
			switch mode {
			case "wrong-domain":
				sums, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
				if err != nil {
					t.Fatal(err)
				}
				sig := Signature{Schema: signatureSchema, Algorithm: "Ed25519", SignedFile: "SHA256SUMS", PublicKeySHA256: digest(pub), Signature: hex.EncodeToString(ed25519.Sign(key, sums))}
				put(t, root, "SHA256SUMS.sig", encode(t, sig))
			case "extra-file":
				put(t, root, "unchecksummed", []byte("extra"))
			case "symlink", "fifo":
				name := filepath.Join(root, "layerclue_linux_amd64.tar.gz")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if mode == "fifo" {
					if err := unix.Mkfifo(name, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					outside := filepath.Join(t.TempDir(), "file")
					if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, name); err != nil {
						t.Fatal(err)
					}
				}
			case "duplicate-checksum":
				raw, _ := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
				lines := strings.Split(string(raw), "\n")
				lines[1] = lines[0]
				put(t, root, "SHA256SUMS", []byte(strings.Join(lines, "\n")))
			case "signature-duplicate-key":
				put(t, root, "SHA256SUMS.sig", []byte(`{"schema":"one","schema":"two"}`))
			}
			if _, err := Verify(context.Background(), root, pub); err == nil {
				t.Fatal("unsafe release accepted")
			}
		})
	}
}
func TestRehashedButContradictoryMetadataFails(t *testing.T) {
	for _, mode := range []string{"target", "sbom-version", "sbom-target", "missing-source", "binary-binding"} {
		t.Run(mode, func(t *testing.T) {
			root := fakeCandidate(t, nil)
			if mode == "target" || mode == "binary-binding" {
				var p Provenance
				raw, _ := os.ReadFile(filepath.Join(root, "PROVENANCE_linux_amd64.json"))
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				if mode == "target" {
					p.Target.Arch = "arm64"
				} else {
					p.BinarySHA256 = strings.Repeat("0", 64)
				}
				put(t, root, "PROVENANCE_linux_amd64.json", encode(t, p))
			}
			if mode == "sbom-version" || mode == "sbom-target" {
				var b BOM
				raw, _ := os.ReadFile(filepath.Join(root, "SBOM_linux_amd64.cdx.json"))
				if err := json.Unmarshal(raw, &b); err != nil {
					t.Fatal(err)
				}
				if mode == "sbom-version" {
					b.Metadata.Component.Version = "9.0.0"
				} else {
					for i := range b.Metadata.Properties {
						if b.Metadata.Properties[i].Name == "layerclue:target" {
							b.Metadata.Properties[i].Value = "wrong/target"
						}
					}
				}
				put(t, root, "SBOM_linux_amd64.cdx.json", encode(t, b))
			}
			if mode == "missing-source" {
				var s SourceManifest
				raw, _ := os.ReadFile(filepath.Join(root, "SOURCE_MANIFEST.json"))
				if err := json.Unmarshal(raw, &s); err != nil {
					t.Fatal(err)
				}
				delete(s.Files, "LICENSE")
				put(t, root, "SOURCE_MANIFEST.json", encode(t, s))
			}
			if err := os.Remove(filepath.Join(root, "SHA256SUMS")); err != nil {
				t.Fatal(err)
			}
			if err := createChecksums(context.Background(), root, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(context.Background(), root, nil); err == nil {
				t.Fatal("metadata contradiction accepted")
			}
		})
	}
}
func sourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range rootFiles {
		put(t, root, name, []byte(name))
	}
	for _, name := range sourceDirs {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	put(t, root, ".gitignore", nil)
	put(t, root, "cmd/program.go", []byte("original source"))
	return root
}
func TestSourceSnapshotIsolationExclusionsAndSymlinks(t *testing.T) {
	root := sourceFixture(t)
	put(t, root, "dist/private.hex", []byte("excluded build output"))
	put(t, root, "examples/private-incident/data", []byte("excluded capture"))
	snapshot, err := Capture(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for name := range snapshot.Data {
		if strings.Contains(name, "private") {
			t.Fatal("captured an excluded directory")
		}
	}
	put(t, root, "cmd/program.go", []byte("changed live tree"))
	copyRoot := t.TempDir()
	if err := snapshot.Materialise(context.Background(), copyRoot); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(copyRoot, "cmd/program.go"))
	if err != nil || string(b) != "original source" {
		t.Fatal("isolated snapshot changed with live source")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("not source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "tools/link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(context.Background(), root); err == nil {
		t.Fatal("followed source symlink")
	}
}
func TestDeterministicArchiveAndPathSafety(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.tgz"), filepath.Join(dir, "b.tgz")
	first := map[string][]byte{"README.md": []byte("docs"), "layerclue": []byte("binary")}
	second := map[string][]byte{"layerclue": []byte("binary"), "README.md": []byte("docs")}
	if err := archiveFiles(context.Background(), first, a, "layerclue"); err != nil {
		t.Fatal(err)
	}
	if err := archiveFiles(context.Background(), second, b, "layerclue"); err != nil {
		t.Fatal(err)
	}
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	if !bytes.Equal(x, y) {
		t.Fatal("archive bytes depend on map order")
	}
	if err := archiveFiles(context.Background(), map[string][]byte{"../outside": nil}, filepath.Join(dir, "bad.tgz"), ""); err == nil {
		t.Fatal("accepted escaping archive path")
	}
	gz, err := gzip.NewReader(bytes.NewReader(x))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	count := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
		expected := int64(0644)
		if header.Name == "layerclue" {
			expected = 0755
		}
		if header.Typeflag != tar.TypeReg || header.Mode != expected || header.Uid != 0 || header.Gid != 0 {
			t.Fatalf("unsafe archive header: %+v", header)
		}
	}
	if count != 2 {
		t.Fatal("missing archive entries")
	}
}
func TestBuildPolicyAndCancellation(t *testing.T) {
	t.Setenv("LAYERCLUE_SECRET_TEST", "not-for-build-children")
	t.Setenv("GOFLAGS", "-ldflags=unsafe")
	env := map[string]string{}
	for _, item := range buildEnvironment("amd64") {
		k, v, _ := strings.Cut(item, "=")
		env[k] = v
	}
	if _, ok := env["LAYERCLUE_SECRET_TEST"]; ok {
		t.Fatal("unrelated secret passed to build subprocess")
	}
	if env["GOFLAGS"] != "" || env["GOWORK"] != "off" || env["CGO_ENABLED"] != "0" {
		t.Fatal("ambient build override accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Build(ctx, BuildOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	root := sourceFixture(t)
	if err := Build(context.Background(), BuildOptions{Root: root, Output: filepath.Join(t.TempDir(), "new"), RequireClean: true}); err == nil {
		t.Fatal("accepted --require-clean without Git")
	}
	if err := allowedOutput(root, filepath.Join(root, "docs/candidate")); err == nil {
		t.Fatal("allowed output inside source inputs")
	}
}
func TestBinaryMetadataPolicy(t *testing.T) {
	info := &debug.BuildInfo{GoVersion: "go1.27.4", Main: debug.Module{Path: "example.org/app", Version: "(devel)"}, Deps: []*debug.Module{{Path: "example.org/lib", Version: "v1.0.0", Sum: "h1:checksum"}}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "-trimpath", Value: "true"}}}
	if _, err := buildInformation(info, appversion.Version, Target{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	info.Deps[0].Replace = &debug.Module{Path: "/private/local"}
	if _, err := buildInformation(info, appversion.Version, Target{OS: "linux", Arch: "amd64"}); err == nil {
		t.Fatal("accepted local dependency replacement")
	}
}
func FuzzValidReleaseVersion(f *testing.F) {
	f.Add(appversion.Version)
	f.Add("1.0.0+build.1")
	f.Add("bad\nversion")
	f.Fuzz(func(t *testing.T, s string) { _ = validVersion(s) })
}

func TestSourceFileByteBudget(t *testing.T) {
	root := sourceFixture(t)
	file, err := os.OpenFile(filepath.Join(root, "README.md"), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((16 << 20) + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err := Capture(context.Background(), root); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("source file budget bypassed: %v", err)
	}
}

func TestRequireCleanBindsCapturedInputsIncludingIgnoredFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git not installed")
	}
	root := sourceFixture(t)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=LayerClue fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Env = gitEnvironment()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, out)
		}
	}
	run("init", "-b", "codex/release-test")
	run("add", ".")
	run("commit", "-qm", "synthetic source fixture")
	ctx := context.Background()
	vcs, err := vcsStatus(ctx, root, true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Capture(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindRevision(ctx, root, snapshot, vcs); err != nil {
		t.Fatal(err)
	}
	put(t, root, ".git/info/exclude", []byte("/tools/ignored.go\n"))
	put(t, root, "tools/ignored.go", []byte("ignored but still a build input"))
	vcs, err = vcsStatus(ctx, root, true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = Capture(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindRevision(ctx, root, snapshot, vcs); err == nil {
		t.Fatal("clean status allowed an ignored uncommitted source input")
	}
	delete(snapshot.Data, "tools/ignored.go")
	snapshot.Data["cmd/program.go"] = []byte("changed captured bytes")
	if err := bindRevision(ctx, root, snapshot, vcs); err == nil {
		t.Fatal("captured bytes were not checked against HEAD")
	}
}
