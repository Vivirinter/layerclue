package distribution

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
	appversion "github.com/Vivirinter/layerclue/internal/version"
	"golang.org/x/sys/unix"
)

type BuildOptions struct {
	Root, Output string
	SigningKey   ed25519.PrivateKey
	RequireClean bool
}

type limitedBuffer struct {
	value bytes.Buffer
	max   int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.value.Len() {
		return 0, evidence.ErrLimit
	}
	return b.value.Write(p)
}
func stringTrim(b []byte) string { return strings.TrimSpace(string(b)) }
func goOutput(parent context.Context, dir string, env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	// #nosec G204 -- Trusted developer toolchain; internal build/module commands use separate argv, isolated sources and an allowlisted environment.
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = time.Second
	out := &limitedBuffer{max: 4 << 20}
	errout := &limitedBuffer{max: 16 << 10}
	cmd.Stdout = out
	cmd.Stderr = errout
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("go command failed: %w: %q", err, errout.value.String())
	}
	return out.value.Bytes(), nil
}
func buildEnvironment(arch string) []string {
	override := map[string]string{"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0"}
	var result []string
	allowed := map[string]bool{}
	for _, name := range []string{"PATH", "HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOPROXY", "GOPRIVATE", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "TMPDIR", "LANG", "LC_ALL"} {
		allowed[name] = true
	}
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if _, ok := override[key]; !ok && allowed[key] {
			result = append(result, v)
		}
	}
	keys := make([]string, 0, len(override))
	for k := range override {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result = append(result, k+"="+override[k])
	}
	return result
}
func vcsStatus(ctx context.Context, root string, require bool) (VCS, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); errors.Is(err, os.ErrNotExist) {
		if require {
			return VCS{}, errors.New("--require-clean requires a committed Git checkout")
		}
		return VCS{Status: "unavailable"}, nil
	} else if err != nil {
		return VCS{}, err
	}
	get := func(args ...string) ([]byte, error) { return gitOutput(ctx, root, nil, args...) }
	rev, err := get("rev-parse", "--verify", "HEAD")
	if err != nil {
		if !require && unbornHead(ctx, root) {
			return VCS{Status: "unborn", Dirty: true}, nil
		}
		return VCS{}, errors.New("Git checkout has no readable HEAD")
	}
	dirty, err := get("status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return VCS{}, err
	}
	result := VCS{Status: "observed", Revision: stringTrim(rev), Dirty: len(dirty) > 0}
	if require && result.Dirty {
		return VCS{}, errors.New("--require-clean refuses tracked or untracked changes")
	}
	return result, nil
}
func allowedOutput(root, output string) error {
	rel, err := filepath.Rel(root, output)
	if err != nil {
		return err
	}
	if rel == "." {
		return errors.New("output cannot be the source root")
	}
	for _, prefix := range sourceDirs {
		if rel == prefix || strings.HasPrefix(filepath.ToSlash(rel), prefix+"/") {
			return errors.New("output cannot be inside captured source inputs")
		}
	}
	return nil
}

// Build compiles an isolated, captured source tree. It writes only a new local
// candidate and never publishes, tags or signs with an implicitly selected key.
func Build(ctx context.Context, o BuildOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("release packaging currently requires Linux")
	}
	if ctx == nil {
		return errors.New("build context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(o.SigningKey) != 0 && len(o.SigningKey) != ed25519.PrivateKeySize {
		return errors.New("invalid release signing key")
	}
	root, err := filepath.Abs(o.Root)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(o.Output)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(parent, filepath.Base(output))
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output exists or cannot be checked")
	}
	if err := allowedOutput(root, output); err != nil {
		return err
	}
	vcs, err := vcsStatus(ctx, root, o.RequireClean)
	if err != nil {
		return err
	}
	source, err := Capture(ctx, root)
	if err != nil {
		return err
	}
	if o.RequireClean {
		if err := bindRevision(ctx, root, source, vcs); err != nil {
			return err
		}
		vcs.Status = "verified-inputs"
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".layerclue-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	src := filepath.Join(stage, "source")
	if err := os.Mkdir(src, 0700); err != nil {
		return err
	}
	if err := source.Materialise(ctx, src); err != nil {
		return err
	}
	out := filepath.Join(stage, "candidate")
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	manifestBytes, err := source.ManifestBytes()
	if err != nil {
		return err
	}
	sourceSHA := digest(manifestBytes)
	if err := writeNew(filepath.Join(out, "SOURCE_MANIFEST.json"), manifestBytes); err != nil {
		return err
	}
	manifest := Manifest{Schema: ManifestSchema, Version: appversion.Version, SourceManifest: "SOURCE_MANIFEST.json", SourceManifestSHA256: sourceSHA, SourceArchive: "layerclue_source.tar.gz", Products: []Product{}}
	if err := archiveFiles(ctx, source.Data, filepath.Join(out, manifest.SourceArchive), ""); err != nil {
		return err
	}
	common := map[string][]byte{}
	for name, data := range source.Data {
		if isBundleInput(name) {
			common[name] = data
		}
	}
	inputs := map[string]string{}
	for name, data := range common {
		inputs[name] = digest(data)
	}
	inputBytes, err := canonicalJSON(inputs)
	if err != nil {
		return err
	}
	common["INPUTS.json"] = inputBytes
	common["SOURCE_MANIFEST.json"] = manifestBytes
	for _, arch := range []string{"amd64", "arm64"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		env := buildEnvironment(arch)
		if _, err := goOutput(ctx, src, env, "mod", "verify"); err != nil {
			return err
		}
		target := Target{OS: "linux", Arch: arch}
		bin := filepath.Join(stage, "binary-"+arch)
		args := []string{"build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-o", bin, "./cmd/layerclue"}
		if _, err := goOutput(ctx, src, env, args...); err != nil {
			return err
		}
		info, err := buildinfo.ReadFile(bin)
		if err != nil {
			return err
		}
		metadata, err := buildInformation(info, appversion.Version, target)
		if err != nil {
			return err
		}
		if metadata.MainModule.Path != "github.com/Vivirinter/layerclue" || info.Path != "github.com/Vivirinter/layerclue/cmd/layerclue" {
			return errors.New("unexpected main module or command path")
		}
		ids, err := checkLicenses(ctx, source, metadata, src, env)
		if err != nil {
			return err
		}
		binary, err := evidence.ReadFile(stage, filepath.Base(bin), MaxFileBytes)
		if err != nil {
			return err
		}
		binSHA := digest(binary)
		buildArgs := []string{"go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-o", "layerclue", "./cmd/layerclue"}
		provenance := Provenance{Schema: ProvenanceSchema, Scope: "self-reported isolated-source build metadata; not an independent compiler, source-author or SLSA attestation", Version: appversion.Version, Target: target, SourceManifestSHA256: sourceSHA, BinarySHA256: binSHA, GoVersion: info.GoVersion, BuildArguments: buildArgs, BuildSettings: metadata.Settings, VCS: vcs}
		bom, err := generateBOM(metadata, target, ids)
		if err != nil {
			return err
		}
		bomBytes, err := canonicalJSON(bom)
		if err != nil {
			return err
		}
		provenanceBytes, err := canonicalJSON(provenance)
		if err != nil {
			return err
		}
		buildBytes, err := canonicalJSON(metadata)
		if err != nil {
			return err
		}
		product := Product{Target: target, Archive: "layerclue_linux_" + arch + ".tar.gz", BinarySHA256: binSHA, SBOM: "SBOM_linux_" + arch + ".cdx.json", Provenance: "PROVENANCE_linux_" + arch + ".json"}
		for name, data := range map[string][]byte{product.SBOM: bomBytes, product.Provenance: provenanceBytes} {
			if err := writeNew(filepath.Join(out, name), data); err != nil {
				return err
			}
		}
		files := map[string][]byte{}
		for name, data := range common {
			files[name] = data
		}
		files["layerclue"] = binary
		files["BUILDINFO.json"] = buildBytes
		files["BUILDINFO.txt"] = []byte(info.String())
		files["SBOM.cdx.json"] = bomBytes
		files["PROVENANCE.json"] = provenanceBytes
		if err := archiveFiles(ctx, files, filepath.Join(out, product.Archive), "layerclue"); err != nil {
			return err
		}
		manifest.Products = append(manifest.Products, product)
	}
	manifestData, err := canonicalJSON(manifest)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(out, "release-manifest.json"), manifestData); err != nil {
		return err
	}
	if err := createChecksums(ctx, out, o.SigningKey); err != nil {
		return err
	}
	var pub ed25519.PublicKey
	if len(o.SigningKey) > 0 {
		pub = o.SigningKey.Public().(ed25519.PublicKey)
	}
	if _, err := Verify(ctx, out, pub); err != nil {
		return fmt.Errorf("candidate self-verification: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return unix.Renameat2(unix.AT_FDCWD, out, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE)
}
func isBundleInput(name string) bool {
	for _, root := range append(append([]string(nil), rootFiles...), optionalRootFiles...) {
		if name == root && name != ".gitignore" {
			return true
		}
	}
	return strings.HasPrefix(name, "docs/") || strings.HasPrefix(name, "third_party/licenses/") || strings.HasPrefix(name, "examples/demo/")
}
func archiveFiles(ctx context.Context, files map[string][]byte, dst, executable string) error {
	names := make([]string, 0, len(files))
	for name := range files {
		if !safeRelative(name) {
			return errors.New("invalid archive member address")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	// #nosec G304 -- New archive in the builder-owned private staging directory; destination is not supplied by archive content.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		mode := int64(0644)
		if name == executable {
			mode = 0755
		}
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err := evidence.Copy(ctx, tw, bytes.NewReader(data), max(1, int64(len(data)))); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Sync()
}
