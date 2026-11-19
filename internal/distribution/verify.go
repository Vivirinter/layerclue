package distribution

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

const signatureSchema = "layerclue.release-signature/v1"
const signatureDomain = "layerclue.release/v1\n"

type Signature struct {
	Schema          string `json:"schema"`
	Algorithm       string `json:"algorithm"`
	SignedFile      string `json:"signed_file"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	Signature       string `json:"signature"`
}
type Result struct {
	Version          string `json:"version"`
	Authenticated    bool   `json:"authenticated"`
	SignaturePresent bool   `json:"signature_present"`
	Files            int    `json:"files_checked"`
	Scope            string `json:"scope"`
}

func artifactNames() []string {
	result := []string{"SOURCE_MANIFEST.json", "release-manifest.json", "layerclue_source.tar.gz"}
	for _, arch := range []string{"amd64", "arm64"} {
		result = append(result, "layerclue_linux_"+arch+".tar.gz", "SBOM_linux_"+arch+".cdx.json", "PROVENANCE_linux_"+arch+".json")
	}
	sort.Strings(result)
	return result
}
func validHash(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func validVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	plus := strings.Split(s, "+")
	if len(plus) > 2 {
		return false
	}
	if len(plus) == 2 && !identifiers(plus[1], false) {
		return false
	}
	core, pre, hasPre := strings.Cut(plus[0], "-")
	if hasPre && !identifiers(pre, true) {
		return false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 1 && p[0] == '0' {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
func identifiers(s string, noLeadingZeros bool) bool {
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		numeric := true
		for _, c := range part {
			if c < '0' || c > '9' {
				numeric = false
			}
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
		}
		if noLeadingZeros && numeric && len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}
func directoryNames(root string) ([]string, error) {
	dir, err := evidence.OpenDir(root, ".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(33)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(names) > 32 {
		return nil, evidence.ErrLimit
	}
	sort.Strings(names)
	return names, nil
}
func fileDigest(ctx context.Context, root, name string, max int64) (string, int64, error) {
	f, err := evidence.OpenRegular(root, name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if before.Size() > max {
		return "", 0, evidence.ErrLimit
	}
	h := sha256.New()
	n, err := evidence.Copy(ctx, h, f, max)
	if err != nil {
		return "", 0, err
	}
	after, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if before.Size() != n || after.Size() != n || before.ModTime() != after.ModTime() {
		return "", 0, errors.New("release artifact changed during hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func createChecksums(ctx context.Context, root string, key ed25519.PrivateKey) error {
	var lines []string
	for _, name := range artifactNames() {
		h, _, err := fileDigest(ctx, root, name, MaxFileBytes)
		if err != nil {
			return err
		}
		lines = append(lines, h+"  "+name+"\n")
	}
	data := []byte(strings.Join(lines, ""))
	if err := writeNew(filepath.Join(root, "SHA256SUMS"), data); err != nil {
		return err
	}
	if len(key) == 0 {
		return nil
	}
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid release signing key")
	}
	pub := key.Public().(ed25519.PublicKey)
	signature := Signature{Schema: signatureSchema, Algorithm: "Ed25519", SignedFile: "SHA256SUMS", PublicKeySHA256: digest(pub), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(signatureDomain), data...)))}
	encoded, err := canonicalJSON(signature)
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(root, "SHA256SUMS.sig"), encoded)
}
func readChecked(root, name, expected string, max int64) ([]byte, error) {
	b, err := evidence.ReadFile(root, name, max)
	if err != nil {
		return nil, err
	}
	if digest(b) != expected {
		return nil, fmt.Errorf("checksum mismatch: %s", name)
	}
	return b, nil
}

// Verify reads regular top-level artifacts only. It never extracts archives,
// parses executables or executes downloaded code. Metadata/source claims remain
// publisher claims; the optional external key authenticates the checked files.
func Verify(ctx context.Context, root string, key ed25519.PublicKey) (*Result, error) {
	if ctx == nil {
		return nil, errors.New("verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) != 0 && len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid trusted public key")
	}
	names, err := directoryNames(root)
	if err != nil {
		return nil, err
	}
	sums, err := evidence.ReadFile(root, "SHA256SUMS", 16<<10)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(string(sums), "\n") {
		return nil, errors.New("checksum file must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n")
	expectedNames := artifactNames()
	if len(lines) != len(expectedNames) {
		return nil, errors.New("unexpected checksum file count")
	}
	hashes := map[string]string{}
	for i, line := range lines {
		if len(line) < 67 || line[64:66] != "  " || !validHash(line[:64]) || line[66:] != expectedNames[i] {
			return nil, errors.New("checksum file has invalid, duplicate or unexpected artifact names/order")
		}
		hashes[line[66:]] = line[:64]
	}
	hasSig := false
	for _, name := range names {
		if name == "SHA256SUMS.sig" {
			hasSig = true
		}
	}
	expectedSet := append(append([]string(nil), expectedNames...), "SHA256SUMS")
	if hasSig {
		expectedSet = append(expectedSet, "SHA256SUMS.sig")
	}
	sort.Strings(expectedSet)
	if strings.Join(names, "\x00") != strings.Join(expectedSet, "\x00") {
		return nil, errors.New("release directory contains missing or unchecksummed files")
	}
	result := &Result{SignaturePresent: hasSig, Files: len(hashes), Scope: "checked top-level file bytes, metadata bindings and optional external-key signature; archives/executables are not opened and build/source/publisher claims are not independently attested"}
	if hasSig {
		raw, err := evidence.ReadFile(root, "SHA256SUMS.sig", 4096)
		if err != nil {
			return nil, err
		}
		var sig Signature
		if err := evidence.DecodeJSON(raw, &sig); err != nil {
			return nil, err
		}
		signature, err := hex.DecodeString(sig.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || sig.Schema != signatureSchema || sig.Algorithm != "Ed25519" || sig.SignedFile != "SHA256SUMS" || !validHash(sig.PublicKeySHA256) {
			return nil, errors.New("invalid release signature envelope")
		}
		if len(key) > 0 {
			if digest(key) != sig.PublicKeySHA256 || !ed25519.Verify(key, append([]byte(signatureDomain), sums...), signature) {
				return nil, errors.New("release signature does not match the external trusted key")
			}
			result.Authenticated = true
		}
	} else if len(key) > 0 {
		return nil, errors.New("release is unsigned but a trusted signature is required")
	}
	var total int64
	for _, name := range expectedNames {
		h, n, err := fileDigest(ctx, root, name, min(MaxFileBytes, MaxReleaseBytes-total))
		if err != nil {
			return nil, err
		}
		total += n
		if h != hashes[name] {
			return nil, fmt.Errorf("checksum mismatch: %s", name)
		}
	}
	checked := func(name string, dst any, max int64) error {
		data, err := readChecked(root, name, hashes[name], max)
		if err != nil {
			return err
		}
		return evidence.DecodeJSON(data, dst)
	}
	var m Manifest
	if err := checked("release-manifest.json", &m, 1<<20); err != nil {
		return nil, err
	}
	if m.Schema != ManifestSchema || !validVersion(m.Version) || m.SourceManifest != "SOURCE_MANIFEST.json" || m.SourceArchive != "layerclue_source.tar.gz" || m.SourceManifestSHA256 != hashes[m.SourceManifest] || len(m.Products) != 2 {
		return nil, errors.New("invalid release manifest")
	}
	var source SourceManifest
	if err := checked(m.SourceManifest, &source, 16<<20); err != nil {
		return nil, err
	}
	if source.Schema != "layerclue.source-inputs/v1" || len(source.Files) == 0 || len(source.Files) > 10000 {
		return nil, errors.New("invalid source manifest")
	}
	for name, h := range source.Files {
		if !safeRelative(name) || !utf8.ValidString(name) || len(name) > 4096 || !validHash(h) {
			return nil, errors.New("invalid source manifest path/hash")
		}
	}
	for _, name := range rootFiles {
		if _, ok := source.Files[name]; !ok {
			return nil, errors.New("source manifest omits a required project input")
		}
	}
	for i, arch := range []string{"amd64", "arm64"} {
		p := m.Products[i]
		if p.Target.OS != "linux" || p.Target.Arch != arch || p.Archive != "layerclue_linux_"+arch+".tar.gz" || p.SBOM != "SBOM_linux_"+arch+".cdx.json" || p.Provenance != "PROVENANCE_linux_"+arch+".json" || !validHash(p.BinarySHA256) {
			return nil, errors.New("invalid product manifest")
		}
		var prov Provenance
		if err := checked(p.Provenance, &prov, 1<<20); err != nil {
			return nil, err
		}
		if prov.Schema != ProvenanceSchema || prov.Version != m.Version || prov.Target != p.Target || prov.SourceManifestSHA256 != m.SourceManifestSHA256 || prov.BinarySHA256 != p.BinarySHA256 || prov.GoVersion == "" || prov.Scope == "" || prov.BuildSettings["CGO_ENABLED"] != "0" || prov.BuildSettings["GOARCH"] != arch || prov.BuildSettings["GOOS"] != "linux" || prov.BuildSettings["-trimpath"] != "true" {
			return nil, errors.New("provenance contradicts release manifest")
		}
		var bom BOM
		if err := checked(p.SBOM, &bom, 1<<20); err != nil {
			return nil, err
		}
		if err := checkBOM(bom, m.Version, prov.GoVersion, p.Target); err != nil {
			return nil, err
		}
	}
	after, err := directoryNames(root)
	if err != nil {
		return nil, err
	}
	if strings.Join(after, "\x00") != strings.Join(names, "\x00") {
		return nil, errors.New("release directory changed during verification")
	}
	result.Version = m.Version
	return result, nil
}
func checkBOM(b BOM, version, goVersion string, target Target) error {
	if b.Format != "CycloneDX" || b.SpecVersion != "1.6" || b.Version != 1 || b.Metadata.Component.Name != "LayerClue" || b.Metadata.Component.Version != version || b.Metadata.Component.Type != "application" || b.Metadata.Component.Ref != "layerclue" || len(b.Components) > 256 || len(b.Components) == 0 || len(b.Dependencies) != 1 {
		return errors.New("invalid binary SBOM header")
	}
	if len(b.Metadata.Component.Licenses) != 1 || b.Metadata.Component.Licenses[0].License.ID != "Apache-2.0" {
		return errors.New("invalid project licence in SBOM")
	}
	props := map[string]string{}
	for _, p := range b.Metadata.Properties {
		if p.Name == "" || props[p.Name] != "" || len(p.Value) > 1024 {
			return errors.New("invalid/duplicate SBOM metadata property")
		}
		props[p.Name] = p.Value
	}
	if props["layerclue:go-version"] != goVersion || props["layerclue:target"] != target.OS+"/"+target.Arch || props["layerclue:scope"] == "" {
		return errors.New("SBOM target/toolchain metadata mismatch")
	}
	refs := map[string]bool{"layerclue": true}
	std := false
	for _, c := range b.Components {
		if c.Ref == "" || refs[c.Ref] || c.Type != "library" || c.Name == "" || c.Version == "" || len(c.Licenses) != 1 || c.Licenses[0].License.ID == "" {
			return errors.New("invalid/duplicate SBOM component")
		}
		refs[c.Ref] = true
		if c.Ref == "go-stdlib" {
			if c.Version != goVersion {
				return errors.New("SBOM toolchain version mismatch")
			}
			std = true
		}
	}
	if !std || b.Dependencies[0].Ref != "layerclue" || len(b.Dependencies[0].DependsOn) != len(b.Components) {
		return errors.New("incomplete SBOM component references")
	}
	seen := map[string]bool{}
	for _, ref := range b.Dependencies[0].DependsOn {
		if ref == "layerclue" || !refs[ref] || seen[ref] {
			return errors.New("invalid SBOM dependency reference")
		}
		seen[ref] = true
	}
	return nil
}
