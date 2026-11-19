package distribution

import (
	"errors"
	"fmt"
	"net/url"
	"runtime/debug"
	"sort"
)

const ManifestSchema = "layerclue.release/v1"
const ProvenanceSchema = "layerclue.build-provenance/v1"

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum,omitempty"`
}
type BuildInfo struct {
	Version    string            `json:"version"`
	GoVersion  string            `json:"go_version"`
	MainModule Module            `json:"main_module"`
	Modules    []Module          `json:"modules"`
	Settings   map[string]string `json:"settings"`
}
type VCS struct {
	Status   string `json:"status"`
	Revision string `json:"revision,omitempty"`
	Dirty    bool   `json:"dirty,omitempty"`
}
type Provenance struct {
	Schema               string            `json:"schema"`
	Scope                string            `json:"scope"`
	Version              string            `json:"version"`
	Target               Target            `json:"target"`
	SourceManifestSHA256 string            `json:"source_manifest_sha256"`
	BinarySHA256         string            `json:"binary_sha256"`
	GoVersion            string            `json:"go_version"`
	BuildArguments       []string          `json:"build_arguments"`
	BuildSettings        map[string]string `json:"build_settings"`
	VCS                  VCS               `json:"vcs"`
}
type Product struct {
	Target       Target `json:"target"`
	Archive      string `json:"archive"`
	BinarySHA256 string `json:"binary_sha256"`
	SBOM         string `json:"sbom"`
	Provenance   string `json:"provenance"`
}
type Manifest struct {
	Schema               string    `json:"schema"`
	Version              string    `json:"version"`
	SourceManifest       string    `json:"source_manifest"`
	SourceManifestSHA256 string    `json:"source_manifest_sha256"`
	SourceArchive        string    `json:"source_archive"`
	Products             []Product `json:"products"`
}
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type LicenseID struct {
	ID string `json:"id"`
}
type LicenseChoice struct {
	License LicenseID `json:"license"`
}
type Component struct {
	Type       string          `json:"type"`
	Ref        string          `json:"bom-ref"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	PURL       string          `json:"purl,omitempty"`
	Licenses   []LicenseChoice `json:"licenses"`
	Properties []Property      `json:"properties,omitempty"`
}
type BOMMetadata struct {
	Component  Component  `json:"component"`
	Properties []Property `json:"properties"`
}
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type BOM struct {
	Format       string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	Version      int          `json:"version"`
	Metadata     BOMMetadata  `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

func buildInformation(info *debug.BuildInfo, version string, target Target) (BuildInfo, error) {
	if info == nil || info.GoVersion == "" || info.Main.Path == "" {
		return BuildInfo{}, errors.New("binary lacks Go module build information")
	}
	result := BuildInfo{Version: version, GoVersion: info.GoVersion, MainModule: Module{Path: info.Main.Path, Version: info.Main.Version, Sum: info.Main.Sum}, Settings: map[string]string{}, Modules: []Module{}}
	if info.Main.Replace != nil {
		return BuildInfo{}, errors.New("release main-module replacement is unsupported")
	}
	for _, item := range info.Settings {
		result.Settings[item.Key] = item.Value
	}
	if result.Settings["GOOS"] != target.OS || result.Settings["GOARCH"] != target.Arch || result.Settings["CGO_ENABLED"] != "0" || result.Settings["-trimpath"] != "true" {
		return BuildInfo{}, errors.New("binary target/static/trimpath settings disagree with release policy")
	}
	seen := map[string]bool{}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			return BuildInfo{}, errors.New("release dependency replacements are unsupported")
		}
		if dep.Path == "" || dep.Version == "" || dep.Sum == "" || seen[dep.Path] {
			return BuildInfo{}, errors.New("binary has incomplete/duplicate module identity")
		}
		result.Modules = append(result.Modules, Module{Path: dep.Path, Version: dep.Version, Sum: dep.Sum})
		seen[dep.Path] = true
	}
	sort.Slice(result.Modules, func(i, j int) bool { return result.Modules[i].Path < result.Modules[j].Path })
	return result, nil
}
func licenseChoice(id string) []LicenseChoice { return []LicenseChoice{{License: LicenseID{ID: id}}} }
func generateBOM(info BuildInfo, target Target, licenses map[string]string) (BOM, error) {
	result := BOM{Format: "CycloneDX", SpecVersion: "1.6", Version: 1, Metadata: BOMMetadata{
		Component:  Component{Type: "application", Ref: "layerclue", Name: "LayerClue", Version: info.Version, Licenses: licenseChoice("Apache-2.0")},
		Properties: []Property{{Name: "layerclue:go-version", Value: info.GoVersion}, {Name: "layerclue:target", Value: target.OS + "/" + target.Arch}, {Name: "layerclue:scope", Value: "binary-linked Go modules and aggregate standard library; excludes test/build dependencies and does not model transitive package edges"}},
	}, Components: []Component{}, Dependencies: []Dependency{}}
	stdLicense, ok := licenses["go:stdlib"]
	if !ok {
		return BOM{}, errors.New("missing standard-library licence")
	}
	result.Components = append(result.Components, Component{Type: "library", Ref: "go-stdlib", Name: "Go standard library", Version: info.GoVersion, Licenses: licenseChoice(stdLicense)})
	refs := []string{"go-stdlib"}
	for _, module := range info.Modules {
		id, ok := licenses[module.Path]
		if !ok {
			return BOM{}, fmt.Errorf("missing licence for linked module %q", module.Path)
		}
		ref := "go-module:" + module.Path + "@" + module.Version
		result.Components = append(result.Components, Component{Type: "library", Ref: ref, Name: module.Path, Version: module.Version, PURL: "pkg:golang/" + module.Path + "@" + url.PathEscape(module.Version), Licenses: licenseChoice(id), Properties: []Property{{Name: "go:module:checksum", Value: module.Sum}}})
		refs = append(refs, ref)
	}
	result.Dependencies = append(result.Dependencies, Dependency{Ref: "layerclue", DependsOn: refs})
	return result, nil
}
