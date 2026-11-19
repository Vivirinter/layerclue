package distribution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

type licenseFile struct {
	Path         string `json:"path"`
	OriginalName string `json:"original_name"`
	SHA256       string `json:"sha256"`
}
type licenseComponent struct {
	Module  string        `json:"module"`
	Version string        `json:"version"`
	License string        `json:"license"`
	Files   []licenseFile `json:"files"`
}
type licenseManifest struct {
	Schema     string             `json:"schema"`
	Components []licenseComponent `json:"components"`
}
type moduleLocation struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

func checkLicenses(ctx context.Context, source *Snapshot, info BuildInfo, dir string, env []string) (map[string]string, error) {
	raw, ok := source.Data["third_party/licenses/manifest.json"]
	if !ok {
		return nil, errors.New("missing third-party licence manifest")
	}
	var list licenseManifest
	if err := evidence.DecodeJSON(raw, &list); err != nil {
		return nil, err
	}
	if list.Schema != "layerclue.third-party/v1" || len(list.Components) > 256 {
		return nil, errors.New("invalid licence manifest")
	}
	known := map[string]licenseComponent{}
	for _, item := range list.Components {
		if item.Module == "" || known[item.Module].Module != "" || len(item.Files) == 0 || len(item.Files) > 16 {
			return nil, errors.New("invalid/duplicate licence component")
		}
		if item.License != "MIT" && item.License != "BSD-3-Clause" && item.License != "Apache-2.0" {
			return nil, errors.New("unsupported licence identifier in release policy")
		}
		for _, file := range item.Files {
			if !safeRelative(file.Path) || filepath.Base(file.OriginalName) != file.OriginalName || file.OriginalName == "." {
				return nil, errors.New("invalid licence file path")
			}
			data, ok := source.Data[file.Path]
			if !ok || digest(data) != file.SHA256 {
				return nil, errors.New("copied licence text does not match its recorded checksum")
			}
		}
		known[item.Module] = item
	}
	goroot, err := goOutput(ctx, dir, env, "env", "GOROOT")
	if err != nil {
		return nil, err
	}
	roots := map[string]string{"go:stdlib": stringTrim(goroot)}
	for _, module := range info.Modules {
		item, ok := known[module.Path]
		if !ok || item.Version != module.Version {
			return nil, fmt.Errorf("linked module %s@%s lacks matching licence coverage", module.Path, module.Version)
		}
		data, err := goOutput(ctx, dir, env, "list", "-mod=readonly", "-m", "-json", module.Path)
		if err != nil {
			return nil, err
		}
		var location moduleLocation
		if err := json.Unmarshal(data, &location); err != nil {
			return nil, err
		}
		if location.Path != module.Path || location.Version != module.Version || location.Dir == "" {
			return nil, errors.New("module licence lookup disagrees with binary build information")
		}
		roots[module.Path] = location.Dir
	}
	ids := map[string]string{}
	for module, root := range roots {
		item, ok := known[module]
		if !ok {
			return nil, fmt.Errorf("missing licence coverage for %s", module)
		}
		for _, file := range item.Files {
			original, err := evidence.ReadFile(root, file.OriginalName, 1<<20)
			if err != nil {
				return nil, err
			}
			if digest(original) != file.SHA256 {
				return nil, fmt.Errorf("licence text changed for %s/%s", module, file.OriginalName)
			}
		}
		ids[module] = item.License
	}
	return ids, nil
}
