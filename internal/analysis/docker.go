package analysis

import (
	"strconv"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/mounts"
)

func attachDockerIdentity(c *casefile.Case, id *casefile.Identity, root mounts.Entry, rep *model.Report) {
	if id == nil || id.Docker == nil {
		return
	}
	const factID = "docker-inspect-identity"
	rep.Facts = append(rep.Facts, model.Fact{ID: factID, Kind: "docker_inspect", Source: model.Source{Artifact: c.DockerInspect}, Strength: model.Observed, Value: map[string]any{
		"sha256": id.MetadataSHA256, "container_id": id.ContainerID, "image_config_digest": id.Docker.Image, "storage_driver": "overlay2", "lowerdir": id.Docker.GraphDriver.Data["LowerDir"], "upperdir": id.Docker.GraphDriver.Data["UpperDir"],
	}})
	const mountFact = "docker-root-mount-stack"
	rep.Facts = append(rep.Facts, model.Fact{ID: mountFact, Kind: "docker_root_mount_stack", Source: model.Source{Artifact: c.MountinfoRef, Line: root.Line}, Strength: model.Observed, Value: map[string]any{"lowerdir": root.LowerDirs(), "upperdir": root.SuperValue("upperdir"), "mount_id": root.ID}})
	deps := []string{factID, mountFact}
	for i, alias := range id.DockerAliases {
		fact := "docker-alias-" + strconv.Itoa(i+1)
		rep.Facts = append(rep.Facts, model.Fact{ID: fact, Kind: "docker_overlay_alias", Source: model.Source{Artifact: alias.Artifact}, Strength: model.Observed, Value: map[string]any{"mountinfo_address": alias.Address, "saved_link_target": alias.Target}})
		deps = append(deps, fact)
	}
	rep.Claims = append(rep.Claims, model.Claim{Kind: "docker_metadata_stack_consistency", Answer: id.ContainerID, DependsOn: deps, Strength: model.Derived})
	// The association does not authenticate the capture. Mount sources continue
	// to require explicit captured-root mappings; inspect Source is never opened.
}
