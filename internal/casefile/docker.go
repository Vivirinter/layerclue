package casefile

import (
	"errors"
	"path/filepath"

	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

func (c *Case) dockerIdentity() (*Identity, error) {
	r, err := docker.Read(c.Root, c.DockerInspect, c.ContainerID)
	if err != nil {
		return nil, err
	}
	table, err := c.MountTable()
	if err != nil {
		return nil, err
	}
	root, ok := c.OverlayMount(table)
	if !ok {
		return nil, errors.New("Docker capture has no visible root OverlayFS mount")
	}
	var aliases []docker.Alias
	resolve := func(address, wanted string) error {
		if c.DockerAliasRoot == "" {
			return errors.New("saved Docker lower alias symlinks are required (docker_alias_root)")
		}
		name, err := docker.AliasName(r.GraphDriver.Data["UpperDir"], address)
		if err != nil {
			return err
		}
		artifact := filepath.Join(c.DockerAliasRoot, name)
		target, err := evidence.Readlink(c.Root, artifact)
		if err != nil {
			return err
		}
		// A captured original link is read as data, never followed. Require Docker's
		// exact relative ../<cache-id>/diff shape, no arbitrary traversal.
		if err := docker.CheckAliasTarget(r.GraphDriver.Data["UpperDir"], address, wanted, target); err != nil {
			return err
		}
		aliases = append(aliases, docker.Alias{Artifact: filepath.ToSlash(artifact), Address: address, Target: target})
		return nil
	}
	if err := r.CheckStackWithAliases(root, resolve); err != nil {
		return nil, err
	}
	return &Identity{Runtime: "docker", ContainerID: r.ID, ImageRef: r.Config.Image, Snapshotter: "overlay2", MetadataSHA256: r.SHA256, Docker: r, DockerAliases: aliases}, nil
}
