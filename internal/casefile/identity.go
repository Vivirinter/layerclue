package casefile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Vivirinter/layerclue/internal/containerd"
	"github.com/Vivirinter/layerclue/internal/docker"
	"github.com/Vivirinter/layerclue/internal/evidence"
)

// Identity is the container record resolved from the metadata database.
type Identity struct {
	Runtime           string
	ContainerID       string
	Namespace         string
	ImageRef          string
	ImageDigest       string
	PodName           string
	PodNamespace      string
	PodUID            string
	Snapshotter       string
	SnapshotKey       string
	SnapshotChain     []containerd.SnapshotRecord
	ProvenanceError   string
	MetadataSHA256    string
	SnapshotterSHA256 string
	Docker            *docker.Record
	DockerAliases     []docker.Alias

	// Candidates lists container identifiers when the case names none and
	// more than one exists. Carrying them lets the caller report the
	// ambiguity instead of guessing.
	Candidates []string
}

// Identity resolves the container the case describes.
//
// It returns (nil, nil) when the case carries no metadata database.
func (c *Case) Identity() (*Identity, error) {
	if c.DockerInspect != "" {
		return c.dockerIdentity()
	}
	if c.Metadata == "" {
		return nil, nil
	}
	store, err := containerd.OpenWithin(c.Root, c.Metadata)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	namespaces, err := store.Namespaces()
	if err != nil {
		return nil, err
	}

	if c.ContainerID != "" {
		var matches []containerd.Container
		for _, ns := range namespaces {
			id := c.ContainerID
			if wanted, name, ok := strings.Cut(id, "/"); ok {
				if wanted != ns {
					continue
				}
				id = name
			}
			ctr, err := store.Container(ns, id)
			switch {
			case err == nil:
				matches = append(matches, ctr)
			case errors.Is(err, containerd.ErrUnsupportedFormat):
				return nil, err
			case !errors.Is(err, containerd.ErrNotFound):
				return nil, err
			}
		}
		if len(matches) == 1 {
			return c.buildIdentity(store, matches[0]), nil
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%w: requested container %q", containerd.ErrNotFound, c.ContainerID)
		}
		return nil, fmt.Errorf("container id %q occurs in several namespaces; specify namespace/id", c.ContainerID)
	}

	var all []containerd.Container
	for _, ns := range namespaces {
		list, err := store.Containers(ns)
		if err != nil {
			return nil, err
		}
		if len(list) > 10000-len(all) {
			return nil, evidence.ErrLimit
		}
		all = append(all, list...)
	}

	switch len(all) {
	case 0:
		return nil, nil
	case 1:
		return c.buildIdentity(store, all[0]), nil
	}

	ids := make([]string, 0, len(all))
	for _, ctr := range all {
		ids = append(ids, ctr.Namespace+"/"+ctr.ID)
	}
	return &Identity{Candidates: ids}, nil
}

func (c *Case) buildIdentity(store *containerd.Store, ctr containerd.Container) *Identity {
	id := &Identity{
		Runtime:        "containerd",
		MetadataSHA256: store.SHA256,
		ContainerID:    ctr.ID,
		Namespace:      ctr.Namespace,
		ImageRef:       ctr.Image,
		Snapshotter:    ctr.Snapshotter,
		SnapshotKey:    ctr.SnapshotKey,
	}
	id.PodName, id.PodNamespace, id.PodUID = ctr.Pod()
	if ctr.Image != "" {
		if img, err := store.Image(ctr.Namespace, ctr.Image); err == nil {
			id.ImageDigest = img.Digest
		}
	}
	if c.ImageProvenance != nil {
		if ctr.Snapshotter != "overlayfs" {
			id.ProvenanceError = "image association currently requires the overlayfs snapshotter"
			return id
		}
		storage, err := containerd.OpenWithin(c.Root, filepath.Join(c.Root, c.ImageProvenance.SnapshotterMetadata))
		if err != nil {
			id.ProvenanceError = err.Error()
			return id
		}
		defer storage.Close()
		id.SnapshotterSHA256 = storage.SHA256
		chain, err := containerd.SnapshotChain(store, storage, ctr.Namespace, ctr.Snapshotter, ctr.SnapshotKey)
		if err != nil {
			id.ProvenanceError = err.Error()
			return id
		}
		if len(chain) == 0 {
			id.ProvenanceError = "container has no captured snapshot chain"
			return id
		}
		id.SnapshotChain = chain
	}
	return id
}
