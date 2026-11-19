package casefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/containerd"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/mounts"
	"github.com/Vivirinter/layerclue/internal/overlay"
)

func TestManifestReferencesStayInsideCase(t *testing.T) {
	for _, body := range []string{
		`{"schema":"layerclue.case/v1","host_root":"/"}`,
		`{"schema":"layerclue.case/v1","host_root":"../outside"}`,
		`{"schema":"layerclue.case/v1","mountinfo":"../outside"}`,
		`{"schema":"layerclue.case/v1","containerd_metadata":"../outside"}`,
		`{"schema":"layerclue.case/v1","schema":"other"}`,
		`{"schema":"unknown"}`,
	} {
		root := t.TempDir()
		write(t, root, "host/proc/1/mountinfo", "10 1 0:9 / / rw - overlay overlay rw,lowerdir=/l\n")
		write(t, root, "case.json", body)
		if _, err := Open(root); err == nil {
			t.Errorf("accepted unsafe manifest %s", body)
		}
	}
}

func TestStackRefusesShiftedRootAndExcessLayers(t *testing.T) {
	root := t.TempDir()
	c := &Case{Root: root, HostRoot: root}
	for _, tc := range []struct {
		root, options string
		want          error
	}{
		{"/subtree", "lowerdir=/missing", overlay.ErrUnsupported},
		{"/", "lowerdir+=/missing,upperdir=/upper", overlay.ErrUnsupported},
		{"/", "lowerdir=/missing,datadir+=/data,upperdir=/upper", overlay.ErrUnsupported},
		{"/", "lowerdir=" + strings.TrimSuffix(strings.Repeat("/missing:", 257), ":"), evidence.ErrLimit},
		{"/", "lowerdir=" + strings.TrimSuffix(strings.Repeat("/missing:", 256), ":") + ",upperdir=/upper", evidence.ErrLimit},
	} {
		table, err := mounts.Parse(strings.NewReader("10 1 0:1 " + tc.root + " / rw - overlay overlay rw," + tc.options + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Stack(table); !errors.Is(err, tc.want) {
			t.Errorf("root=%s: expected %v before scanning layer directories, got %v", tc.root, tc.want, err)
		}
	}
}

func TestHostRootSymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("accepted host_root symlink")
	}
}

func TestMountinfoDiscoveryRefusesSeveralProcesses(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []string{"1", "2"} {
		write(t, root, "host/proc/"+pid+"/mountinfo", "10 1 0:9 / / rw - overlay overlay rw,lowerdir=/l\n")
	}
	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "multiple process") {
		t.Fatalf("picked arbitrary context: %v", err)
	}
}

func TestRequestedIdentityNeverFallsBack(t *testing.T) {
	root := writeCase(t, map[string]string{"case.json": `{"schema":"layerclue.case/v1","container_id":"absent"}`})
	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(); !errors.Is(err, containerd.ErrNotFound) {
		t.Fatalf("wrong identity fallback: %v", err)
	}
}
