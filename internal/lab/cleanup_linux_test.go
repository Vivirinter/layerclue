//go:build linux

package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateRuntimeCleanupRepairsOnlyOwnedKernelWork(t *testing.T) {
	for _, escape := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "lc-ctr-fixture")
		work := filepath.Join(root, "root/io.containerd.snapshotter.v1.overlayfs/snapshots/3/work/work")
		if err := os.MkdirAll(filepath.Dir(work), 0700); err != nil {
			t.Fatal(err)
		}
		if escape {
			outside := t.TempDir()
			if err := os.Chmod(outside, 0500); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, work); err != nil {
				t.Fatal(err)
			}
			if err := removePrivateContainerdRoot(root); err == nil {
				t.Fatal("followed a replaced kernel work directory")
			}
			st, err := os.Stat(outside)
			if err != nil || st.Mode().Perm() != 0500 {
				t.Fatal("cleanup changed an outside directory")
			}
		} else {
			if err := os.Mkdir(work, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(work, "owned"), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(work, 0); err != nil {
				t.Fatal(err)
			}
			if err := removePrivateContainerdRoot(root); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatal("private runtime root remains")
			}
		}
	}
}
