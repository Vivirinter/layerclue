package acquire

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

func TestAssignOwnerDoesNotFollowExternalLinks(t *testing.T) {
	outside := t.TempDir()
	file := filepath.Join(outside, "keep")
	if err := os.WriteFile(file, []byte("outside the import"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, target := range map[string]string{
		"external-directory": outside,
		"external-file":      file,
		"loop":               "loop",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "own-file"), []byte("copied evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := assignOwner(root, Owner{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.SameState(before, after) {
		t.Fatal("ownership traversal changed a file outside the imported tree")
	}
	for _, name := range []string{"external-directory", "external-file", "loop"} {
		st, err := os.Lstat(filepath.Join(root, name))
		if err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("logical link was not preserved: %s: %v", name, err)
		}
	}
}
