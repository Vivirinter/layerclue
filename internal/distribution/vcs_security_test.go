package distribution

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnbornRepositoryAndAmbientGitIsolation(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git not installed")
	}
	root, other := t.TempDir(), t.TempDir()
	for _, dir := range []string{root, other} {
		cmd := exec.Command("git", "-C", dir, "init", "--quiet", "-b", "codex/fixture")
		cmd.Env = gitEnvironment()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("initialize disposable fixture: %v %s", err, out)
		}
	}
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(other, "alternate-index"))
	t.Setenv("LAYERCLUE_TEST_SECRET", "must-not-be-inherited")
	ctx := context.Background()
	actual, err := gitOutput(ctx, root, nil, "rev-parse", "--absolute-git-dir")
	if err != nil || stringTrim(actual) != filepath.Join(root, ".git") {
		t.Fatalf("ambient repository overrode the selected root: %q %v", actual, err)
	}
	for _, entry := range gitEnvironment() {
		if strings.HasPrefix(entry, "LAYERCLUE_TEST_SECRET=") || strings.HasPrefix(entry, "GIT_DIR=") || strings.HasPrefix(entry, "GIT_WORK_TREE=") || strings.HasPrefix(entry, "GIT_INDEX_FILE=") {
			t.Fatalf("unexpected inherited variable: %q", entry)
		}
	}
	state, err := vcsStatus(ctx, root, false)
	if err != nil || state.Status != "unborn" || !state.Dirty || state.Revision != "" {
		t.Fatalf("uncommitted development source was mishandled: %+v %v", state, err)
	}
	if _, err := vcsStatus(ctx, root, true); err == nil {
		t.Fatal("clean-release mode accepted a repository without a commit")
	}
}
