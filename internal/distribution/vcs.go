package distribution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func gitOutput(ctx context.Context, root string, input []byte, args ...string) ([]byte, error) {
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	all := append([]string{"--no-replace-objects", "-c", "core.fsmonitor=false", "-C", root}, args...)
	// #nosec G204 -- Trusted developer Git executable; internal metadata commands use separate argv, time/output bounds and gitEnvironment.
	cmd := exec.CommandContext(child, "git", all...)
	cmd.Env = gitEnvironment()
	cmd.WaitDelay = time.Second
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out := &limitedBuffer{max: 4 << 20}
	errout := &limitedBuffer{max: 4096}
	cmd.Stdout = out
	cmd.Stderr = errout
	if err := cmd.Run(); err != nil {
		if child.Err() != nil {
			return nil, child.Err()
		}
		return nil, fmt.Errorf("Git metadata command failed: %w", err)
	}
	return out.value.Bytes(), nil
}

// Repository selection and global Git configuration must not override -C or
// launch an ambient fsmonitor/filter/credential helper. These metadata commands
// need no network, credentials, alternate index or inherited repository state.
func gitEnvironment() []string {
	var env []string
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1")
}

func unbornHead(ctx context.Context, root string) bool {
	ref, err := gitOutput(ctx, root, nil, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || !strings.HasPrefix(stringTrim(ref), "refs/heads/") {
		return false
	}
	_, err = gitOutput(ctx, root, nil, "show-ref", "--verify", "--quiet", stringTrim(ref))
	var status *exec.ExitError
	return errors.As(err, &status) && status.ExitCode() == 1
}

// bindRevision checks every captured byte sequence against the immutable HEAD
// blob, including inputs ignored by git status. Git performs its own object-hash
// protocol (SHA-1 or SHA-256); the release source manifest always uses SHA-256.
func bindRevision(ctx context.Context, root string, source *Snapshot, vcs VCS) error {
	if vcs.Status != "observed" || vcs.Dirty || vcs.Revision == "" {
		return errors.New("cannot bind source inputs to an uncommitted/dirty checkout")
	}
	listing, err := gitOutput(ctx, root, nil, "ls-tree", "-r", "-z", "--full-tree", vcs.Revision)
	if err != nil {
		return err
	}
	blobs := map[string]string{}
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 {
			return errors.New("invalid Git tree metadata")
		}
		if fields[1] == "blob" && (fields[0] == "100644" || fields[0] == "100755") {
			blobs[name] = fields[2]
		}
	}
	for name, data := range source.Data {
		want, ok := blobs[name]
		if !ok {
			return fmt.Errorf("source input is not a committed regular file: %q", name)
		}
		// --no-filters avoids running repository content filters and compares the
		// exact captured bytes instead of a normalised or transformed variant.
		got, err := gitOutput(ctx, root, data, "hash-object", "--no-filters", "--stdin")
		if err != nil {
			return err
		}
		if stringTrim(got) != want {
			return fmt.Errorf("captured source bytes differ from HEAD: %q", name)
		}
	}
	return nil
}
