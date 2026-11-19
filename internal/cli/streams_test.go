package cli_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/cli"
)

func TestRunUsesIndependentStreams(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
		out  string
		err  string
	}{
		{"version", []string{"version"}, 0, "layerclue ", ""},
		{"help", []string{"help"}, 0, "", "usage:"},
		{"unknown", []string{"not-a-command"}, 2, "", "unknown command"},
		{"flag-error", []string{"explain", "--not-a-flag"}, 2, "", "flag provided but not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := cli.Run(tc.args, &stdout, &stderr); got != tc.code {
				t.Fatalf("exit = %d, want %d", got, tc.code)
			}
			for _, stream := range []struct{ got, want string }{{stdout.String(), tc.out}, {stderr.String(), tc.err}} {
				if (stream.want == "" && stream.got != "") || !strings.Contains(stream.got, stream.want) {
					t.Fatalf("stream = %q, want %q", stream.got, stream.want)
				}
			}
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic writer failure") }

func TestExplainPropagatesOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := cli.Run([]string{"explain", "/usr/bin/helper", "--case", filepath.Join("..", "..", "examples", "demo"), "--json"}, failedWriter{}, &stderr)
	if code != 3 || !strings.Contains(stderr.String(), "synthetic writer failure") {
		t.Fatalf("failed output: exit=%d stderr=%q", code, stderr.String())
	}
}
