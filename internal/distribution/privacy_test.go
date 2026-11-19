package distribution

import (
	"context"
	"testing"
)

func TestCaptureRejectsCredentialsEvenWhenGitIgnored(t *testing.T) {
	for _, name := range []string{"docs/.env", "tools/.env.production", "tools/private.hex", "docs/key.pem", "tools/id_ed25519", "docs/credentials.json", "tools/kubeconfig", "tools/cluster.kubeconfig"} {
		t.Run(name, func(t *testing.T) {
			root := sourceFixture(t)
			put(t, root, ".gitignore", []byte(name+"\n"))
			put(t, root, name, []byte("synthetic non-secret test content"))
			if _, err := Capture(context.Background(), root); err == nil {
				t.Fatal("included a sensitive-looking file from an explicit source directory")
			}
		})
	}
}
