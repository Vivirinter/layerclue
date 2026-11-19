package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadKeyPolicy(t *testing.T) {
	root := t.TempDir()
	seed := bytes.Repeat([]byte{17}, ed25519.SeedSize)
	name := filepath.Join(root, "private.hex")
	if err := os.WriteFile(name, []byte(hex.EncodeToString(seed)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed)
	got, err := Read(name, true)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("private seed decoding: %v", err)
	}
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(name, true); err == nil {
		t.Fatal("accepted a group/other-readable private seed")
	}
	if got, err := Read(name, false); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("public key permissions/decoding: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, false); err == nil {
		t.Fatal("accepted a physical symlink")
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(fifo, false); err == nil {
		t.Fatal("accepted a FIFO")
	}
	if err := os.WriteFile(name, bytes.Repeat([]byte("0"), 257), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(name, false); err == nil {
		t.Fatal("accepted an oversized key")
	}
}

func TestKeyOutsideSelectedTree(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "key.hex"), filepath.Join(alias, "key.hex")} {
		if err := Outside(root, path); err == nil {
			t.Fatalf("accepted a key inside the selected tree through %q", path)
		}
	}
	rel, err := filepath.Rel(mustWorkingDir(t), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Outside(rel, filepath.Join(parent, "trusted.hex")); err != nil {
		t.Fatalf("external key with relative candidate path: %v", err)
	}
}

func mustWorkingDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
