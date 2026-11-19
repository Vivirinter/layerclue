package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateRefusesExistingDestination(t *testing.T) {
	dest := t.TempDir()
	sentinel := filepath.Join(dest, "keep")
	if err := os.WriteFile(sentinel, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := generate(dest); err == nil {
		t.Fatal("replaced an existing destination")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "existing" {
		t.Fatal("changed existing data")
	}
}

func TestGenerateCompleteSyntheticCase(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "case")
	if err := generate(dest); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"case.json", "mountinfo", "containerd/meta.db", "snapshotter/metadata.db", "host/snapshots/2/fs/opt/tool"} {
		if _, err := os.Stat(filepath.Join(dest, path)); err != nil {
			t.Fatal(err)
		}
	}
}
