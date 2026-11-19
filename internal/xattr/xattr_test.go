//go:build linux

package xattr

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSetGetHas(t *testing.T) {
	name := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := "user.layerclue.test"
	if err := Set(name, key, []byte("value")); err != nil {
		t.Skipf("extended attributes unsupported here: %v", err)
	}

	got, ok := Get(name, key)
	if !ok {
		t.Fatal("attribute was not found")
	}
	if !bytes.Equal(got, []byte("value")) {
		t.Fatalf("value = %q, want %q", got, "value")
	}
	if !Has(name, key) {
		t.Fatal("Has reported false for an existing attribute")
	}
}

func TestMissingAttribute(t *testing.T) {
	name := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(name, "user.layerclue.absent"); ok {
		t.Fatal("a missing attribute must not be reported as present")
	}
	if Has(name, "user.layerclue.absent") {
		t.Fatal("Has reported true for a missing attribute")
	}
}
