package evidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactBoundary(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(root, filepath.Join(root, "escape/file"), 100); err == nil {
		t.Fatal("followed an escaping parent symlink")
	}
	if _, err := ReadFile(root, filepath.Join(outside, "file"), 100); err == nil {
		t.Fatal("accepted an outside artifact")
	}
	if err := os.Symlink(filepath.Join(outside, "file"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(root, filepath.Join(root, "link"), 100); err == nil {
		t.Fatal("read a logical symlink as host content")
	}
	if target, err := Readlink(root, filepath.Join(root, "link")); err != nil || target != filepath.Join(outside, "file") {
		t.Fatalf("readlink: %q %v", target, err)
	}
}

func TestBudgetsAndCancellation(t *testing.T) {
	if _, err := ReadAll(bytes.NewBufferString("12345"), 4); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Copy(ctx, io.Discard, bytes.NewBufferString("x"), 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := Copy(context.Background(), io.Discard, bytes.NewBufferString("12345"), 4); !errors.Is(err, ErrLimit) {
		t.Fatalf("copy limit: %v", err)
	}
}

func TestInvalidCopyAuthorityIsRefused(t *testing.T) {
	if _, err := ReadAll(bytes.NewReader(nil), math.MaxInt64); !errors.Is(err, ErrLimit) {
		t.Fatalf("overflowing read budget was accepted: %v", err)
	}
	if _, err := Copy(context.Background(), io.Discard, bytes.NewReader(nil), math.MaxInt64); !errors.Is(err, ErrLimit) {
		t.Fatalf("overflowing copy budget was accepted: %v", err)
	}
	if _, err := Copy(nil, io.Discard, bytes.NewReader(nil), 1); err == nil {
		t.Fatal("accepted a missing cancellation context")
	}
}
