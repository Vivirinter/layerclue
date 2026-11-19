package resolve

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashCacheRejectsReplacedEvidence(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "file")
	if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{CaseRoot: root})
	if _, err := r.hash(&located{HostPath: name, Info: st}); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, name); err != nil {
		t.Fatal(err)
	}
	now, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.hash(&located{HostPath: name, Info: now}); err == nil {
		t.Fatal("used a cached hash for a replaced evidence inode")
	}
}

func TestHashRejectsMetadataChangeBeforeRead(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "file")
	if err := os.WriteFile(name, []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	r := New(Options{CaseRoot: root})
	if _, err := r.hash(&located{HostPath: name, Info: st}); err == nil {
		t.Fatal("accepted metadata changed after lookup")
	}
}

func TestHashCacheRejectsInPlaceChangeWithRestoredMtime(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "file")
	if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{CaseRoot: root})
	if _, err := r.hash(&located{HostPath: name, Info: st}); err != nil {
		t.Fatal(err)
	}
	// Linux may use a coarse clock for ctime; move beyond its tick so the
	// mutation is observable. Metadata checks are not an atomic snapshot.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(name, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.hash(&located{HostPath: name, Info: current}); err == nil {
		t.Fatal("used an old hash after an in-place change with restored size/mtime")
	}
}
