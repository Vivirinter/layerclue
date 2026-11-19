package custody

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"golang.org/x/sys/unix"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "host/lower"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"host/lower/tool": "hello", "mountinfo": "100 1 0:1 / / rw - overlay overlay rw,lowerdir=/lower,userxattr\n", "case.json": `{"schema":"layerclue.case/v1","mountinfo":"mountinfo"}`} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/outside/not-read", filepath.Join(root, "logical-link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(root, "host/lower/tool"), "user.test", []byte{0, 1, 255}, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "host/lower/tool"), filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestSignedInventoryAndMutations(t *testing.T) {
	root := fixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := New(context.Background(), root, "offline fixture", DefaultLimits(), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	seal, err = Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), root, seal, DefaultLimits(), pub); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(context.Background(), root, seal, DefaultLimits(), other); err == nil {
		t.Fatal("accepted wrong trust anchor")
	}
	unsigned := *seal
	unsigned.Signature = ""
	if err := Verify(context.Background(), root, &unsigned, DefaultLimits(), pub); err == nil {
		t.Fatal("accepted unsigned inventory with required key")
	}
	if err := os.WriteFile(filepath.Join(root, "host/lower/tool"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), root, seal, DefaultLimits(), pub); err == nil {
		t.Fatal("accepted changed bytes")
	}
}
func TestInventoryMetadataAndExtraPaths(t *testing.T) {
	for _, tc := range []string{"mode", "xattr", "hardlink", "extra", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			root := fixture(t)
			s, err := New(context.Background(), root, "offline fixture", DefaultLimits(), nil)
			if err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "mode":
				err = os.Chmod(filepath.Join(root, "host/lower/tool"), 0644)
			case "xattr":
				err = unix.Setxattr(filepath.Join(root, "host/lower/tool"), "user.test", []byte("replacement"), 0)
			case "hardlink":
				p := filepath.Join(root, "hardlink")
				st, _ := os.Stat(p)
				err = os.Remove(p)
				if err == nil {
					err = os.WriteFile(p, []byte("hello"), 0600)
				}
				if err == nil {
					err = os.Chtimes(p, st.ModTime(), st.ModTime())
				}
			case "extra":
				err = os.WriteFile(filepath.Join(root, "extra"), nil, 0600)
			case "symlink":
				p := filepath.Join(root, "logical-link")
				err = os.Remove(p)
				if err == nil {
					err = os.Symlink("/different", p)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(context.Background(), root, s, DefaultLimits(), nil); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
}
func TestInventoryRejectsFIFOAndBudgets(t *testing.T) {
	root := fixture(t)
	if _, err := Scan(context.Background(), root, Limits{FileBytes: 2, TotalBytes: 1024}); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("file budget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, root, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), root, DefaultLimits()); err == nil {
		t.Fatal("accepted FIFO")
	}
}
func TestCollectAtomicPortableBundle(t *testing.T) {
	root := fixture(t)
	dst := filepath.Join(t.TempDir(), "bundle")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	if err := Collect(context.Background(), root, dst, "offline fixture", DefaultLimits(), key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dst, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), filepath.Join(dst, "case"), seal, DefaultLimits(), pub); err != nil {
		t.Fatal(err)
	}
	if err := Collect(context.Background(), root, dst, "offline fixture", DefaultLimits(), nil); err == nil {
		t.Fatal("replaced existing bundle")
	}
	st, err := os.Stat(filepath.Join(dst, "case/host/lower/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("unexpected mode: %v", st.Mode())
	}
	if err := Collect(context.Background(), root, filepath.Join(root, "recursive"), "offline fixture", DefaultLimits(), nil); err == nil {
		t.Fatal("accepted recursive output")
	}
	if err := Verify(context.Background(), root, mustInventory(t, root), DefaultLimits(), nil); err != nil {
		t.Fatal(err)
	}
}
func mustInventory(t *testing.T, root string) *Seal {
	t.Helper()
	s, err := New(context.Background(), root, "test", DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRecomputedChecksumCannotForgeSignature(t *testing.T) {
	root := fixture(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	original, err := New(context.Background(), root, "original method assertion", DefaultLimits(), key)
	if err != nil {
		t.Fatal(err)
	}
	forged := *original
	forged.Inventory.Method = "attacker changed the signed method"
	b, _ := json.Marshal(forged.Inventory)
	sum := sha256.Sum256(b)
	forged.SHA256 = hex.EncodeToString(sum[:])
	if err := Verify(context.Background(), root, &forged, DefaultLimits(), pub); err == nil {
		t.Fatal("recomputed unkeyed checksum bypassed signature")
	}
	if err := Verify(context.Background(), root, &forged, DefaultLimits(), nil); err != nil {
		t.Fatalf("unsigned integrity-only scope should not pretend to authenticate the method: %v", err)
	}
}
func TestCollectReducesExecutableAndSetIDPermissions(t *testing.T) {
	root := fixture(t)
	if err := os.Chmod(filepath.Join(root, "host/lower/tool"), 0755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	before := mustInventory(t, root)
	dst := filepath.Join(t.TempDir(), "bundle")
	if err := Collect(context.Background(), root, dst, "offline fixture", DefaultLimits(), nil); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dst, "case/host/lower/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		t.Fatalf("restored privileged execution mode: %v", st.Mode())
	}
	if err := Verify(context.Background(), root, before, DefaultLimits(), nil); err != nil {
		t.Fatalf("packaging changed source: %v", err)
	}
}

func TestInventoryValueBudgetSupportsThirtyThousandEntries(t *testing.T) {
	entries := []Entry{{Path: ".", Kind: "directory", Mode: uint32(os.ModeDir | 0700), UID: 1000, GID: 1000, MtimeNS: 1}}
	for i := 0; i < 30000; i++ {
		entries = append(entries, Entry{Path: fmt.Sprintf("file-%05d", i), Kind: "file", Mode: 0600, UID: 1000, GID: 1000, MtimeNS: 1, Size: 1, SHA256: strings.Repeat("a", 64)})
	}
	seal := Seal{Inventory: Inventory{Schema: Schema, Method: "synthetic decoder-capacity fixture", Limits: DefaultLimits(), Entries: entries}}
	data, err := json.Marshal(seal.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	seal.SHA256 = hex.EncodeToString(sum[:])
	data, err = json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	var control Seal
	if err := evidence.DecodeJSON(data, &control); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("ordinary manifest value limit changed: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil || len(decoded.Inventory.Entries) != 30001 {
		t.Fatalf("bounded inventory capacity: %v", err)
	}
}

func TestInventoryRefusesOverflowingMtime(t *testing.T) {
	root := fixture(t)
	name := filepath.Join(root, "host/lower/tool")
	far := time.Unix(1<<34, 0)
	if err := os.Chtimes(name, far, far); err != nil {
		t.Skipf("filesystem does not support far-future timestamps: %v", err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(time.Unix(0, info.ModTime().UnixNano())) {
		t.Skip("filesystem clamped mtime into the representable range")
	}
	if _, err := Scan(context.Background(), root, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "timestamp range") {
		t.Fatalf("overflowing date was silently inventoried: %v", err)
	}
}
