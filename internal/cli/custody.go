package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/render"
	"github.com/Vivirinter/layerclue/internal/signing"
)

func keyFile(name string, private bool) ([]byte, error) { return signing.Read(name, private) }

func writeNew(name string, data []byte) error {
	// #nosec G304 G703 -- Operator-selected output path, not an evidence path; O_EXCL refuses existing final entries. The output parent is trusted.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			// #nosec G703 -- Only cleans up a failed newly created key/inventory in the operator-selected trusted output parent.
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func (a *application) cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	private := fs.String("private-key", "", "new private seed file (0600)")
	public := fs.String("public-key", "", "new public key file")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *private == "" || *public == "" {
		return exitUsage
	}
	// Refuse existing destinations before creating either file. O_EXCL below
	// protects each destination from replacement even if a concurrent writer wins.
	for _, p := range []string{*private, *public} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(a.stderr, "key destination exists or cannot be checked")
			return exitCase
		}
	}
	privatePath, _ := filepath.Abs(*private)
	publicPath, _ := filepath.Abs(*public)
	if privatePath == publicPath {
		return exitUsage
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err == nil {
		err = writeNew(*private, []byte(hex.EncodeToString(priv.Seed())+"\n"))
	}
	if err == nil {
		err = writeNew(*public, []byte(hex.EncodeToString(pub)+"\n"))
	}
	if err != nil {
		fmt.Fprintln(a.stderr, render.Safe(err.Error()))
		return exitCase
	}
	fmt.Fprintln(a.stdout, "Ed25519 key files created; keep the private key and trusted public key outside evidence bundles.")
	return exitOK
}
func (a *application) cmdCustody(command string, args []string) int {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	root := fs.String("case", "", "prepared case directory")
	output := fs.String("output", "", "new inventory file or collection bundle directory")
	inventory := fs.String("inventory", "", "existing inventory file")
	method := fs.String("method", "", "operator assertion describing original acquisition")
	signKey := fs.String("sign-key", "", "external Ed25519 private seed file")
	public := fs.String("public-key", "", "external trusted Ed25519 public key")
	timeout := fs.Duration("timeout", 2*time.Minute, "maximum scan duration (up to 10m)")
	fileBytes := fs.Int64("max-file-bytes", 256<<20, "per-file read budget")
	totalBytes := fs.Int64("max-total-bytes", 4<<30, "total bytes per scan")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *root == "" || *timeout <= 0 || *timeout > 10*time.Minute || *fileBytes <= 0 || *fileBytes > 8<<30 || *totalBytes <= 0 || *totalBytes > 32<<30 {
		return exitUsage
	}
	if command == "verify-case" {
		if *inventory == "" || *output != "" || *signKey != "" || *method != "" {
			return exitUsage
		}
	} else if *output == "" || *method == "" || *inventory != "" || *public != "" {
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	limits := custody.Limits{FileBytes: *fileBytes, TotalBytes: *totalBytes}
	err := func() error {
		abs, err := filepath.Abs(*root)
		if err != nil {
			return err
		}
		var private ed25519.PrivateKey
		var trusted ed25519.PublicKey
		if *signKey != "" {
			name, err := filepath.Abs(*signKey)
			if err != nil {
				return err
			}
			if err := custody.Outside(abs, name); err != nil {
				return err
			}
			raw, err := keyFile(name, true)
			if err != nil {
				return err
			}
			private = raw
		}
		if *public != "" {
			name, err := filepath.Abs(*public)
			if err != nil {
				return err
			}
			if err := custody.Outside(abs, name); err != nil {
				return err
			}
			raw, err := keyFile(name, false)
			if err != nil {
				return err
			}
			trusted = raw
		}
		if command == "collect" {
			return custody.Collect(ctx, abs, *output, *method, limits, private)
		}
		if command == "seal" {
			dst, err := filepath.Abs(*output)
			if err != nil {
				return err
			}
			if err := custody.Outside(abs, dst); err != nil {
				return err
			}
			seal, err := custody.New(ctx, abs, *method, limits, private)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(seal, "", "  ")
			if err != nil {
				return err
			}
			if _, err := custody.Decode(data); err != nil {
				return err
			}
			return writeNew(dst, data)
		}
		path, err := filepath.Abs(*inventory)
		if err != nil {
			return err
		}
		if err := custody.Outside(abs, path); err != nil {
			return err
		}
		data, err := evidence.ReadFile(filepath.Dir(path), filepath.Base(path), custody.MaxInventoryBytes)
		if err != nil {
			return err
		}
		seal, err := custody.Decode(data)
		if err != nil {
			return err
		}
		return custody.Verify(ctx, abs, seal, limits, trusted)
	}()
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		if command == "verify-case" {
			return exitStrict
		}
		return exitCase
	}
	if command == "verify-case" {
		if *public == "" {
			fmt.Fprintln(a.stdout, "Case inventory matches; signature authentication was not performed.")
		} else {
			fmt.Fprintln(a.stdout, "Case inventory and Ed25519 signature match the supplied trusted public key; original acquisition authenticity is not established.")
		}
	} else if command == "collect" {
		fmt.Fprintln(a.stdout, "Prepared-case bundle created; case/ contains working evidence, inventory.json records integrity. Original acquisition consistency is an operator assertion.")
	} else {
		fmt.Fprintln(a.stdout, "Case inventory created; preserve it separately from evidence.")
	}
	return exitOK
}
