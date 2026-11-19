// Command mkrelease creates verifiable local candidates; it never publishes.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Vivirinter/layerclue/internal/distribution"
	"github.com/Vivirinter/layerclue/internal/signing"
)

func main() {
	fs := flag.NewFlagSet("mkrelease", flag.ExitOnError)
	output := fs.String("output", "", "new directory for local source/binary release candidates")
	key := fs.String("sign-key", "", "external Ed25519 private-seed file; unsigned by default")
	clean := fs.Bool("require-clean", false, "require a committed, clean Git checkout")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall build limit (up to 30m)")
	_ = fs.Parse(os.Args[1:])
	if *output == "" || fs.NArg() != 0 || *timeout <= 0 || *timeout > 30*time.Minute {
		fs.Usage()
		os.Exit(2)
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	root, err := filepath.Abs(".")
	var private ed25519.PrivateKey
	if err == nil && *key != "" {
		err = signing.Outside(root, *key)
		if err == nil {
			var raw []byte
			raw, err = signing.Read(*key, true)
			private = raw
		}
	}
	if err == nil {
		err = distribution.Build(ctx, distribution.BuildOptions{Root: root, Output: *output, SigningKey: private, RequireClean: *clean})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkrelease: %q\n", err.Error())
		os.Exit(1)
	}
	absolute, _ := filepath.Abs(*output)
	fmt.Println(absolute)
}
