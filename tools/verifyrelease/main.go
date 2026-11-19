// Command verifyrelease checks a candidate without extracting or executing it.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Vivirinter/layerclue/internal/distribution"
	"github.com/Vivirinter/layerclue/internal/signing"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	fs := flag.NewFlagSet("verifyrelease", flag.ContinueOnError)
	root := fs.String("dir", "", "release directory")
	public := fs.String("public-key", "", "external trusted Ed25519 public-key file")
	require := fs.Bool("require-signed", false, "require --public-key and a valid signature")
	asJSON := fs.Bool("json", false, "emit result JSON")
	timeout := fs.Duration("timeout", time.Minute, "maximum verification time (up to 10m)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 || *root == "" || *timeout <= 0 || *timeout > 10*time.Minute || *require && *public == "" {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var key ed25519.PublicKey
	if *public != "" {
		if err := signing.Outside(*root, *public); err != nil {
			fmt.Fprintf(os.Stderr, "verifyrelease: %q\n", err.Error())
			return 1
		}
		raw, err := signing.Read(*public, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verifyrelease: %q\n", err.Error())
			return 1
		}
		key = raw
	}
	result, err := distribution.Verify(ctx, *root, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verifyrelease: %q\n", err.Error())
		return 1
	}
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
	} else {
		if result.Authenticated {
			fmt.Printf("Release %s: %d file checksums and the external-key signature match.\n", result.Version, result.Files)
		} else {
			fmt.Printf("Release %s: %d file checksums match; publisher authentication was not performed.\n", result.Version, result.Files)
		}
		fmt.Println(result.Scope)
	}
	return 0
}
