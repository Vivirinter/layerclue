// mkexample creates synthetic cases. It never collects real host evidence and
// refuses to replace an existing destination.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Vivirinter/layerclue/internal/testfixture"
	"golang.org/x/sys/unix"
)

type fixtureFailure struct{ error }
type reporter struct{ parent, staging string }

func (*reporter) Helper()           {}
func (*reporter) Fatal(args ...any) { panic(fixtureFailure{errors.New(fmt.Sprint(args...))}) }
func (r *reporter) TempDir() string {
	dir, err := os.MkdirTemp(r.parent, ".layerclue-example-")
	if err != nil {
		r.Fatal(err)
	}
	r.staging = dir
	return dir
}

func generate(destination string) (err error) {
	name, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(name); err == nil {
		return errors.New("destination exists; select a new directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(name)
	// #nosec G301 -- Only the synthetic example output parent; actual generated data is in a private MkdirTemp stage.
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	r := &reporter{parent: parent}
	defer func() {
		if r.staging != "" {
			_ = os.RemoveAll(r.staging)
		}
		if value := recover(); value != nil {
			if failure, ok := value.(fixtureFailure); ok {
				err = failure.error
			} else {
				panic(value)
			}
		}
	}()
	f := testfixture.NewProvenanceCase(r)
	if err := unix.Renameat2(unix.AT_FDCWD, f.Root, unix.AT_FDCWD, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	r.staging = ""
	return nil
}

func main() {
	output := flag.String("output", "", "new directory for a synthetic OCI/containerd case")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := generate(*output); err != nil {
		fmt.Fprintln(os.Stderr, strconv.QuoteToGraphic(err.Error()))
		os.Exit(1)
	}
	fmt.Printf("Created synthetic case %q\n", *output)
}
