package cli

import (
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/Vivirinter/layerclue/internal/casefile"
)

// permute moves positional arguments behind the flags so that
// "explain /path --json" works, which is how people actually type. Go's flag
// package stops at the first non-flag argument.
func permute(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if _, _, hasValue := strings.Cut(name, "="); hasValue {
				continue
			}
			f := fs.Lookup(name)
			if f == nil {
				continue
			}
			bf, isBool := f.Value.(interface{ IsBoolFlag() bool })
			if isBool && bf.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(append(flags, "--"), positional...)
}

func openCase(dir string) (*casefile.Case, error) {
	if dir != "" {
		return casefile.Open(dir)
	}
	if env := os.Getenv("LAYERCLUE_CASE"); env != "" {
		return casefile.Open(env)
	}
	if _, err := os.Stat("case.json"); err == nil {
		return casefile.Open(".")
	}
	if info, err := os.Stat("case"); err == nil && info.IsDir() {
		return casefile.Open("case")
	}
	return nil, errors.New("no case directory: pass --case, set LAYERCLUE_CASE, or run inside a case")
}
