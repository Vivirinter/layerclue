// Package cli implements LayerClue command parsing, rendering and process adapters.
package cli

import (
	"fmt"
	"io"

	appversion "github.com/Vivirinter/layerclue/internal/version"
)

const version = appversion.Version

// Exit codes are part of the interface: CI jobs and wrappers depend on them.
const (
	exitOK          = 0
	exitStrict      = 1
	exitUsage       = 2
	exitCase        = 3
	exitUnsupported = 4
)

type application struct {
	stdout io.Writer
	stderr io.Writer
}

// Run executes one command and returns its process exit code without calling
// os.Exit or changing global streams. A nil stream discards that output.
func Run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return (&application{stdout: stdout, stderr: stderr}).run(args)
}

func (a *application) run(args []string) int {
	if len(args) == 0 {
		a.usage()
		return exitUsage
	}
	switch args[0] {
	case "_identity-worker":
		return a.cmdIdentityWorker(args[1:])
	case "explain":
		return a.cmdExplain(args[1:])
	case "compare":
		return a.cmdCompare(args[1:])
	case "inspect":
		return a.cmdInspect(args[1:])
	case "verify":
		return a.cmdVerify(args[1:])
	case "seal", "verify-case", "collect":
		return a.cmdCustody(args[0], args[1:])
	case "keygen":
		return a.cmdKeygen(args[1:])
	case "acquire-docker":
		return a.cmdAcquireDocker(args[1:])
	case "version", "-v", "--version":
		fmt.Fprintf(a.stdout, "layerclue %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		a.usage()
		return exitOK
	default:
		fmt.Fprintf(a.stderr, "layerclue: unknown command %q\n\n", args[0])
		a.usage()
		return exitUsage
	}
}

func (a *application) usage() {
	fmt.Fprint(a.stderr, `layerclue — explain the provenance of a path inside a container

usage:
  layerclue explain <path> [--case DIR] [--json] [--trace] [--strict]
  layerclue compare <path> --case DIR --content-root DIR --manifest sha256:... [--json]
  layerclue inspect       [--case DIR]
  layerclue verify <report.json> [--case DIR] [--strict]
  layerclue seal --case DIR --output FILE --method DESCRIPTION [--sign-key FILE]
  layerclue verify-case --case DIR --inventory FILE [--public-key FILE]
  layerclue collect --case DIR --output NEW_BUNDLE --method DESCRIPTION [--sign-key FILE]
  layerclue keygen --private-key FILE --public-key FILE
  layerclue acquire-docker --source SNAPSHOT --plan FILE --output NEW_BUNDLE [--sign-key FILE]
  layerclue version

The case directory is discovered from --case, then $LAYERCLUE_CASE, then
./case.json or ./case.

explain limits: --timeout 30s --max-file-bytes 268435456
verify without --case checks structure/checksum only, not source evidence.
`)
}
