// Command layerclue explains the provenance of paths in captured containers.
package main

import (
	"os"

	"github.com/Vivirinter/layerclue/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
