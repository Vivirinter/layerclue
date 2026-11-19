package cli

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/render"
)

func (a *application) cmdAcquireDocker(args []string) int {
	fs := flag.NewFlagSet("acquire-docker", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := fs.String("source", "", "offline host-filesystem snapshot root")
	planName := fs.String("plan", "", "acquisition plan JSON")
	output := fs.String("output", "", "new bundle directory")
	keyName := fs.String("sign-key", "", "external Ed25519 private seed file")
	owner := fs.String("owner", "", "optional numeric output UID:GID, applied before sealing")
	timeout := fs.Duration("timeout", 2*time.Minute, "maximum acquisition duration (up to 10m)")
	fileBytes := fs.Int64("max-file-bytes", 256<<20, "per-source-file read budget")
	totalBytes := fs.Int64("max-total-bytes", 4<<30, "total data bytes per source verification pass")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *source == "" || *planName == "" || *output == "" || *timeout <= 0 || *timeout > 10*time.Minute || *fileBytes <= 0 || *fileBytes > 8<<30 || *totalBytes <= 0 || *totalBytes > 32<<30 {
		fs.Usage()
		return exitUsage
	}
	var outputOwner *acquire.Owner
	if *owner != "" {
		uid, gid, ok := strings.Cut(*owner, ":")
		u, ue := strconv.ParseUint(uid, 10, 31)
		g, ge := strconv.ParseUint(gid, 10, 31)
		if !ok || ue != nil || ge != nil {
			fmt.Fprintln(a.stderr, "owner must be a numeric UID:GID")
			return exitUsage
		}
		outputOwner = &acquire.Owner{UID: int(u), GID: int(g)}
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	summary, err := func() (*acquire.Summary, error) {
		root, err := filepath.Abs(*source)
		if err != nil {
			return nil, err
		}
		name, err := filepath.Abs(*planName)
		if err != nil {
			return nil, err
		}
		data, err := evidence.ReadFile(filepath.Dir(name), filepath.Base(name), evidence.MaxManifestBytes)
		if err != nil {
			return nil, err
		}
		plan, err := acquire.DecodePlan(data)
		if err != nil {
			return nil, err
		}
		var key ed25519.PrivateKey
		if *keyName != "" {
			name, err := filepath.Abs(*keyName)
			if err != nil {
				return nil, err
			}
			if err := custody.Outside(root, name); err != nil {
				return nil, err
			}
			raw, err := keyFile(name, true)
			if err != nil {
				return nil, err
			}
			key = raw
		}
		return acquire.Docker(ctx, acquire.Options{Source: root, Output: *output, Plan: plan, Limits: custody.Limits{FileBytes: *fileBytes, TotalBytes: *totalBytes}, SigningKey: key, Owner: outputOwner})
	}()
	if err != nil {
		fmt.Fprintln(a.stderr, "layerclue:", render.Safe(err.Error()))
		return exitCase
	}
	fmt.Fprintf(a.stdout, "Docker case created: %d layer roots, %d explicit mount captures, %d namespace mounts without captures.\n", summary.LayerRoots, summary.CapturedMounts, summary.UncapturedMounts)
	fmt.Fprintf(a.stdout, "Source mode: %s; read-only mount observed: %t. Original snapshot atomicity/authenticity are not proven.\n", summary.SourceMode, summary.SourceReadOnly)
	return exitOK
}
