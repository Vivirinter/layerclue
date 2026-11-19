// Command mkdockerexample creates a portable synthetic host-shaped snapshot
// and an acquisition plan. It never connects to Docker or reads host evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/docker"
	"golang.org/x/sys/unix"
)

func main() {
	fs := flag.NewFlagSet("mkdockerexample", flag.ExitOnError)
	output := fs.String("output", "", "new directory for source/ and plan.json")
	_ = fs.Parse(os.Args[1:])
	if *output == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := generate(*output); err != nil {
		fmt.Fprintf(os.Stderr, "%q\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Created synthetic Docker snapshot and plan in %q\n", *output)
}
func generate(output string) error {
	name, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("destination exists or cannot be checked")
	}
	// #nosec G301 -- Synthetic example parent is intentionally traversable; generated case contents are in a private staging directory.
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(name), ".layerclue-docker-example-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	source := filepath.Join(stage, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		return err
	}
	put := func(root, rel string, data []byte) error {
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		// #nosec G304 -- Synthetic fixture writer uses local generated names inside its own new private stage.
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	base := "var/lib/docker/overlay2/" + strings.Repeat("1", 64) + "/diff"
	upper := "var/lib/docker/overlay2/" + strings.Repeat("2", 64) + "/diff"
	for rel, data := range map[string]string{
		base + "/usr/bin/helper": "image helper\n", base + "/etc/app.conf": "enabled=false\n",
		base + "/opt/deleted": "old image file\n", upper + "/etc/app.conf": "enabled=true\n",
		upper + "/opt/deleted": "", "captures/bin/helper": "mounted helper\n",
	} {
		if err := put(source, rel, []byte(data)); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(source, base, "proc"), 0700); err != nil {
		return err
	}
	if err := unix.Setxattr(filepath.Join(source, upper, "opt/deleted"), "user.layerclue.overlay.whiteout", nil, 0); err != nil {
		return err
	}
	alias := strings.Repeat("A", 26)
	if err := os.MkdirAll(filepath.Join(source, "var/lib/docker/overlay2/l"), 0700); err != nil {
		return err
	}
	if err := os.Symlink("../"+strings.Repeat("1", 64)+"/diff", filepath.Join(source, "var/lib/docker/overlay2/l", alias)); err != nil {
		return err
	}
	id := strings.Repeat("a", 64)
	var record docker.Record
	record.ID = id
	record.Image = "sha256:" + strings.Repeat("b", 64)
	record.Config.Image = "synthetic:example"
	record.GraphDriver.Name = "overlay2"
	record.GraphDriver.Data = map[string]string{"LowerDir": "/" + base, "UpperDir": "/" + upper}
	record.Mounts = []docker.Mount{{Type: "bind", Source: "/original-host-path-not-used", Destination: "/usr/bin"}}
	data, err := json.Marshal([]docker.Record{record})
	if err != nil {
		return err
	}
	if err := put(source, "metadata/inspect.json", data); err != nil {
		return err
	}
	mi := fmt.Sprintf("10 1 0:1 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/%s,upperdir=/%s\n11 10 8:1 / /usr/bin rw - ext4 /dev/synthetic rw\n12 10 0:3 / /proc rw - proc proc rw\n", alias, upper)
	if err := put(source, "metadata/mountinfo", []byte(mi)); err != nil {
		return err
	}
	plan := acquire.Plan{Schema: acquire.PlanSchema, ContainerID: id, Inspect: "metadata/inspect.json", Mountinfo: "metadata/mountinfo", Method: "synthetic portable Docker snapshot; not an original acquisition", SourceMode: "operator_asserted_immutable_copy", OverlayAttributes: "capture", Mounts: []acquire.Mount{{ID: 11, Source: "captures/bin", Complete: true}}}
	data, err = json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := put(stage, "plan.json", data); err != nil {
		return err
	}
	return unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, name, unix.RENAME_NOREPLACE)
}
