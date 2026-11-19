# LayerClue

Offline container forensics: explain where a selected file came from and which
captured evidence supports the answer.

A path can resolve to an image/lower layer, a writable layer or a mounted file
that hides both. LayerClue reports the visible and lower views, hashes, supporting
facts, missing evidence and a trace. It helps DFIR and security teams investigate
saved container filesystems without starting the captured workload.

Current version: **0.1.0**, the first release for evaluation.
There is no stable-support, independent-audit or complete-forensics claim.

## Supported systems

The current implementation analyses **Linux OverlayFS captures**: classic Docker
overlay2 and prepared containerd cases. The analyser also runs on Linux because
its confined file access uses Linux kernel APIs. This scope is broader than
Docker alone; Windows containers and other snapshotters need separate support.

Runtime needs openat2 support (kernel 5.6+ with a permitting policy),
/proc/self/fd, /dev/null and writable temporary storage. A static binary needs
no Go compiler, shell, Docker socket or registry. amd64 has execution coverage;
arm64 is cross-built. See [compatibility](docs/COMPATIBILITY.md).

## Quick start

Build on Linux with the Go toolchain pinned in
[CI](.github/workflows/ci.yml) and use the bundled synthetic case:

```sh
CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -trimpath -o bin/layerclue ./cmd/layerclue
./bin/layerclue inspect --case examples/demo
./bin/layerclue explain /usr/bin/helper --case examples/demo --trace --strict
./bin/layerclue explain /etc/app.conf --case examples/demo --strict
work=$(mktemp -d)
./bin/layerclue explain /usr/bin/helper --case examples/demo --json > "$work/report.json"
./bin/layerclue verify "$work/report.json" --case examples/demo --strict
```

The helper is hidden by a captured mount; the configuration differs in the
writable layer. No live container, root access or mounting is needed for this
example. Keep real acquisition originals separate and analyse readable working
copies; see [case preparation](docs/CASE.md).

Binary bundles are distributed through [Releases](https://github.com/Vivirinter/layerclue/releases),
subject to repository access. This release includes SHA-256 checksums but no
publisher signature; checksums alone do not authenticate the publisher.
Verify the complete candidate using trusted tooling before unpacking it into a
new private directory. Signed packages require an independently obtained trust key. See
[release verification](docs/DEVELOPMENT.md#release-packages).

## Commands

- `inspect` — inspect the saved case and namespace/layer configuration.
- `explain PATH` — explain the captured path; `--json`, `--trace`, `--strict`.
- `compare PATH` — compare selected bytes against an explicitly selected OCI image.
- `verify REPORT` — validate a report; `--case DIR` also repeats its analysis.
- `acquire-docker` — import an existing offline snapshot using an explicit plan.
- `keygen`, `seal`, `verify-case`, `collect` — keys, inventories and working copies.
- `version`, `help` — build version and command usage.

Run `layerclue help` for syntax. See [case formats and workflows](docs/CASE.md)
for Docker/containerd, OCI comparison, signatures and import examples.

Exit codes: **0** completed, **1** strict/integrity/comparison failure,
**2** invalid arguments, **3** input/I/O/budget/timeout failure,
**4** explicitly unsupported semantics. A non-strict exit 0 can still contain an
incomplete verdict; inspect the result. `--strict` fails on missing evidence,
unsupported semantics and unverified premises.

## Interpretation and safety

- The captured lower view is not automatically a trusted original image.
  OCI metadata association, selected-byte equality and publisher trust are
  separate claims.
- Report verification checks structure/checksum; `--case` adds fresh analysis.
  Signed inventories authenticate a recorded baseline with an external trusted
  key. Neither proves that original acquisition was truthful or complete.
- LayerClue cannot determine who changed a file, when, whether it is malicious
  or which older inode a process executed. Importing an offline snapshot does
  not create an atomic live snapshot.
- Artifact reads are confined and bounded; the metadata worker has process
  limits. Hostile evidence still needs external VM/resource isolation. Reading
  may change access times. See [the security model](docs/SECURITY.md).

## Documentation and development

- [Case preparation and workflows](docs/CASE.md)
- [Security model and limits](docs/SECURITY.md)
- [Supported configurations and validation scope](docs/COMPATIBILITY.md)
- [Architecture, tests, CI and release preparation](docs/DEVELOPMENT.md)

Start development with `go test -race -count=1 -timeout 90s ./...` and `go vet ./...`.
CI checks packages without publishing them. Contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md); vulnerability reporting is in
[SECURITY.md](SECURITY.md). Use only synthetic/sanitised data in public issues.

Author: **Vivirinter**.

Licensed under [Apache-2.0](LICENSE); dependencies retain
[their original notices](THIRD_PARTY_NOTICES.txt). See [CHANGELOG.md](CHANGELOG.md)
for changes. Release bundles include source hashes, build records, linked
component SBOMs and optional external-key signatures.
