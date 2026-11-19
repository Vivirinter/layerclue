# Development and releases

Current version is 0.1.0, the first release. Changes are recorded in CHANGELOG.md.
Report engine versions are exact replay identifiers: after a label change,
preserve old reports/binaries and generate a new report for fresh-case replay.
Checksum-only verification can still validate an old report's recorded structure.

The Go module is github.com/Vivirinter/layerclue. Build from a reviewed commit
of the [source repository](https://github.com/Vivirinter/layerclue).
Versions before 1.0 carry no stable-support commitment.

## Package structure

One Go module produces one user-facing executable. Following
[Go's module-layout guidance](https://go.dev/doc/modules/layout), command startup
is small and implementation packages are private:

```text
cmd/layerclue/          args/standard streams -> cli.Run -> process exit
internal/cli/          commands, flag parsing, rendering, metadata-worker adapter
internal/analysis/     report assembly, Docker/OCI association, file comparison
internal/              casefile, resolve, overlay, mounts, oci, docker, containerd
internal/              evidence, custody, acquire, verify, signing, render
internal/distribution/ source-bound release building/verification
internal/lab/          opt-in runtime and installation integration tests
tools/                 example/release entrypoints and CI orchestration
```

Domain packages do not import cli. Report verification remains independent of
analysis/resolve; fresh-case replay is orchestrated by the CLI. analysis.Options
passes the file budget and an identity-reader callback: production uses the
bounded subprocess reader; only trusted synthetic tests parse identity in-process.
BuildReport returns an unsealed report, Compare seals its captured report.
cli.Run takes independent stdout/stderr writers and returns an exit code.
Tests live with the responsible package; preserve actual process/signal tests.

Prefer concrete types/small functions and actual consumer-side dependencies.
Keep acquisition, path confinement and trust decisions in their domain packages.
Preserve command syntax, streams, exit codes, deadlines and wire formats during
refactoring; compare old/new executables on the same synthetic case.

## Checks and CI

Use Linux and the Go toolchain pinned in
[CI](../.github/workflows/ci.yml), respecting the language requirement in
[go.mod](../go.mod):

```sh
go test -race -count=1 -timeout 90s ./...
go vet ./...
go run github.com/zricethezav/gitleaks/v8@v8.30.1 dir --config tools/gitleaks.toml --gitleaks-ignore-path /dev/null --ignore-gitleaks-allow --redact=100 --no-banner --no-color --timeout=120 .
go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
bash tools/ci/audit.sh
bash tools/ci/package.sh
```

Gitleaks 8.30.1 scans local content for secret patterns with redacted output and
no credential verification/upload. It runs in CI and before package smoke checks.
gosec analyses source; govulncheck checks known Go vulnerabilities and retrieves
its database over the network. CycloneDX is a component inventory format, not a
scanner. These tools are development dependencies, not CLI runtime modules.
No source is submitted to an AI/remote code-analysis service by these commands.

Review each scanner finding before fixing or annotating it. Existing narrow
`#nosec Gxxx -- reason` comments cover trusted subprocesses, operator/private-stage
paths, synthetic fixture permissions and bounded fixture indexing. Re-review the
boundary when a caller changes. No global exclusions, severity filters, no-fail
mode or automatic fixes should hide new findings. Successful write/sync/close
results must be checked; explicit secondary closes/best-effort cleanup are not
proof of successful cleanup. Keep reports/real evidence/private keys out of Git.

audit.sh runs pinned actionlint 1.7.12, ShellCheck 0.11.0, offline zizmor 1.32.0
and CI-gate regressions. Its Linux amd64 wheels and SBOM-validator dependencies
are hash-pinned in tools/requirements-*.txt and installed in private temporary
venvs. Scripts use /usr/bin/python3 and support Python 3.12/3.13; choose another
supported interpreter explicitly with LAYERCLUE_CI_PYTHON. The pinned validator
requirements include interpreter-dependent transitive dependencies; installs
must retain --require-hashes and --only-binary=:all:.
Python and Bash are not required by the installed CLI.

CI runs workflow-audit, quality, security and eight bounded ten-second fuzz
campaigns independently, then package. ci-success fails for any failed/cancelled/
skipped required job or requested lab. The workflow covers push, pull_request and
merge_group. New PR runs cancel earlier runs of that PR.

Actions use verified full commit SHAs; jobs use the hosted Ubuntu runner and
exact Go toolchain selected in the workflow, read-only modules, isolated Go
configuration, no restored/shared Go cache and
per-job timeouts. Default permissions are empty; checkout jobs request only
contents:read and do not persist credentials. No publishing/OIDC/write token,
production secrets, privileged PR trigger or self-hosted runner is configured.
The maintained runner OS image is not an immutable digest. PR code still runs as
arbitrary code in its disposable runner. Offline zizmor cannot establish online
action-advisory/tag checks; future SHA updates need separate verification.

package.sh checks synthetic reports/OCI/imports/inventories, signed test-key
packages, offline SBOM schemas and binary installation. Files/keys stay in private
temporary directories with normal/handled-interruption cleanup, not guaranteed
SIGKILL cleanup or secure erasure. CI adds --require-clean; local developer mode
may omit it. Neither creates commits or public releases. Detailed historical
logs are retained with local validation artifacts, not shipped as a session diary.

Routine Dependabot version-update PRs for Actions/Go/Python are disabled with
open-pull-requests-limit: 0. Review and apply dependency upgrades manually.
This setting does not disable security-update PRs if enabled separately in GitHub;
see [Dependabot configuration](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#open-pull-requests-limit).
Embedded go run tool versions and the Go patch pin need deliberate maintenance;
linked-module upgrades also require matching licence versions/hashes and SBOMs.

## Optional labs

Kernel/Docker/containerd labs are explicit opt-ins for disposable compatible
environments. Normal tests do not access runtime sockets. Manual CI labs require
the default branch and successful package checks; preflight rejects absent or
incompatible tools/namespaces. The runner label alone does not supply them.
Nothing installs runtimes, relaxes policies or restarts system daemons.

```sh
LAYERCLUE_KERNEL_TEST=1 go test -v -count=1 -timeout 45s -run '^Test(KernelOverlay|SnapshotAcquisition)$' ./internal/lab
LAYERCLUE_DOCKER_TEST=1 go test -v -count=1 -timeout 180s -run '^TestDockerOverlay2$' ./internal/lab
LAYERCLUE_CONTAINERD_TEST=1 LAYERCLUE_RUNC_TEST=1 go test -race -v -count=1 -timeout 180s -run '^TestPrivateContainerd$' ./internal/lab
LAYERCLUE_INSTALL_TEST=1 LAYERCLUE_INSTALL_CHROOT_TEST=1 go test -v -count=1 -timeout 240s -run '^TestBinaryInstallation$' ./internal/lab
```

The private containerd profile requires preinstalled containerd 1.7/ctr/unshare;
manual runc additionally needs /usr/bin/runc. All namespace identities and the
single-user mapping are checked before daemon/mount operations. Installation
checks run as the ordinary user and optionally in an empty private chroot.
See [observed coverage](COMPATIBILITY.md), not a claim of every runtime/kernel.

## Release packages

Run from trusted source, choosing a new output directory with an existing parent:

```sh
go run ./tools/mkrelease --output /tmp/layerclue-candidate
go run ./tools/verifyrelease --dir /tmp/layerclue-candidate --json
```

Run the local secret check above before invoking the builder directly; a clean
scan is not proof that arbitrary personal data is absent. Source capture refuses
common credential filenames even when ignored by Git. .gitignore prevents
accidental additions, not deliberate staging or disclosure in other channels.
Never distribute the entire working directory or private validation backups.

The builder inventories explicit source/docs/tool inputs and compiles a private
captured tree: readonly modules, CGO off, trimpath, buildvcs=false, local toolchain,
workspace/ambient flags disabled, Linux amd64/v1 and arm64/v8.0. It verifies module
and licence hashes; replacements, symlinks/special source files and existing
outputs are refused. --require-clean additionally binds every input to a regular
committed Git blob, including ignored inputs. Developer dirty/unborn/non-Git
builds stay explicitly unverified, never labelled a clean committed revision.
Git commands use isolated configuration/environment with lazy fetching disabled.
The compiler/module cache/build host remain trusted; this is not a hermetic or
independent source-author/SLSA attestation.

There are nine checksummed artifacts: two binary archives, a source archive,
SOURCE_MANIFEST.json, release-manifest.json and per-target SBOM/provenance files.
Binary bundles include the executable, concise documentation, licences/notices,
BUILDINFO, source manifest, SBOM/provenance, synthetic examples/demo and INPUTS.json
hashes for bundled inputs. Generated captures, keys and tool executables are
excluded. Archive ordering/modes/ownership/times are normalised. CycloneDX 1.6
lists actual linked modules and aggregate standard library; build/test-only
modules and transitive package edges are excluded. Go h1 sums are module
properties, not archive SHA-256 values. Provenance records binary/source hashes,
target/toolchain/settings and VCS state as self-reported facts.

For an actual publisher, create/store a separate external key; none is implicit:

```sh
go run ./cmd/layerclue keygen --private-key /safe/release-private.hex --public-key /safe/release-public.hex
go run ./tools/mkrelease --output /tmp/layerclue-signed --require-clean --sign-key /safe/release-private.hex
go run ./tools/verifyrelease --dir /tmp/layerclue-signed --public-key /safe/release-public.hex --require-signed
```

Use a verifier built from already trusted source, the complete artifact set and
an independently obtained public key. SHA256SUMS.sig signs exact checksum-list
bytes under layerclue.release/v1, separately from case inventories. A supplied
key requires a valid signature; in-bundle trust keys fail. Without it the result
is unauthenticated consistency only. The verifier never extracts/runs downloads
or proves opaque archive/binary content corresponds to publisher claims. Use
immutable verified downloads, inspect/extract only trusted packages into new
private directories and recheck changed files. See [distribution limits](SECURITY.md#resource-budgets).

To validate both SBOM schemas without network schema retrieval:

```sh
/usr/bin/python3 -m venv .venv-release
.venv-release/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/requirements-release-check.txt
.venv-release/bin/python tools/validate_sbom.py --dir /tmp/layerclue-candidate
```

This validates pinned official schema syntax, not vulnerabilities or publisher
trust. Before publication, require successful CI for the exact committed source.
The first release has checksums but no publisher signature; unsigned verification
must not be presented as publisher authentication. Publication is a separate
explicit action, not an automatic effect of this CI workflow. Before stable
release, configure required branch checks, establish key custody/trust
distribution and an actual reporting channel, and obtain an external analyst
pilot. Local checks do not establish those remote settings or external review.
