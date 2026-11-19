# Supported configurations

The first release covers the configurations validated below. Validation
establishes the tested scope, not stable support, original acquisition truth or
legal admissibility.

## Platform

The analyser runs on Linux and interprets Linux mountinfo/OverlayFS semantics.
Windows/macOS execution, Windows containers and other storage backends are not
implemented. This is an implementation boundary, not a claim that all containers
use OverlayFS or that every Docker/containerd configuration is supported.

Local execution was checked on Linux amd64. openat2 requires kernel 5.6+ and
an allowing policy; this API minimum is not a tested kernel matrix.
/proc/self/fd, /dev/null and writable temporary
storage are required. Linux amd64/v1 and arm64/v8.0 cross-build; only amd64 has
runtime validation. No compiler, shell, shared libraries or runtime daemon is
needed by the installed static binary.

## Observed runtime coverage

- Real kernel OverlayFS labs cover lower/upper changes, same-byte copy-up,
  whiteouts, opaque directories, mount mappings/overmounts, link ordering,
  read-only/native-marker import and escaped layer paths.
- Docker Engine classic overlay2 labs cover saved inspect/original
  alias matching, selected file origins, signed offline import/working copies,
  native whiteout conversion and foreign output ownership. Only disposable
  local fixtures are started/paused/removed; no image pull or daemon prune.
- Private containerd/ctr labs use actual image/snapshot/container
  metadata, generated OCI bytes and private user/mount/PID/network namespaces,
  config/state/socket. Data is copied after unmount and clean daemon shutdown.
  Eight origin scenarios, OCI association, changed selected bytes and signatures
  passed. CRI/NRI/restart/opt/tracing integrations are disabled in that test daemon.
- An additional runc profile starts a minimal non-TTY OCI process on
  the same snapshot: rootless, no new privileges, empty capabilities, private
  namespaces and state. It is a manual runc launch, not containerd task/shim/CRI.
- Installation checks run the static CLI and metadata-worker with no executable
  search path and in a private empty chroot with only packaged/synthetic files,
  /proc and /dev/null. Race/unit/scanner checks and old/new report replay passed
  locally; historical detailed logs live with validation artifacts outside source.

Docker's containerd image store, rootless variants and other drivers are not
validated. Containerd coverage is limited to the private lab profile described
in [development checks](DEVELOPMENT.md#optional-labs); other runtime versions
need their own lab even where metadata layouts look similar.
Pod labels can be read as saved identity facts, but there is no
validated Kubernetes/CRI/CNI deployment, kubectl integration or live collector.
The default managed-task devpts mapping did not fit the private lab's single-GID
mapping; no host policies were expanded to accommodate it. Lab exporters are
synthetic helpers, not production acquisition tools.

## Unsupported semantics and remaining work

An unshifted root OverlayFS stack is required. Shifted/nested/data-only layers,
lowerdir+/datadir+, metacopy/redirect encounters and unavailable active attributes
fail explicitly. Missing layers/mounts cannot silently become complete evidence.
OCI comparison supports bounded tar/gzip interpretation without extraction;
relevant hardlinks, sparse data, zstd and nested indexes require separate support.
There is no whole-tree image equivalence, publisher authentication from image
hashes, atomic original snapshot acquisition or application-provided OS sandbox.

Hosted GitHub CI covers the standard source, security and package checks.
Optional runtime labs need separate prerequisites and are not implied by a
successful standard run. Independent analyst pilots/security review and a
publisher trust channel remain unestablished.
See [case requirements](CASE.md), [security](SECURITY.md) and
[development/release checks](DEVELOPMENT.md).
