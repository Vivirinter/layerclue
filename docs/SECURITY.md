# Security model

## Trust and evidence access

Case manifests, mount tables, databases, paths, xattrs and bytes are untrusted.
The analyst selects a coherent immutable working copy and a trusted executable;
the hosting kernel/filesystem and that directory choice remain trusted. Analyse
unprivileged when possible. Native trusted-attribute acquisition needs separately
authorised filesystem authority; see [case preparation](CASE.md).

Artifact reads use directory-relative openat2 beneath the selected case, refusing
physical symlink/magic-link ancestors and nested mounts. A pinned O_PATH inode
is checked before data access; FIFO/devices cannot replace a regular file during
reopening. Logical container links are interpreted inside the captured namespace.
Native whiteout devices are metadata only and become portable regular markers.
No captured program, archive payload, device or capability is executed/recreated.

Mount mappings, completeness and original acquisition accuracy remain collector
assertions. Read-only opens can change atime. State checks compare inode, size,
mode, owner, mtime, ctime and link count before/after reads and cache reuse;
coarse timestamps, later changes and privileged writers still require a coherent
capture. A copied live database is not made consistent by hashing it.

JSON rejects unknown/duplicate fields, alternate-case collisions into the same
Go field, invalid Unicode surrogates and excessive byte/value/depth input.
Map keys remain case-sensitive and fact-number literals remain exact. Mount
options are split before unescaping; malformed/duplicate path options and
invalid decoded names fail. Root OverlayFS must be unshifted; unsupported
lowerdir+/datadir+, nested overlays and metacopy/redirect encounters fail closed.
Unreadable active trusted markers cannot silently become absent markers.

## Isolation and exclusions

Runtime metadata is read by a subprocess with a reduced environment, private
parent-owned temporary directory, core dumps disabled, CPU/descriptor/file-size
limits, bounded stdout/stderr and a wall timeout. The output limiter cannot be
bypassed through io.Copy's ReaderFrom fast path. Parent cleanup handles normal,
crash and timeout worker exits.

This is not a full OS sandbox or hard RSS bound. GOMEMLIMIT is soft; no seccomp,
Landlock or cgroup hard-memory policy is installed. Hostile evidence needs an
externally constrained VM with CPU/memory/disk limits. Malicious/unresponsive
storage, a compromised kernel and privileged concurrent modification are outside
the guarantee. Temporary deletion is not guaranteed secure erasure. Cooperative
SIGINT/SIGTERM cleanup does not cover SIGKILL, power loss or blocked storage;
no end-to-end power-failure durability is promised.

Terminal metadata is escaped and raw file contents are not logged. Reports and
inspect captures still contain incident-sensitive paths, identities and hashes.
There is no automatic telemetry or registry fetch in analysis. Keep originals,
credentials, private keys and real captures out of public issues/CI artifacts.

Release preparation includes local redacted secret scanning and conservative
credential-filename rejection. Ignore rules are not a publication boundary.
Review the exact source/archive manifest as well: a scanner cannot recognise
every personal name or arbitrary incident detail. Git author identities and
upload-account visibility are separate from the contents of a release archive.

## Meaning of verification

- A report checksum is unkeyed. Structural verification checks invariants;
  fresh-case replay repeats the same engine, not an independent algorithm or
  whole-case inventory. Engine/budget changes cannot silently expand authority.
- OCI association checks captured descriptors, bytes, both snapshot graphs,
  chainIDs and exact disk paths before attaching any layer digest. It does not
  establish truthful acquisition, original launch or unpacked-file equality.
- compare rechecks tar/gzip bytes in the interpretation pass and builds a bounded
  virtual tree without extraction. It compares one regular file's type/bytes,
  not metadata or a whole tree. Relevant hardlinks, sparse/ambiguous/escaping or
  unsupported formats fail closed. zstd and nested indexes are unsupported.
- Signed inventories authenticate a readable baseline only with an independently
  trusted external Ed25519 key. Atime, symlink xattrs, concealed privileged
  metadata and original acquisition authenticity are excluded.
- collect/import create a new private working copy with reduced permissions,
  preserve original readable metadata in a journal and refuse existing/recursive
  outputs. They do not create an atomic live snapshot. Output parents remain
  trusted; os.Root ownership confinement does not remove every same-user race.

Release verification has a separate signing domain. It hashes regular top-level
files and checks metadata/signatures; it never extracts archives, parses a
provided executable or runs downloaded code. Self-reported provenance/SBOMs are
not independent build attestations. Without an external publisher trust key,
checksums provide consistency only. See [release verification](DEVELOPMENT.md#release-packages).

## Resource budgets

Limits constrain work; counts can fail earlier because byte/value limits also
apply. Hashing/copy cancellation is cooperative between responsive I/O reads.

- Control/OCI manifests and indexes: 1 MiB; OCI config: 4 MiB;
  mountinfo/reports: 16 MiB; metadata databases:
  256 MiB. Mount tables: 8,192 entries; OverlayFS: 256 total lower/upper layers;
  logical paths: 4,096 bytes and 40 link expansions.
- File hashing: default 256 MiB, caller-selected maximum 8 GiB. explain deadline
  defaults to 30 seconds, compare to one minute; maximum ten minutes.
- Metadata worker: ten-second wall timeout, CPU soft/hard 3/4 seconds,
  128 descriptors, 256 MiB file-size limit, stdout 1 MiB/stderr 4 KiB;
  soft GOMEMLIMIT=128MiB, not a total-process memory guarantee.
- OCI verification: at most 256 layers; 256 MiB blob/512 MiB expanded per layer;
  aggregate blob/expanded limits 1 GiB each per verification pass. Tar comparison:
  100,000 entries and 16 MiB path/link storage per layer/tree, path/link 4,096
  bytes, archive depth 128. Repeated stages can perform more than one pass.
- Inventory: 256 MiB per file/4 GiB read bytes by default, caller maxima 8/32 GiB,
  50,000 entries, depth 128 and 16 MiB JSON; at most 1,000,000 JSON values.
  Ordinary control JSON retains its 200,000-value bound. Hardlink bytes count on
  every read; unreadable/special/nested-mount/invalid-name inputs are refused.
- Docker import: 40,000 source entries, 12 MiB serialized entry metadata,
  16 MiB journal/inventory each, depth 128 and 128 path components. Generated
  parents count toward inventory limits. Import/inventory deadlines default to
  two minutes, maximum ten. Unrepresentable signed-nanosecond mtimes fail.
- Release tooling: source up to 10,000 files, 16 MiB/input and 128 MiB total;
  distribution up to 32 top-level entries, 64 MiB/file, 512 MiB total,
  16 MiB source manifest and 4 KiB signature envelope. Developer source,
  toolchain/module cache and build host remain trusted.

See [compatibility](COMPATIBILITY.md) for observed configurations,
[development checks](DEVELOPMENT.md#checks-and-ci) for scanner boundaries and
[root SECURITY.md](../SECURITY.md) for the actual reporting-channel status.
No independent audit or legal evidence-admissibility guarantee is asserted.
