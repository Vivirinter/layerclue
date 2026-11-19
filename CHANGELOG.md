# Changes

## Unreleased

- Report v4 separates visible/lower presence, established absence,
  whiteout/opaque blocking and unavailable evidence. Complete mount absence
  requires an existing captured root and explicit completeness assertion.
- Strict explanations accept established absence; OCI comparisons distinguish
  ordinary absence from inconclusive results. Human output never uses a missing
  location alone as proof of absence.
- Captured inode metadata and journal-recorded source mode/UID/GID/mtime are
  shown separately, with bounded parsing, object/control bindings and explicit
  source-trust limits. No original permissions are restored.
- V3 report structure/checksum verification remains supported; replay requires
  regenerating reports with the current schema. Added journal/parser,
  contradiction, integrity and evidence-preservation regressions.

## 0.1.0

First release of the offline container file-provenance CLI, without
stable-support guarantees before version 1.0.

### Implemented

- Synthetic demonstration/test fixtures, redacted local secret scans and
  release-source credential-filename guards.
- Offline selected-path explanations for captured Linux OverlayFS namespaces,
  with visible/lower views, mount mappings, hashes, facts and missing evidence.
- Saved classic Docker overlay2 identity and original-alias validation; prepared
  containerd metadata and explicit OCI snapshot/image association.
- Bounded tar/gzip selected-file comparison without extraction or execution.
- Report structure/checksum verification and exact-version fresh-case replay.
- External-key Ed25519 case inventories, portable working copies and offline
  Docker snapshot import with acquisition journals and no-replace publication.
- Confined reads, observable-state checks, strict input parsing, resource budgets
  and an isolated metadata worker. Unsupported semantics fail explicitly.
- Thin command entrypoint, separate CLI/analysis packages and independent streams.
- Source-bound package tooling, linked-module SBOMs, optional release signatures
  and artifact verification using an external publisher trust key.
- CI workflow/security checks, race tests, bounded fuzzing, synthetic fixtures
  and explicitly opted-in runtime/installation labs.
- Concise case, security, compatibility and development documentation; Apache-2.0
  and original third-party licences/notices.

### Validation boundary

Local synthetic, kernel, classic-overlay2 Docker, private containerd/manual-runc
and binary-installation checks are described in docs/COMPATIBILITY.md. Historical
checkpoints/results are retained outside source. Hosted CI gates the standard
checks and package build; runtime labs remain opt-in. Independent analyst
pilots/security review, broader runtime certification and publisher trust remain
unestablished. Import consumes an existing snapshot; it does not create an atomic
live acquisition. Worker isolation is not a complete OS or hard-memory sandbox.
