# Cases and workflows

LayerClue reads saved filesystem state. Obtain a coherent offline capture first;
neither manual file copies, `collect` nor `acquire-docker` freeze a live workload.
Record the process/namespace, runtime/kernel, acquisition method and intervals.
Keep originals separate, analyse a readable working copy and write reports
outside it. Missing evidence cannot prove original absence.

## Prepared case

```text
case/
  case.json
  mountinfo
  host/layers/lower/...
  host/layers/upper/...
  captures/bin/...
  containerd/meta.db             # optional consistent captured database
```

```json
{
  "schema": "layerclue.case/v1",
  "host_root": "host",
  "mountinfo": "mountinfo",
  "mounts": [
    {"mount_id": 101, "artifact": "captures/bin", "complete": true}
  ]
}
```

Replace paths/mount IDs with your capture. All artifact addresses are local to
the case: no absolute host_root, physical symlink ancestors or nested mounts.
Logical container symlinks are preserved as data and resolved by the analyser.
Preserve file types, xattrs and hardlinks; names must be UTF-8, bytes need not be.

An artifact maps the **mounted root itself**: a file for a file mount, a directory
for a directory mount. Append only the path relative to its mount point, not the
mountinfo root/source. Neither mountinfo source nor Docker Source is an
automatically usable host path. `complete:true` is the collector's assertion.

Case selection is --case, then LAYERCLUE_CASE, then local case.json or case/.
Without an explicit manifest, one process mount table can be discovered under
host/proc/PID/mountinfo or proc/PID/mountinfo. Select mountinfo or pid explicitly
when contexts conflict. Unknown/duplicate JSON fields fail.

For runtime identity, optionally add containerd_metadata and container_id
(namespace/id when needed). Conventional database locations are containerd/meta.db,
evidence/containerd/meta.db and
host/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db; ambiguity requires
an explicit selection. Never point analysis at a running daemon's database.

### OverlayFS attributes

Native userxattr mounts use user.overlay.*; other native mounts use trusted.overlay.*.
Only the active namespace has meaning. Unreadable trusted markers are refused.
A CAP_SYS_ADMIN bit/full initial-style UID map is a necessary guard, not proof
of authority for every filesystem's owning namespace.

For a portable copy, export active whiteout/opaque/metacopy/redirect attributes
under user.layerclue.overlay.*. Clear stale reserved values first, preserve empty
attributes as present, record the original namespace/completeness, then set
`"overlay_xattr_namespace":"capture"`. Setting the field alone does not restore
missing evidence. Raw native device whiteouts must be exported before `collect`.
Metacopy/redirect markers remain explicitly unsupported during analysis.

## Docker classic overlay2

Save `docker inspect FULL_ID` as an array with exactly one selected record,
together with coherent process mountinfo, every layer and relevant mounted root.
Add docker_inspect, docker_alias_root and the full 64-character container_id to
case.json. Saved inspect can contain secrets: protect the complete capture.
docker_inspect cannot be combined with containerd_metadata/image_provenance.

Inspect paths often use overlay2/CACHE_ID/diff while mountinfo uses
overlay2/l/SHORT_ID. Preserve each original short symlink under docker_alias_root
with its literal ../CACHE_ID/diff target, and materialise the copied layer at the
mountinfo alias address under host_root. That address must be a real directory.
The original link is read as text, checked lexically and never followed; stack
position and upper paths must agree. Missing/altered aliases fail strict analysis.
Docker's Image field is a config digest, not a platform manifest digest.

### Import an existing offline snapshot

The source is one host-shaped local tree containing saved inspect/mountinfo,
layer directories, original aliases and explicitly exported mount roots. An
external acquisition plan has this shape; replace the ID/paths/mount number:

```json
{
  "schema": "layerclue.docker-acquisition/v1",
  "container_id": "<full 64-character lowercase hex ID>",
  "inspect": "metadata/inspect.json",
  "mountinfo": "metadata/mountinfo",
  "method": "Description of the original coherent offline acquisition",
  "source_mode": "read_only_mount",
  "overlay_attributes": "native",
  "mounts": [{"mount_id": 311, "source": "exported-mounts/bin", "complete": true}]
}
```

source_mode is required: read_only_mount checks the selected route's mount flags;
operator_asserted_immutable_copy explicitly trusts a prepared working copy.
Neither proves storage snapshot atomicity or excludes writes through another
route. The live filesystem root / is refused. overlay_attributes is also
required: native reads authorised active markers, capture reads a previously
completed portable export. Source references are canonical snapshot-relative
paths. Unmapped namespace mounts remain unavailable and are journaled.

The synthetic workflow requires no Docker daemon or root:

```sh
work=$(mktemp -d)
go run ./tools/mkdockerexample --output "$work/example"
./bin/layerclue acquire-docker --source "$work/example/source" \
  --plan "$work/example/plan.json" --output "$work/bundle"
./bin/layerclue explain /usr/bin/helper --case "$work/bundle/case" --strict
```

For real input, supply your offline source/plan and optionally --sign-key with an
external private seed. --owner UID:GID assigns output ownership **before sealing**;
foreign ownership needs appropriate CHOWN/DAC_OVERRIDE authority. Do not chown a
sealed case in place. Existing/recursive outputs, overlapping roots and missing
layers are refused. Output is validated and published by a no-replace rename.

The bundle has case/ and inventory.json. Its layerclue.acquisition/v2 journal
records plan/checksum, import interval, source mode, observed mount policy,
included/omitted roots, bytes, observable metadata, directory names, markers and
links. This interval is not the original snapshot time. The importer rechecks
those inputs before publication; detection is not atomic collection.

Regular files become 0600, directories 0700; internal hardlinks/logical symlinks remain.
A native character-device 0:0 whiteout is inspected through O_PATH and converted
to a regular portable marker. No devices, execution bits or capabilities are
recreated. Unrelated/symlink xattrs, access/birth times, external hardlinks, full
disk/memory and execution history are outside scope. See [limits](SECURITY.md#resource-budgets).
An acquired bundle needs no subsequent collect step.

## Containerd and OCI association

For optional provenance, capture both consistent containerd databases and local
OCI blobs in the same acquisition epoch. Add this object alongside an explicit
container_id and containerd_metadata; replace the digest and paths:

```json
{
  "image_provenance": {
    "manifest_digest": "sha256:<64 lowercase hex characters>",
    "content_root": "oci",
    "snapshotter_metadata": "containerd/snapshotter.db",
    "snapshotter_root": "host/snapshots"
  }
}
```

content_root contains blobs/sha256/HEX. The platform manifest must match the
saved image target or an unambiguous verified direct OCI index member with a
matching size/Linux architecture. No platform guessing, nested-index resolution
or network fetch occurs. snapshotter_root contains numeric ID directories and
must match the exact captured mount stack.

The check verifies manifest/config/layer hashes, descriptor sizes and diffIDs,
then matches ordered chainIDs and both metadata graphs' keys, parents, kinds and
storage IDs. Blob digest, diffID, chainID and disk ID are distinct. The first
chainID is its diffID; later ones hash previous-chainID + space + next-diffID.

Success is verified_metadata_association and attaches captured_metadata layer
digests. Failure leaves status unverified, adds missing evidence, attaches no
layer digest and fails --strict. Association does not establish unpacked-file
equivalence, original launch configuration or publisher trust.

Generate a synthetic provenance case with a new output directory:

```sh
go run ./tools/mkexample --output examples/provenance
./bin/layerclue explain /opt/tool --case examples/provenance --trace --strict
```

## Compare and verify reports

`compare PATH --case CASE --content-root oci --manifest DIGEST --json` compares
selected regular-file type/bytes with an explicitly chosen platform manifest.
Use image_provenance.manifest_digest from the generated case, never a Docker
config ID. A Docker case can also be compared when corresponding OCI blobs
are supplied explicitly. Nothing is fetched, extracted or executed.

Output schema is layerclue.comparison/v1 with a sealed captured report. Exit 0
requires complete captured evidence and matching_bytes. Exit 1 can mean changed
bytes, absence, non-regular data or an inconclusive result; inspect status.
Exit 2 is invalid arguments, 3 processing failure, 4 unsupported OCI semantics.
Ownership, modes, xattrs and whole-tree equivalence are not compared. Reproduce
a comparison by rerunning it; `verify` accepts explain reports, not comparisons.

`verify REPORT` checks report structure/checksum only. `verify REPORT --case CASE`
adds fresh analysis and canonical-report comparison; it uses the same engine,
not an independent implementation. layerclue.report/v4 records engine version,
hash budget and explicit visible_state/lower_state values. Replay requires the
same schema and engine; a higher untrusted report
budget needs an explicit verifier-side --max-file-bytes increase. Only changes
affecting that selected-path analysis are covered.

The unreleased analyser emits v4; released 0.1.0 binaries emit v3. Structure and
checksum verification of v3 remains supported without inferring missing states.
Replay of v3 with the changed analyser requires regenerating the report.

View states are `present`, `absent`, `deleted_by_whiteout`,
`hidden_by_opaque_parent` and `unknown`. Ordinary absence is an explicit negative
observation. Absence from a mount requires its captured root to exist and the
case's explicit `complete: true` assertion. Missing roots, partial captures and
missing layers remain unknown. A non-directory ancestor or dangling logical
symlink can establish that the requested resolved path is absent. Neither a
whiteout nor an absent path proves previous existence, actor or deletion time.
`explain --strict` accepts established absence; `compare` distinguishes
`both_absent`, `absent_in_capture`, `absent_in_image` and `inconclusive`, with exit
1 for all of them. It returns 0 only for matching regular-file bytes.

## Inventories and working copies

`seal`, `verify-case` and `collect` use layerclue.inventory/v1, separately from
report verification. Keep inventories and trust keys outside the case. Keys are
32-byte hex private seeds/public keys; private inputs must have owner-only
permissions. Obtain the trusted public key independently of any untrusted bundle.

```sh
out=$(mktemp -d)
./bin/layerclue keygen --private-key "$out/private.hex" --public-key "$out/public.hex"
./bin/layerclue collect --case examples/demo --output "$out/bundle" \
  --method 'synthetic example; not original acquisition' --sign-key "$out/private.hex"
./bin/layerclue verify-case --case "$out/bundle/case" \
  --inventory "$out/bundle/inventory.json" --public-key "$out/public.hex"
```

Use seal --case CASE --output EXTERNAL_INVENTORY --method DESCRIPTION to baseline
a prepared case without copying it. --sign-key is optional; verify-case without
--public-key checks integrity only. A supplied key requires a valid signature.
Signature scope is the recorded baseline, not original acquisition truth.

Inventory covers the exact readable path set, regular bytes, types, modes,
owners, mtimes, internal hardlinks, symlink targets and enumerable non-symlink
xattrs. It excludes atime, symlink xattrs, concealed privileged metadata and
original acquisition authenticity. Signed-nanosecond mtime overflow is refused.
verify-case returns 0 for a match, 1 for mismatch/verification failure.

collect packages an already prepared **portable** case, checks source inventory
before/after copying and writes a layerclue.acquisition/v1 journal. Existing,
recursive, missing-layer or reserved-journal inputs are refused. Output files
are 0600/directories 0700; original ownership/timestamps are journaled rather
than restored. Only needed user OverlayFS attrs are restored; execution bits,
devices/capabilities are never recreated. Reanalyse the transformed copy to make
its own report. Preserve acquisition originals and journals separately.

In v4, `captured_metadata` contains the selected working-copy mode, numeric
UID/GID and nanosecond mtime. `original_metadata` is a separate acquisition
record, read from bounded v1 collection or v2 Docker journals. File records must
match type, size and SHA-256; directory records must match type and the sorted
immediate child-name digest of the physical provider directory (not a merged
namespace listing or descendant contents). `mode_bits` is Go FileMode, not raw
Linux st_mode or a chmod argument; the matching `mode` string preserves set-ID
flags for display. Collection inventories
are checksum-checked and bound to current case control artifacts; Docker plans
are checksum-checked and matched to the selected container ID. Duplicate output
addresses, escaping paths and unknown mode bits are refused. No journal source
address is opened, and no recorded permissions, ownership or times are restored.

The report binds the exact journal checksum and source-metadata fact. This is
an observed record, not independent authentication of its author or original
source. Verify the case inventory with an external trusted key separately.
No journal/matching record means source metadata is unavailable. An unreadable,
malformed or mismatching journal marks analysis incomplete and fails strict
mode; it cannot supply partially accepted original metadata. Symlinks used as
physical journal addresses are never followed. Source nanosecond times are
decimal strings in arbitrary fact values to preserve common JSON round-trips;
the typed metadata field remains an exact integer.

For a local self-check, verify the new bundle, confirm a repeated collect refuses
that destination with exit 3, then alter only the disposable copied helper and
confirm verify-case exits 1. The original demo should still replay. This is not
an independent analyst pilot. Report version/SHA, OS/runtime, observed exit codes,
unclear explanations and one useful work task through the sanitised issue form.
