# Contributing

Contributions use Apache-2.0. Keep changes reviewable and use synthetic fixtures;
never commit incident data, credentials or signing keys.

Follow [package boundaries](docs/DEVELOPMENT.md#package-structure): cmd starts the
process, cli handles commands/streams, analysis composes reports, and domain
packages enforce their own security contracts. Keep tests beside the responsible
code and preserve metadata-worker/process tests.

Run [development checks](docs/DEVELOPMENT.md#checks-and-ci) and relevant opt-in
labs. Add regressions for incorrect provenance, path escapes, incomplete evidence,
unsupported semantics and resource limits. Preserve CLI/exit/format compatibility;
compare old/new executables and report replay when changing those boundaries.

Review scanner findings individually; exceptions need a narrow local reason.
Dependency upgrades need matching licence hashes and release/SBOM checks. Do not
invent reporting contacts, support claims or publisher identities. See
[security reporting](SECURITY.md) and [the security model](docs/SECURITY.md).
