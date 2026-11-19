# Security reporting

LayerClue is in initial development before version 1.0. There is no published
stable-support or response-time commitment yet.

A dedicated private vulnerability reporting channel is not configured. No
email address or private-reporting feature is claimed to exist. Maintainers
must publish an actual contact or enable their repository's reporting feature
before inviting confidential reports.

For ordinary non-sensitive bugs, use the repository's issue tracker once the
repository is published. Do not include live incident captures, credentials,
private signing seeds, customer data or unreleased exploit details in a public
issue. Sensitive reports should wait for a suitable maintainer contact.

The implementation trust boundaries, input limits and known unsupported cases
are documented in [the security model](docs/SECURITY.md). Release integrity and
external-key verification are documented in [release preparation](docs/DEVELOPMENT.md#release-packages).
An inventory signature is distinct from a release signature and neither proves
original incident-acquisition authenticity.
