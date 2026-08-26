# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability. Send a minimal encrypted report to the
security contact published by Enigm. Include the affected version, attack prerequisites, expected
impact and a reproducer when safe to share.

## Supported versions

Only the latest tagged minor release is supported while the package remains below version 1.0.

## Cryptographic claims

The implemented primitive components follow FIPS 203 and FIPS 204 through pinned
`@noble/post-quantum` dependencies. This package is not a validated FIPS 140-3 cryptographic
module. JavaScript secret-key operations also require a dedicated side-channel assessment before
high-risk production deployment. Native constant-time providers may implement the same public API
without changing the protocol wire format.

## Release requirements

- Reproduce dependency integrity from a lockfile.
- Run known-answer, negative, mutation, interoperability and performance tests.
- Produce a signed software bill of materials and provenance attestation.
- Complete independent cryptographic review before a stable release.
- Treat changes to transcripts, framing, key derivation or suite identifiers as protocol changes.
