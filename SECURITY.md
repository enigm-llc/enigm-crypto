# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability. Use GitHub's **Report a vulnerability**
form in the repository Security tab so the report and follow-up remain private. Include the
affected version, attack prerequisites, expected impact and a minimal reproducer when safe to
share. Do not include production keys, user data or provider credentials.

## Supported versions

Only the latest tagged minor release is supported while the package remains below version 1.0.

## Cryptographic claims

The implemented primitive components follow FIPS 203 and FIPS 204 through pinned
`@noble/post-quantum` dependencies. This package is not a validated FIPS 140-3 cryptographic
module. JavaScript secret-key operations also require a dedicated side-channel assessment before
high-risk production deployment. Native constant-time providers may implement the same public API
without changing the protocol wire format.

## Stable release requirements

- Reproduce dependency integrity from a lockfile.
- Install dependencies without lifecycle scripts and verify registry signatures and attestations.
- Run known-answer, negative, mutation, interoperability and performance tests.
- Pass dependency, secret, static-analysis and GitHub Actions security checks.
- Produce a signed software bill of materials and provenance attestation.
- Complete independent cryptographic review before a stable release.
- Treat changes to transcripts, framing, key derivation or suite identifiers as protocol changes.

GitHub releases remain explicitly marked as pre-release while the package version is below 1.0 and
the independent cryptographic review is incomplete. npm publication must use trusted publishing and
the exact tarball produced by the protected release workflow.
