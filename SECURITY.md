# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability. Use GitHub's **Report a vulnerability**
form in the repository Security tab so the report and follow-up remain private. Include the
affected version, attack prerequisites, expected impact and a minimal reproducer when safe to
share. Do not include production keys, user data or provider credentials.

## Supported versions

The latest tagged prerelease is the supported candidate while the package remains below 1.0.
Untagged source and older prereleases have no stability or support guarantee.

## Cryptographic claims

The implemented primitive components follow FIPS 203 and FIPS 204 through pinned
`@noble/post-quantum` dependencies. This package is not a validated FIPS 140-3 cryptographic
module. JavaScript secret-key operations also require a dedicated side-channel assessment before
high-risk production deployment. There is no pluggable native cryptographic engine in this package. A native implementation would
require its own review and interoperability evidence; storage/entropy adapters are not replacements
for the cryptographic implementation.

## Stable release requirements

- Reproduce dependency integrity from a lockfile.
- Install dependencies without lifecycle scripts and verify registry signatures and attestations.
- Run known-answer, negative, mutation, interoperability and performance tests.
- Pass dependency, secret, static-analysis and GitHub Actions security checks.
- Produce and verify artifact-linked SBOM and build provenance attestations.
- Complete independent cryptographic review before a stable release.
- Treat changes to transcripts, framing, key derivation or suite identifiers as protocol changes.

GitHub releases remain explicitly marked as pre-release while the package version is below 1.0 and
the independent cryptographic review is incomplete. CI npm submission must use trusted publishing and
the exact tarball produced by the protected release workflow, with maintainer 2FA approval of
the staged version. Namespace bootstrap and external release controls are documented in
[Release](docs/RELEASE.md).

The [candidate security assessment](docs/SECURITY-ASSESSMENT.md) records findings, mitigations and
residual risks. Content confidentiality does not establish participant anonymity; see
[Privacy](docs/PRIVACY.md). Report findings even if all CI or dependency checks pass.
