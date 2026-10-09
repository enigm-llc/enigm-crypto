# Security assessment of the development candidate for the planned 1.0.0 release

Assessment date: 2026-10-09. Scope: repository source, SDK state boundaries, documented protocol,
locked dependencies, packed artifacts, public examples and release workflow. This is an engineering
review with regression tests, not an independent cryptographic audit, penetration-test certification,
formal proof or guarantee of anonymity. No live production system was attacked or modified.

## Findings and disposition

| Finding | Disposition | Remaining boundary |
| --- | --- | --- |
| Clear participant/account/device/session metadata in message SDK | Explicitly documented; existing wire format preserved | Blocks a claim that service operators cannot identify/link participants |
| Valid historical witness signatures could bootstrap trust indefinitely | Freshness window added; default 24 hours, configurable | Required fresh witness mode rejects continuity and zero quorum; globally latest-head discovery still requires an independent authenticated head |
| Untrusted base64 decoded before object size limits | Bounded decoding added to SDK device, binding and message paths | Attachment decoding now has explicit bounds; host must still bound downloads, network parsing and low-level inputs |
| Delimiter-based session locator can alias identifier tuples | SDK rejects delimiter-bearing/oversized identifiers before deriving contexts | Historical unsupported identifiers need an explicit migration; no silent rewrite of ciphertext contexts |
| SDK recovery allows historical content-key decryption and repeated reads | Documented as intentional recoverable-history behavior | Retained recovery/session compromise and delivery deduplication remain distinct from primitive ratchet security |
| Version/tag mismatch and missing GitHub release repository context | Release metadata guard and explicit repository context added | Tag/main/environment protection and authorized maintainers must be configured externally |
| Public examples relied on private source paths | Examples use public imports and are verified as packed consumers | Demonstration in-memory stores and simulated trust are not production adapters |

Freshness prevents a ten-year-old witnessed proof from establishing new trust, but a 24-hour window
still permits a bounded stale-head interval. It does not prove that no newer revocation exists.
Applications requiring current status must require fresh quorum and an authenticated recent head;
witness-outage continuity must not be misrepresented as that guarantee.

Input restrictions are a compatibility change for formerly accepted unsafe SDK identifiers: `:`/`|`,
empty identifiers and identifiers longer than 256 code units are rejected. Existing larger messages
require a configured `maximumMessageBytes`; the SDK accepts up to 32 MiB. Normal supported inputs
retain identical cryptographic transcripts and wire bytes. Do not reset keys/state to bypass these
errors; migrate unsupported historical inputs through an explicitly reviewed policy.

## Review areas

- Hybrid identities, signed prekeys, conventional and sender-sealed envelopes, version/suite/context binding.
- Canonical base64 and strict UTF-8, invalid/truncated/overlong sequences and BOM handling.
- Sender account/device attribution at bootstrap and established receives, including recovery.
- Authenticated persistence before ratchet commit, failed writes, account isolation and transfer conflicts.
- One-time key lifecycle, secure entropy requirements and independently owned secret buffers.
- Transparency inclusion, active membership, consistency, rollback/equivocation, witness quorum and freshness.
- Group epoch rotation, recovery tradeoffs and bounded untrusted inputs.
- Published file allowlist, license notices, public imports, package consumers, deterministic rebuilt tarballs,
  lockfile integrity, registry signatures/attestations, SBOM and least-privilege release permissions.

The regression suite covers negative mutations and boundary cases; exact protocol/signature snapshots
are compared across ESM/CJS/React Native. The Hermes VM checks cold imports without text globals,
authenticated text bootstrap/established sessions and binary attachments. Real device acceptance remains
separate. Test counts and CI results are release evidence, not a measure of cryptographic assurance.

The dependency audit on the assessment date reported no known vulnerabilities in the locked graph.
The local signature check verified 13 installed registry signatures and 5 attestations. This is a
point-in-time check of installed platform-specific dependencies, not evidence that dependencies or
the composed protocol are vulnerability-free. Re-run both checks for each release.

## Residual risks and release boundaries

The message SDK does not meet server-blind participant anonymity. Its binding authority knows account/
device mappings, clear key packets disclose relationships, and network/provider metadata remain
observable. See [Privacy](PRIVACY.md). Meeting that objective requires a new reviewed protocol and
coordinated host design; encryption or hashing alone does not establish it.

Independent cryptographic/state-machine/side-channel review is required before a stable release.
JavaScript secret erasure is best effort, attachment operations buffer entire files, secure storage
and lock correctness are host obligations, and retained history-recovery secrets weaken historical
forward secrecy. A compromised endpoint, hostile host adapters, inaccurate clocks, leaked backups or
metadata-observing service are outside the library's content-confidentiality guarantee.

Publication also depends on namespace ownership, maintainer 2FA, configured npm OIDC trust and
protected GitHub environments/tags. Their existence cannot be inferred from source checks. A package
can be a technically verified development candidate without meeting the stronger production/anonymity
objective. Do not label this review as independent certification or the candidate as fully anonymous.
