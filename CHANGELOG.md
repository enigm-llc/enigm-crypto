# Changelog

## 1.0.0 — Unreleased

- Add modular core, primitives, protocols, codecs and SDK imports while preserving root exports.
- Add bundled ESM, CommonJS and React Native entry points with internal strict UTF-8 support.
- Add explicit secure-storage/device-key/entropy/transport integration contracts and Enigm V2
  message, attachment, session and transparency clients.
- Persist and enforce authenticated sender attribution for established receive sessions; legacy
  sessions require a matching authenticated bootstrap before attribution migration.
- Select live last-resort bundles while retaining expired private keys for delayed delivery.
- Bound decoded SDK wire objects, message sizes and recipient packet counts before expensive work.
- Reject ambiguous delimiter-bearing SDK protocol identifiers without changing valid wire bytes.
- Count only witness signatures within the configured freshness window for new trust.
- Document participant metadata exposure, history-recovery tradeoffs, runtime constraints and
  remaining prerequisites for publication and production use.

This candidate is not an independently audited stable release. Existing wire versions and
cryptographic transcripts are unchanged for valid supported inputs.
