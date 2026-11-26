# Changelog

## 1.0.0 — Unreleased

- Normalize generated bundles to remove the no-op HMAC clone self-assignment and the
  unreachable engine override left after test-hook tree shaking. Cryptographic source,
  dependency bytes, native binaries and test hooks remain unchanged.

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
- Require witness quorum members to use distinct keys and prevent the log key from satisfying quorum.
- Reject ill-formed UTF-16 at cryptographic identifier boundaries and noncanonical framed suite tokens.
- Resume one-time key consumption with durable session claims after storage or process interruption.
- Authenticate recovery capsules before receive commits and reserve one-time key claims before a
  retained private prekey can create another session.
- Store ML-DSA-65 and ML-KEM-768 private keys as FIPS 204/203 seeds (`mlDsaSeed`, `mlKemSeed`).
  Expanded private keys are rejected with `EnigmKeyError` `KEY_FORMAT_CHANGED` (no migration:
  regenerate); seeds that do not derive the stored public key raise `KEY_MISMATCH`.
- Add a primitive engine boundary with an automatic React Native iOS native engine (Rust,
  synchronous JSI, dynamic framework) behind a known-answer self-test, silent JavaScript fallback
  in production and a development warning. `cryptoBackend()` reports the active engine.
- Cache successful KEM bundle signature verifications by a hash of all verified bytes when the
  JavaScript engine runs; expiry and structure are still checked on every call.
  `clearVerificationCache()` drops the cache.
- Route every primitive (ML-DSA, ML-KEM, Ed25519, X25519, SHA-2, HMAC/HKDF-SHA512, AES-256-GCM)
  through the engine with unchanged rules, including strict Ed25519 (`zip215: false`) and
  X25519 low-order rejection.
- Document participant metadata exposure, history-recovery tradeoffs, runtime constraints and
  remaining prerequisites for publication and production use.

This candidate is not an independently audited stable release. Existing wire versions and
cryptographic transcripts are unchanged for valid supported inputs.
