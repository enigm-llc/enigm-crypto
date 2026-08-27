# Threat Model

## Security goals

- Resist passive capture followed by future quantum cryptanalysis, assuming ML-KEM-768 remains
  secure.
- Preserve confidentiality if either ML-KEM-768 or X25519 alone fails.
- Reject forged identity or key-bundle material unless both signature checks are bypassed.
- Protect plaintext against compromise of a ciphertext-only transport or storage service.
- Prevent substitution across application contexts that are correctly bound by the caller.
- Fail closed on an unsupported version, suite, key identifier or supplemental-secret policy.

## Outside this module

- A compromised unlocked endpoint while plaintext or active session keys are in memory.
- Malicious keyboard, screen-capture, accessibility or operating-system components.
- Traffic analysis, contact-discovery leakage and transport metadata correlation.
- Rollback or replay when the host does not persist monotonic key and message state.
- Recovery after compromise until a fresh authenticated secret is mixed into the session.
- Supply-chain and microarchitectural side channels in the JavaScript runtime.
- Deletion guarantees for backups, provider logs or copies retained by recipients.

## Trust boundaries

The host may authenticate users, distribute public bundles, enforce authorization and store
ciphertext. It must never send private identity keys, private KEM keys, chain keys, plaintext content
keys or supplemental secrets to that service. Platform secure storage is trusted to isolate
account-scoped private state. UI and transport layers are not cryptographic trust boundaries.

## Required host controls

- Verify account/device ownership before publishing or replacing public keys.
- Atomically consume one-time key bundles and reject replays.
- Bind associated data to stable, unambiguous identifiers.
- Persist ratchet advancement before confirming message delivery.
- Scope storage keys by account and device; wipe only the selected account on logout.
- Enforce authorization and deletion independently of ciphertext confidentiality.
