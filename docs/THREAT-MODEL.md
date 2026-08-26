# Threat Model

## Protected against

- Passive capture followed by future quantum cryptanalysis, assuming ML-KEM-768 remains secure.
- Failure of either ML-KEM-768 or X25519 alone in the hybrid key establishment.
- Forged identity/prekey material unless both ML-DSA-65 and Ed25519 verification are bypassed.
- Backend, database, realtime or object-storage compromise without device private keys.
- Ciphertext substitution across correctly bound application contexts.
- Accidental protocol downgrade caused by timeout, parse failure or absent capability data.

## Not protected against by this module alone

- A compromised unlocked endpoint while plaintext or active session keys are in memory.
- Malicious keyboard, screen capture, accessibility or operating-system components.
- Traffic analysis, contact discovery leakage or transport metadata correlation.
- Rollback/replay unless the backend and host persist monotonic key/message state.
- Post-compromise recovery until a fresh authenticated KEM/ratchet contribution is processed.
- Supply-chain or microarchitectural side channels in the JavaScript runtime.
- Server deletion guarantees where backups, provider logs or external recipients retain copies.

## Trust boundaries

The backend may authenticate users, distribute public bundles, enforce authorization and store
ciphertext. It must never receive private identity/KEM keys, chain keys, plaintext content keys or
supplemental secrets. Secure storage is trusted to isolate account-scoped key blobs. The UI is not a
cryptographic trust boundary.
