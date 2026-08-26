# Enigm Protocol V2

## Cipher suite

`ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512`

The suite combines independent classical and post-quantum components. Both signature checks are
required. Both KEM shared secrets are length-framed and fed into HKDF-SHA-512. AES-256-GCM uses a
fresh 96-bit nonce. Context is hashed into associated data, so ciphertext cannot be moved between
conversations, devices or content types when the host supplies the required binding fields.

## Identity

Each account-device identity has independent ML-DSA-65 and Ed25519 key pairs. Its key identifier is
the SHA-256 digest of a domain-separated transcript containing both public keys. Secret seeds and
expanded secret keys never leave device secure storage.

## KEM bundles

A recipient publishes ML-KEM-768 and X25519 public KEM keys, their expiration and identity key ID.
The identity signs the complete bundle with ML-DSA-65 and Ed25519. Production messaging should use
atomically consumed one-time bundles plus a short-lived last-resort bundle.

## Envelope

The sender encapsulates to ML-KEM-768 and performs X25519 with a fresh ephemeral key. HKDF derives
one 256-bit AEAD key from both shared secrets and the complete public transcript. The encrypted
result is hybrid-signed. Unknown versions, stale bundles, mismatched key IDs, missing supplemental
secrets and invalid signatures fail closed.

An optional supplemental secret can be contributed by a separately reviewed provider. Enigm's
Round5 protection layer can contribute that secret as defense in depth. It is not named in the
baseline suite and does not substitute for either ML-KEM-768 or X25519.

## Message keys

An envelope should normally protect a session/root key, not every large payload. A symmetric chain
derives a unique AES key per message and erases the prior chain key after durable advancement. This
gives forward secrecy for prior chain messages, but post-compromise healing requires periodic fresh
KEM/DH contributions.

## Required next protocol layer

Signal-class post-compromise security requires an asynchronous prekey handshake and a hybrid
ratchet. Enigm's target is a PQXDH-style bootstrap followed by a classical Double Ratchet combined
with an ML-KEM sparse continuous key agreement. This module does not claim that property merely by
providing static envelopes.

## Retained server history

The protocol does not silently retain old ratchet keys. Products that require a newly authorized
device to recover historical server ciphertext must define a separate recovery capsule. Such a
capsule is an explicit confidentiality tradeoff: compromise of its account recovery key can expose
the history it covers even when the live ratchet has erased old message keys. Recovery keys must be
hardware-wrapped, account-scoped, transferred only through authenticated device approval and kept
out of backend plaintext.

## Encoding

All signed and derived transcripts use unsigned big-endian fixed integers and length-prefixed byte
strings. Domain labels and suite/version values are included in every transcript. Application wire
encoding must preserve these bytes exactly; JSON object ordering must never be signed directly.
