# Protocol V2

## Cipher suite

`ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512`

The suite combines independent classical and post-quantum components. Both signature checks are
required. Both key-establishment secrets are length-framed and fed into HKDF-SHA-512. AES-256-GCM
uses a fresh 96-bit nonce. The caller context is hashed into associated data, preventing valid
ciphertext from being moved between correctly bound conversations, devices or content types.

## Identity

Each device identity has independent ML-DSA-65 and Ed25519 key pairs. Its key identifier is the
SHA-256 digest of a domain-separated transcript containing both public keys. Secret seeds and
expanded secret keys are returned only to the caller and must remain in platform secure storage.

## KEM bundles

A recipient publishes ML-KEM-768 and X25519 public keys, an expiration time and its identity key
identifier. The identity signs the complete bundle with ML-DSA-65 and Ed25519. Messaging systems
should atomically consume one-time bundles and may expose a longer-lived last-resort bundle so an
offline recipient remains reachable.

## Envelope

The sender encapsulates to ML-KEM-768 and performs X25519 with a fresh ephemeral key. HKDF derives
one 256-bit AEAD key from both shared secrets and the complete public transcript. The encrypted
result is signed by both sender algorithms. The authenticated header includes the envelope creation
time. Sealing requires a bundle that is valid at creation; opening may happen later, provided the
signed creation time was within the bundle validity window and is not implausibly in the future.
Unknown versions, stale-at-creation bundles, mismatched key IDs, missing supplemental secrets and
invalid signatures fail closed.

An optional supplemental secret may be supplied by an independently reviewed provider. It is not
part of the baseline suite and cannot substitute for ML-KEM-768 or X25519.

## Sender-sealed envelope

A sender-sealed envelope exposes only the recipient KEM key identifier, hybrid encapsulation,
creation time, nonce, suite and ciphertext. The sender public identity, plaintext and hybrid
signature are encoded inside that ciphertext. Opening requires the recipient identity and private
KEM bundle, validates the outer associated data, verifies both inner signatures and optionally
binds the recovered sender identity to a caller-supplied expected identity. Decoders reject
oversized fields, trailing bytes, invalid flags, future creation times and missing supplemental
secrets when the sender selected that policy.

This primitive hides sender identity from a ciphertext-only relay. It does not by itself hide the
network source, recipient routing token, timing or size. A host protocol must provide anonymous
admission, abuse resistance and transport unlinkability before claiming sealed-sender delivery.

## Sessions

An envelope normally protects a fresh session root key. Two domain-separated directional chains
derive unique AES keys and advance after every message. A bounded skipped-key cache permits
out-of-order delivery while limiting memory use. Explicit rekeying mixes a fresh authenticated
hybrid secret into the root and erases old chain state.

This symmetric construction provides forward secrecy for erased chain keys. A complete messaging
protocol must define authenticated prekey consumption, durable state transitions, replay handling,
rekey cadence and recovery behavior around these primitives.

## Groups

A group epoch binds one random 256-bit secret to the canonical set of member-device identifiers.
Separate keys are derived for metadata and messages. Membership changes require a fresh epoch; the
previous epoch secret is wiped and must not be distributed to newly added members.

## Key transparency

Transparency events form a SHA-256 hash chain over a monotonically increasing sequence, previous
event hash, opaque account and device commitments, identity key identifier, action and event time.
A hybrid identity signs checkpoints containing the chain size, head hash and issue time. Clients
persist the last accepted checkpoint and reject rollback or a different head at an already observed
size. Advancing a checkpoint requires every supplied event to be contiguous with the trusted head.

The public-log layer hashes opaque event commitments as RFC 6962 leaves. It provides complete and
incremental tree construction, inclusion proofs, consistency proofs and C2SP-compatible signed
checkpoints. The interoperable log signature is Ed25519; the private checkpoint additionally uses
the hybrid identity signature. These signatures cover different protocol transcripts and are not
interchangeable.

A deployment must publish the append-only entries and proofs, obtain checkpoint cosignatures from
independent witnesses and gossip accepted checkpoints between clients before it can claim robust
protection against operator equivocation. Public entries should contain random-looking commitments,
never account names, device identifiers or discoverable public-key mappings.

## Recoverable history

Forward secrecy and recovery of all historical server ciphertext on a new device are competing
properties. Products requiring recovery must define a separate authenticated recovery capsule.
The capsule weakens historical forward secrecy to the security of its recovery key and must be
documented as a distinct security boundary.

## Encoding

Signed and derived transcripts use unsigned big-endian fixed integers and length-prefixed byte
strings. Domain labels, protocol version and suite are included. Wire encodings must preserve the
canonical bytes exactly; unordered object serialization must never be signed directly.
