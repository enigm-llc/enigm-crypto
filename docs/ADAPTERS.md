# Host adapter contracts

## Entropy

Supply an OS-backed `RandomSource(length): Uint8Array` returning exactly that many fresh
secure random bytes. The runtime must also expose an OS-backed `crypto.getRandomValues`
for Noble curve scalar blinding. This requirement remains even with explicit random sources.
Compiled package imports do not require TextEncoder, TextDecoder or Buffer and do not install them.
Deterministic entropy is suitable only for tests. Failure to supply secure entropy fails closed.

## SecureStateStore

`read`, `write` and `delete` operate on opaque serialized records. Writes must atomically
replace one record. `exclusive(accountId, operation)` must serialize operations by account
across all SDK clients using that store, and across processes when they share records.
The same lock must not be recursively acquired. Namespace different SDK record keys in the
adapter as needed. Session records pass the raw local account ID to read/write; the host adapter maps it
to its secure platform label. Transparency uses
`checkpoint:` and `trust:` labels. A mobile migration must explicitly map existing Keychain
labels and import existing serialized state. Platform-specific migrations are host responsibilities.

Use encrypted platform storage with appropriate device/account access controls. Never log
serialized state, recovery keys or private keys. Errors must reject, rather than report a
successful write. A storage outage must not silently reset trust or sessions. Transparency
writes span two records; incomplete writes fail closed and require explicit recovery by the host.
Deleting trust is an explicit reset and removes prior rollback protection.

## DeviceKeyStore

`load(accountId)` returns the private identity plus private KEM bundles with `lastResort` flags.
Return fresh independently owned byte buffers, because the SDK wipes its copies after use.
Do not return references to the adapter's persistent or shared in-memory keys.
`consume(accountId, keyId)` atomically consumes a one-time bundle and rejects reuse.
Last-resort bundles are not consumed. Serialize complete receive operations by local account
outside the SDK's individual record locks to prevent concurrent prekey reuse.

## Transparency and transport

Pin a trusted base64 Ed25519 log key, checkpoint origin, named witness keys and quorum.
`fetchConsistencyProof(from, to)` returns `{version:1, oldSize, newSize, proof}`; the library
validates sizes, hashes, canonical encodings and the proof before accepting advancement.
The host network adapter must bound response size before parsing, enforce a timeout,
authenticate transport and honor cancellation. The library accepts an already-parsed value
and cannot impose network response limits. No URL, authorization token or backend client is
embedded in the SDK. Applications must verify the full identity proof before establishing trust.

## Input limits and identifiers

The message SDK defaults to 1 MiB of plaintext (`maximumMessageBytes`, configurable from
1 byte through 32 MiB), a 16-byte AEAD tag and at most 100 recipient packets. Device SDK public
objects are limited to 32 KiB decoded and conventional envelope frames to 2 MiB decoded.
Encoded sizes are checked before base64 allocation. A fixed-size content-key packet uses
32-byte chain identifiers, 12-byte nonces and at most 48 ciphertext bytes. The lower-level
base64 decoder accepts an optional decoded-byte limit; callers of low-level APIs remain
responsible for choosing appropriate bounds.

SDK conversation, device and message identifiers must be nonempty, at most 256 UTF-16 code
units, and contain neither `:` nor `|`. Existing V2 locators/contexts concatenate identifiers
with these delimiters; allowing them in identifiers creates ambiguous tuples. Use canonical
opaque identifiers and preserve their exact bytes. Low-level protocols accept arbitrary byte
contexts, so callers must frame their own identifiers unambiguously.

Attachments are fully buffered and have base64 expansion. The host must cap files and responses
before loading/parsing; avoid converting an unbounded remote object into a JavaScript string.
The SDK cannot prevent allocations already performed by the network adapter or JSON parser.

## Witness freshness and continuity

Set `maximumWitnessAgeSeconds` to a positive integer matching the deployment's checkpoint
refresh/revocation policy; the default is 86,400 seconds. Only signatures within that window
count toward the configured witness quorum for new identity trust. Clock accuracy matters;
low-level verification also rejects timestamps more than 300 seconds in the future.

Previously witnessed identities may continue without a current quorum to preserve the explicit
witness-outage behavior. A result with `quorumMet: false` is continuity, not a fresh revocation
check. Require `quorumMet: true` and an authenticated recent head when an operation requires
current status. Reject a zero quorum for production policy unless an independently reviewed
alternative trust mechanism is deliberately used. Consistency/inclusion prove relationships
between supplied checkpoints, not that a checkpoint is globally latest.

### Required current witness evidence

Pass `requireFreshWitnesses: true` to `verifyIdentity` before authorizing a new send or membership
change. This requires a positive witness quorum and rejects stale prior-trust continuity before
persisting a checkpoint. Configure at most 15 witnesses. A zero quorum is only a development policy
and cannot satisfy this stricter operation. Fresh evidence still does not prove a globally latest head.

### Buffered attachment bounds

Attachment functions accept `EnigmAttachmentLimits` as the third encryption argument and fourth
decryption argument. `maximumPlaintextBytes` defaults to 50 MiB, with an explicit maximum of 128 MiB.
Keys and nonces have fixed decoding bounds; ciphertext expansion and recovered base64 are bounded
before allocating decoded buffers. Hosts must bound downloaded files before reading or parsing them.
Larger historical files require a separately reviewed policy; wire bytes for supported files are unchanged.
