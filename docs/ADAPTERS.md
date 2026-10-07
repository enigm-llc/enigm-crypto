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
labels and import existing serialized state; this release does not perform that migration.

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
