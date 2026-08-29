# Key Transparency

The library exposes two complementary layers:

1. A private event transcript with opaque account and device commitments, a monotonic sequence and
   hybrid-signed checkpoints.
2. An RFC 6962 append-only Merkle tree with inclusion proofs, consistency proofs and C2SP signed
   checkpoints for interoperable public witnessing.

Neither layer publishes account names, device identifiers or a searchable identity directory.
Applications should publish only a 32-byte commitment for each canonical private event. An
authorized identity lookup returns the event preimage and its inclusion proof to the client that is
allowed to inspect that identity.

## Append

`appendRfc6962Entry` accepts the current frontier, current tree size and one opaque event
commitment. It returns the next root, frontier and every perfect-subtree node created by the append.
Persist the event, created nodes and updated frontier in the same serializable database transaction
as the identity change.

The frontier makes append cost logarithmic. Persisted nodes allow proofs to be assembled without
loading the complete history.

## Checkpoint

Create a checkpoint with a stable HTTPS origin, tree size and root hash. Sign its C2SP note with a
dedicated Ed25519 log key. Keep the log key separate from device identities and expose its verifier
key through a pinned application release and an authenticated public metadata endpoint.

The hybrid checkpoint is an additional application signature. It does not replace the C2SP log
signature expected by interoperable witnesses.

## Witnessing

Submit each new signed checkpoint and the required consistency proof to independent witnesses.
Store and serve their timestamped cosignatures with the checkpoint. Clients verify:

- the log signature;
- the configured witness quorum;
- consistency with the last locally accepted checkpoint;
- inclusion of the identity event they are about to trust.

An unavailable witness should not invalidate an already verified identity. A new identity or key
rotation should remain pending until the configured witness policy is satisfied. Conflicting roots
for the same origin and size are evidence of equivocation and must fail closed for affected identity
changes.

## Gossip

Clients should exchange the latest accepted origin, size and root through authenticated end-to-end
encrypted messages. A client rejects a smaller size and reports a different root at the same size.
When one checkpoint is newer, it requests and verifies an RFC 6962 consistency proof before
advancing local trust.

## Retention

The append-only log survives account and device deletion. Its public entries are opaque hashes and
cannot be removed without invalidating subsequent checkpoints. Private lookup material may be
deleted under the product retention policy; previously published commitments remain non-reversible
when commitments are derived with a secret, domain-separated key.
