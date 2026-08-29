# Enigm Crypto

`@enigm/crypto` is a portable TypeScript library for hybrid classical and post-quantum
cryptographic protocols. It contains no UI, network client, analytics, database or storage
implementation. Applications control transport and persistence; this package provides canonical
encodings, authenticated envelopes, identities, content encryption, sessions and group epochs.

## Status

This package is pre-release security software. It has not completed an independent cryptographic
audit and is not a FIPS 140-3 validated module. Review [SECURITY.md](SECURITY.md) and the
[threat model](docs/THREAT-MODEL.md) before using it with sensitive data.

## Install

```sh
npm install @enigm/crypto
```

The package publishes ESM, CommonJS and React Native entry points from one TypeScript source.
Node.js uses the runtime CSPRNG. Other runtimes must provide a cryptographically secure random
source backed by the operating system.

## Cipher suite

`ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512`

- ML-KEM-768 (FIPS 203) and X25519 hybrid key establishment.
- ML-DSA-65 (FIPS 204) and Ed25519 hybrid authentication.
- HKDF-SHA-512 domain-separated key derivation.
- AES-256-GCM authenticated encryption with caller-bound associated data.
- Sender-sealed envelopes with sender identity inside recipient-only ciphertext.
- Per-message symmetric chain state with bounded out-of-order delivery.
- Explicit protocol and suite identifiers; unsupported values fail closed.
- Optional supplemental secret input for an independently reviewed defense-in-depth provider.

Security does not depend on the optional supplemental contribution. Both baseline KEM secrets and
both baseline signatures are required.

## Quick start

```ts
import {
  generateIdentity,
  generateKemBundle,
  open,
  publicIdentity,
  publicKemBundle,
  seal,
  utf8,
} from '@enigm/crypto';

const sender = generateIdentity();
const recipient = generateIdentity();
const recipientBundle = generateKemBundle(recipient, Date.now() + 60_000);
const context = utf8('conversation:42|sender:device-a|recipient:device-b|message:1');

const envelope = seal({
  sender,
  recipientIdentity: publicIdentity(recipient),
  recipient: publicKemBundle(recipientBundle),
  plaintext: utf8('hello'),
  context,
});

const plaintext = open({
  sender: publicIdentity(sender),
  recipientIdentity: publicIdentity(recipient),
  recipient: recipientBundle,
  envelope,
  context,
});
```

See the executable [examples](examples) for envelopes, bidirectional sessions, group epoch
rotation, large-content encryption, sealed senders and signed key-transparency checkpoints.
The public-log integration contract is documented in
[Key transparency](docs/KEY-TRANSPARENCY.md).

## API map

| Module | Responsibility |
| --- | --- |
| `identity` | Hybrid identity generation, fingerprints, signing and verification |
| `kem` | Hybrid signed recipient key bundles |
| `envelope` | Authenticated hybrid key or payload envelopes |
| `sealed-sender` | Recipient-only sender identity and authenticated payload envelopes |
| `session` | Directional session state, skipped keys and explicit rekeying |
| `ratchet` | Low-level symmetric chain operations |
| `group` | Group epoch creation, rotation and encrypted epoch payloads |
| `payload` | AES-256-GCM content keys and ciphertexts |
| `codec` | Canonical binary wire encoding and strict decoding |
| `transparency` | Hash-chained key events, hybrid checkpoints and gossip observations |
| `transparency-log` | Incremental RFC 6962 trees, proofs and C2SP signed checkpoints |

## Integration requirements

- Scope every private identity, KEM bundle and session state to one local account and device.
- Store private material with platform secure storage and clear plaintext buffers after use.
- Publish only public identities, signed public KEM bundles and ciphertexts.
- Consume one-time bundles atomically and reject reuse.
- Retain a consumed bundle's private key until the corresponding envelope is opened, and use the
  authenticated envelope creation time for delayed-delivery validation.
- Bind `context` to protocol version, conversation, sender device, recipient device, message ID and
  content type.
- Bind an opened sealed-sender identity to the expected account before accepting its payload.
- Persist session advancement before acknowledging delivery and reject replayed counters.
- Rotate a group epoch after every membership change. A newly added member must receive only the
  new epoch secret.
- Treat recovery of historical ciphertext as a separate protocol with an explicit security model.

## Development

```sh
npm ci
npm run check
npm test
npm run examples
npm run benchmark
npm run build
npm run pack:verify
npm run --silent sbom > enigm-crypto.cdx.json
npm pack --dry-run
```

Protocol-visible changes must update the suite or version, tests and
[protocol specification](docs/PROTOCOL.md) in the same pull request. Contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md); vulnerabilities use the private process in
[SECURITY.md](SECURITY.md).
