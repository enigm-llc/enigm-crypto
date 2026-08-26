# Enigm Crypto

`@enigm/crypto` is the portable cryptographic core of Enigm Crypto V2. It contains no product UI,
network client, Firebase dependency, analytics or storage implementation. The host application
controls transport and secure persistence while this package owns canonical encodings, transcripts,
hybrid key establishment, signatures, content encryption and ratchet state transitions.

## Install

```sh
npm install @enigm/crypto
```

The package publishes ESM, CommonJS and React Native entry points from the same TypeScript source.
Node uses the package CSPRNG by default. React Native hosts must inject an operating-system CSPRNG;
the Enigm mobile integration uses `react-native-quick-crypto`.

## Suite

`ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512`

Enigm Crypto V2 provides:

- FIPS 203 ML-KEM-768 combined with X25519 for hybrid key establishment.
- FIPS 204 ML-DSA-65 combined with Ed25519 for hybrid identity and prekey authentication.
- HKDF-SHA-512 domain-separated key derivation.
- AES-256-GCM authenticated encryption with caller-bound associated data.
- A forward-secure symmetric chain for per-message keys.
- Optional supplemental secret input for Enigm's separately implemented Round5 protection layer.
  Baseline security never depends on that supplemental contribution.
- Explicit protocol and cipher-suite identifiers. Unknown suites fail closed.
- Storage interfaces that require the host application to scope private material by account.

## Minimal envelope example

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

const alice = generateIdentity();
const bob = generateIdentity();
const bobBundle = generateKemBundle(bob, Date.now() + 60_000);
const context = utf8('conversation:42|sender:alice-device|recipient:bob-device|message:1');

const envelope = seal({
  sender: alice,
  recipientIdentity: publicIdentity(bob),
  recipient: publicKemBundle(bobBundle),
  plaintext: utf8('hello'),
  context,
});

const plaintext = open({
  sender: publicIdentity(alice),
  recipientIdentity: publicIdentity(bob),
  recipient: bobBundle,
  envelope,
  context,
});
```

Production integrations should use envelopes to establish or refresh session keys, then use the
session and content-key APIs for messages and large payloads. Private identities and private KEM
bundles in this example must be moved into account-scoped secure storage immediately.

## Status

This repository is pre-release cryptographic software. Passing tests and using standardized
algorithms do not constitute a FIPS 140-3 validation, a formal protocol proof or an independent
security audit. Do not describe this module as "better than Signal" until its session protocol,
multi-device model and implementation have completed independent review.

## Clean V2 cutover

Enigm 2.2 performs a destructive conversation cutover. Existing users, contacts and commercial
records remain, while prior conversations, messages, groups, calls and device cryptographic state
are removed before V2 is enabled. There is no runtime legacy negotiation or timeout downgrade.

## Server history and forward secrecy

Recoverable server-side history and Signal-style deletion of old message keys are competing
properties. A client cannot both erase every old key and later decrypt every old server ciphertext
on a fresh device without transferring or escrowing recovery material. Enigm's integration must
therefore keep these layers explicit:

- live per-device sessions can erase ratchet keys for forward secrecy and post-compromise recovery;
- optional account recovery capsules can preserve history across an approved device transfer;
- the recovery layer weakens historical forward secrecy to the security of the transferred recovery
  key and must never be represented as Signal-equivalent protection.

Production activation remains gated on the documented cutover checks, multi-device tests and an
independent protocol and implementation review.

## Public API map

| Module | Responsibility |
| --- | --- |
| `identity` | Hybrid identity generation, fingerprints, signing and verification |
| `kem` | Signed ML-KEM/X25519 recipient bundles |
| `envelope` | Hybrid authenticated key or payload envelopes |
| `session` | Directional session state, bounded skipped keys and explicit rekeying |
| `ratchet` | Low-level symmetric chain operations |
| `group` | Group epoch creation, rotation and encrypted epoch payloads |
| `payload` | AES-256-GCM content keys and ciphertexts |
| `codec` | Canonical binary wire encoding and strict decoding |

## Repository layout

```text
src/        implementation and exported types
test/       positive, negative, replay, rotation and codec tests
docs/       protocol, threat model and Enigm 2.2 migration contract
scripts/    release build helpers
```

## Host responsibilities

- Keep private identity, KEM and chain state in account-scoped Keychain/Secure Enclave storage.
- Persist only encrypted state blobs and wipe plaintext key buffers after each operation.
- Publish public identities, signed public KEM bundles and ciphertexts only.
- Enforce one-time prekey consumption atomically on the server.
- Bind the caller-provided `context` to conversation, sender device, recipient device, message ID,
  content type and protocol version.
- Delete previous chain keys after durable advancement while retaining a bounded skipped-key
  cache for out-of-order delivery.
- Reject replayed prekeys, messages and stale key versions.

## Development

```sh
npm ci
npm run check
npm test
npm run benchmark
```

Run `npm pack --dry-run` before publishing and inspect the resulting file list. Protocol changes
must update the suite or version, tests, protocol document and migration guidance in the same pull
request.

See [Protocol V2](docs/PROTOCOL.md), [Threat model](docs/THREAT-MODEL.md) and
[migration guidance](docs/MIGRATION.md). Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md),
and vulnerabilities must use the private process in [SECURITY.md](SECURITY.md).
