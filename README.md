# Enigm Crypto

`@enigm/crypto` is an Apache-2.0 TypeScript library for hybrid classical and post-quantum
cryptography, with a portable messaging SDK. It runs through public ESM, CommonJS and
React Native entry points. It provides no built-in network transport, platform storage,
UI, analytics or telemetry. Host-supplied adapters control persistence and network requests.

**Status:** development in progress; `1.0.0` is the planned first final release and is not yet
published or approved for production. It has not completed an independent
cryptographic audit and is not a FIPS 140-3 validated module. The message SDK encrypts content
but exposes participant/routing metadata; it is **not a server-blind anonymous messaging
protocol**. Read [Security](SECURITY.md), [Privacy](docs/PRIVACY.md) and the
[security assessment](docs/SECURITY-ASSESSMENT.md) before integration.

## Installation

After the first approved npm release is available:

```sh
npm install @enigm/crypto
```

Before that release, install a reviewed release tarball after verifying its checksum and
GitHub provenance against the intended repository and commit:

```sh
npm install ./enigm-crypto-1.0.0.tgz
```

Node.js 20.19 or newer is supported. Browser and React Native runtimes must provide OS-backed
entropy, including `crypto.getRandomValues` for curve scalar blinding even when an explicit
`RandomSource` is supplied. See [React Native](docs/REACT-NATIVE.md). The compiled imports
need no `TextEncoder`, `TextDecoder` or `Buffer` and install no global text polyfills.
Noble dependencies are pinned and bundled in each compiled entry point; npm also installs
the declared dependencies. TypeScript source is included for review, not as a supported deep import.

## Quick start

This local example creates both endpoints. In an application, each endpoint keeps its own
private keys, and recipient keys must be verified before encryption.

```ts
import {
  equal, generateIdentity, generateKemBundle, open, publicIdentity,
  publicKemBundle, seal, utf8, wipe,
} from '@enigm/crypto';

const sender = generateIdentity();
const recipient = generateIdentity();
const bundle = generateKemBundle(recipient, Date.now() + 60_000);
const context = utf8('example|conversation:42|sender:a|recipient:b|message:1');
const original = utf8('hello');
let plaintext: Uint8Array | undefined;
try {
  const envelope = seal({
    sender, recipientIdentity: publicIdentity(recipient),
    recipient: publicKemBundle(bundle), plaintext: original, context,
  });
  plaintext = open({
    sender: publicIdentity(sender), recipientIdentity: publicIdentity(recipient),
    recipient: bundle, envelope, context,
  });
  if (!equal(original, plaintext)) throw new Error('Round trip failed');
} finally {
  wipe(original, sender.mlDsaSecretKey, sender.ed25519SecretKey,
    recipient.mlDsaSecretKey, recipient.ed25519SecretKey,
    bundle.mlKemSecretKey, bundle.x25519SecretKey);
  if (plaintext) wipe(plaintext);
}
```

`wipe` overwrites caller-owned byte arrays on a best-effort basis; JavaScript strings,
engine copies and garbage collection prevent a guaranteed memory-erasure claim.

## Public modules

| Import | Responsibility |
| --- | --- |
| `@enigm/crypto` | Complete API, including existing low-level exports |
| `@enigm/crypto/core` | Bytes, strict UTF-8, canonical base64 and shared types |
| `@enigm/crypto/primitives` | Hybrid identities, signatures and KEM bundles |
| `@enigm/crypto/protocols` | Envelopes, sessions, ratchets, group epochs, content and transparency |
| `@enigm/crypto/codecs` | Canonical binary wire encodings |
| `@enigm/crypto/sdk` | Message, device, session, attachment and transparency clients; adapter types |

The suite is `ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512`:
ML-KEM-768 and X25519 contribute to key establishment, both ML-DSA-65 and Ed25519 signatures
are required, and HKDF-SHA-512 separates keys for AES-256-GCM. An optional supplemental
secret never substitutes for either baseline key-establishment contribution or signature.

## Messaging SDK

The SDK constructs per-device message key packets, verifies authenticated sender attribution,
persists session state, and handles binary attachments. It preserves existing Enigm V2 wire
formats. The host supplies secure storage, device-key lifecycle, native entropy, authenticated
transport and trusted transparency configuration through [explicit adapters](docs/ADAPTERS.md).

See [SDK integration](docs/SDK.md) for factory inputs, message flow, limits, recovery and
migration. The executable [message example](examples/messages.ts) demonstrates a new and
an established session with simulated, out-of-band trust. It does not replace complete
recipient transparency verification.

For files, send the returned file key inside an authenticated encrypted message:

```ts
import { encryptEnigmAttachment, decryptEnigmAttachment } from '@enigm/crypto/sdk';
// binaryFile and randomSource are supplied by the host.
const { encrypted, fileKey } = encryptEnigmAttachment(binaryFile, randomSource);
const recovered = decryptEnigmAttachment(encrypted, fileKey);
```

Images, audio, video and documents share this API. Attachments are buffered in memory and
preserve UTF-8 base64 inside the encrypted payload; this is not a streaming file codec.

## Security and integration boundaries

- Verify public keys against account/device ownership and a complete witnessed transparency proof.
- Keep private identities, prekeys, session and recovery state in account/device-scoped secure storage.
- Serialize complete receive operations and atomically consume one-time prekeys after authenticated persistence.
- Preserve private prekeys needed for delayed delivery and historical migration.
- Bind associated data to unambiguous protocol, conversation, device, message and content identifiers.
- Persist ratchet advancement before acknowledging delivery; deduplicate transport deliveries separately.
- Rotate group epochs on membership changes; do not share prior secrets with new members.
- SDK history recovery deliberately permits repeated history reads and weakens historical forward secrecy
  to the security of retained recovery/session state.
- Set response/file limits before parsing or allocating. Witness continuity is not proof of current revocation status.
- Sender-sealed envelopes hide identity inside ciphertext; they do not hide network source, routing, timing or size.

The [protocol specification](docs/PROTOCOL.md), [key transparency contract](docs/KEY-TRANSPARENCY.md)
and [threat model](docs/THREAT-MODEL.md) explain these boundaries.

## Examples and development

From a source checkout:

```sh
npm ci --ignore-scripts
npm run check
npm test
npm run examples
npm run test:runtime
npm run test:package
npm run pack:verify
npm run release:check
```

To run a shipped TypeScript example in a separate Node.js project, install the reviewed
package/tarball and a TypeScript runner:

```sh
npm install --save-dev tsx
npx tsx node_modules/@enigm/crypto/examples/envelope.ts
npx tsx node_modules/@enigm/crypto/examples/messages.ts
```

Examples use generated demonstration data; the volatile adapter is unsuitable for production.
[Contributing](CONTRIBUTING.md), [release preparation](docs/RELEASE.md) and the
[changelog](CHANGELOG.md) describe maintenance. Report suspected vulnerabilities privately
through [SECURITY.md](SECURITY.md).
