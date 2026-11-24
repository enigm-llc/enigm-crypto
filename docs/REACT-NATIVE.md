# React Native and Hermes

Install the reviewed npm release or release tarball, then import public entry points:

```ts
import { utf8 } from '@enigm/crypto/core';
import { createEnigmMessageClient } from '@enigm/crypto/sdk';
```

The `react-native` export condition resolves to bundled CommonJS. ESM and CommonJS are built
from the same source. Metro versions without export-condition support can process the root
compiled entry; verify the resolver behavior for your supported React Native versions.

## Native engine (automatic)

The package ships a native primitive engine for React Native iOS in Rust (`native/`): ML-DSA-65
keygen/sign/verify, ML-KEM-768 keygen/encapsulate/decapsulate, Ed25519 keygen/sign/strict
verify, X25519, SHA-256/512, HMAC/HKDF-SHA512 and AES-256-GCM, exposed as a synchronous JSI binding by the autolinked `EnigmCrypto` pod
(`ios/EnigmCryptoNative.xcframework`, a dynamic framework). Installing the package and running
`pod install` is all an app does; the API, inputs and outputs are unchanged.

- Selection happens once per runtime, on the first cryptographic operation. Node.js, browsers and
  any runtime without the binding use the JavaScript engine (@noble).
- Before a native binding is used it must pass a known-answer self-test against values produced
  by the JavaScript engine, including rejection of modified signatures. A missing, stale
  (different ABI version) or failing binding is never used.
- Fallback is silent in production: results are byte-identical, only slower. When `__DEV__` is
  true a single `console.warn` explains why the native engine is unavailable and how to relink it.
- `cryptoBackend()` returns `'native'` or `'js'` for diagnostics and QA; apps never need it.
- Protocol logic, transcripts, validation and errors stay in TypeScript. Only primitives run
  natively, so every protocol (envelopes, sealed sender, sessions, transparency) benefits.
- Inputs are read in place from `Uint8Array` views and outputs are fresh `ArrayBuffer`s zeroed
  when collected; private keys never become JavaScript strings.
- Shared vectors (`npm run test:native`, CI job `native`) require the Rust engine to reproduce the
  JavaScript engine, including Ed25519 edge cases (torsion, small-order R and A, non-canonical
  encodings, S ≥ ℓ), X25519 low-order and non-canonical u, AES-GCM tag rejection and ML-KEM
  implicit rejection.

Measured on a physical iPhone (Hermes, debug build, 25 envelopes of 64 bytes): `open` 23 ms
versus 5.5 s with the JavaScript engine, `seal` 36 ms versus 8.7 s, identity plus KEM bundle
generation 3 ms versus 0.5 s. With fixed entropy both engines produced identical identity, bundle
and envelope bytes and opened each other's envelopes. Android is not yet shipped and uses the
JavaScript engine.

Maintainers rebuild the framework with `npm run build:ios-native` (macOS, Xcode, Rust 1.99.0).
The framework is a build output: it is produced for the release tarball and is not committed.

## Private key format

`PrivateIdentity.mlDsaSeed` (32 bytes) and `PrivateKemBundle.mlKemSeed` (64 bytes) replace the
expanded ML-DSA/ML-KEM private keys. Keys stored by an earlier candidate are rejected with
`EnigmKeyError` code `KEY_FORMAT_CHANGED` and must be regenerated and republished; a seed that
does not derive its stored public key raises `KEY_MISMATCH`. Call `clearVerificationCache()` on
lock, logout or account switch to drop cached bundle-signature results (hashes of public data).

## Runtime requirements

The package does not require or install global `TextEncoder`, `TextDecoder` or `Buffer`.
Its internal UTF-8 decoder rejects invalid input. Compiled dependency tree shaking removes
unused eager initialization; direct imports of `src` or individual Noble modules do not have
this compiled-entry guarantee.

Provide an OS-backed `RandomSource` and install an OS-backed `crypto.getRandomValues` provider
before invoking key generation/signing. Supplying only `RandomSource` does not satisfy curve
scalar blinding. React Native does not supply that CSPRNG in every runtime. Choose and validate
a native provider in the host application; do not use deterministic entropy or `Math.random`.
The SDK intentionally leaves native provider selection and storage policy to the host.

```ts
// nativeRandomBytes is your reviewed native OS CSPRNG adapter.
const randomSource = (length: number): Uint8Array => nativeRandomBytes(length);
// Separately initialize the host's native crypto.getRandomValues provider.
```

Use [secure adapter contracts](ADAPTERS.md) for Keychain/Keystore-backed encrypted records,
fresh private-key buffer ownership and complete receive-operation locks. Preserve existing
state/labels through explicit migrations; never reset sessions to make an upgrade succeed.

## Platform verification

The repository's runtime checks test compiled ESM/CJS/RN imports and strict decoding. The
additional Hermes harness was exercised with React Native 0.77's macOS Hermes VM:

```sh
# Contributor commands from a source checkout, not an installed npm package:
npm run test:runtime
npm run test:package
node scripts/verify-hermes-runtime.mjs /absolute/path/to/rn-app/node_modules
```

This evidence does not cover every Hermes/Metro version or constitute physical iOS/Android
acceptance. Verify cold startup, native entropy, secure persistence, delayed messages,
history/recovery, account isolation, and image/audio/video/document behavior on each supported
platform. Remove application compatibility shims only after all dependencies and device paths
are verified. The iOS native engine is optional for correctness; Android ships no native module yet.
