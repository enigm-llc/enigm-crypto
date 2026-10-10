# React Native and Hermes

Install the reviewed npm release or release tarball, then import public entry points:

```ts
import { utf8 } from '@enigm/crypto/core';
import { createEnigmMessageClient } from '@enigm/crypto/sdk';
```

The `react-native` export condition resolves to bundled CommonJS. ESM and CommonJS are built
from the same source. Metro versions without export-condition support can process the root
compiled entry; verify the resolver behavior for your supported React Native versions.

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
are verified. No native Swift/Kotlin bridge is shipped or required by this library itself.
