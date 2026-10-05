# React Native UTF-8 runtime support

The React Native export resolves to `dist-cjs/index.js`. Enigm's UTF-8 paths use
an internal encoder and fatal decoder, without Buffer or browser text APIs.
Encoding replaces unpaired UTF-16 surrogates with U+FFFD. Decoding rejects
overlong encodings, invalid continuation bytes, truncation, surrogate code
points and code points beyond U+10FFFF. It preserves the previous default
TextDecoder BOM handling (strip only an initial U+FEFF). Neither wire formats
nor signature/hash domains change.

The current Noble curves dependency has a separate import-time requirement:
Ed25519 initializes FROST domains with Noble hashes' `utf8ToBytes`, which uses
the global TextEncoder. A missing-only encoder fallback therefore runs before
each Enigm module that imports Noble curves, including direct source imports.
It leaves a provided encoder untouched. Do not remove its `sideEffects`
package metadata: optimized bundles must retain this initialization.
No TextDecoder polyfill or new dependency is needed.

## Verification

Run `npm ci --ignore-scripts`, `npm run check`, `npm test`, `npm run test:runtime`,
`npm run pack:verify`, `npm pack --dry-run`, `npm audit --audit-level=high` and
`npm audit signatures`.

The runtime test uses fresh processes for ESM, CommonJS and the react-native
export condition, with TextEncoder, TextDecoder and Buffer removed. It checks
identity/KEM generation, signatures, both envelope protocols, strict codec
rejection and byte hashes captured from upstream commit
`44bb45575bb5ad3ea9ae125aa021af49395380f5`. Entropy is deterministic ONLY in tests.
Production still requires an OS-backed CSPRNG; in particular ML-DSA signing
also uses secure random bytes, even when key generation receives a RandomSource.

On macOS, run `node scripts/verify-hermes-runtime.mjs /path/to/rn-app/node_modules`
after the build. This bundles `test/hermes-runtime.ts` with the react-native
condition, transforms it with the app's `@react-native/babel-preset`, and runs
the Hermes VM bundled with RN 0.77. It reads the mobile toolchain without
changing the app. This exercises actual Hermes rather than a Node simulation.
An iOS app integration run remains necessary before removing any mobile workaround.

## Reproducible mobile vendor update

Review and merge the source correction first. The mobile management script
requires a clean source checkout whose HEAD is exactly current origin/main.
It deliberately refuses an unmerged branch or tracked edits.

Prepare that source checkout with `git fetch origin`, `git switch main`,
`git pull --ff-only`, `npm ci --ignore-scripts` and `npm run build`.
In the mobile repository run:

```sh
node scripts/manage-enigm-crypto-vendor.mjs sync --source /absolute/path/to/enigm-crypto
npm ci --ignore-scripts
node scripts/manage-enigm-crypto-vendor.mjs verify --source /absolute/path/to/enigm-crypto
```

The sync regenerates `vendor/enigm-crypto` from the package files allowlist,
updates `vendor/enigm-crypto.lock.json` with commit/version/file count/tree SHA-256,
and removes the installed package so installation restores the new payload.
Review the generated vendor diff and lock together. Never edit the vendor or
invent a lock hash manually. Preserve unrelated mobile changes.

Run the mobile checks and an iOS/Hermes cold start, then send a Unicode message
through prepare-encryption and decrypt both standard and sealed-sender messages.
Remove the temporary app TextEncoder setup only after this integration passes.
Do not publish a package or bypass the script's current-main requirement.
