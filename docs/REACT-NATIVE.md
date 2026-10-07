# React Native / Hermes

Use compiled public npm imports, including `@enigm/crypto/sdk`. The React Native export
condition resolves to bundled CommonJS. ESM and CommonJS also ship from the same TypeScript
source. Metro can use the compiled entry when it does not support export conditions.

UTF-8 uses internal routines with fatal invalid-input rejection. No TextEncoder, TextDecoder
or Buffer polyfill is installed. Build-time tree shaking removes unused Noble FROST domain
initialization that previously required TextEncoder during import. Direct development imports
of source/Noble modules do not have this compiled-package guarantee.

The host must supply OS-backed entropy and `crypto.getRandomValues` for curve scalar blinding;
see ADAPTERS.md. Do not bypass cryptographic checks to accommodate a runtime.

Library validation:

```sh
npm run test:runtime
npm run test:package
node scripts/verify-hermes-runtime.mjs /absolute/path/to/rn-app/node_modules
```

The last command uses the existing React Native Babel tooling and RN 0.77 macOS Hermes VM.
It does not modify the application. VM testing is distinct from device testing.

Next integration stage: update the vendored copy with the application's
`scripts/manage-enigm-crypto-vendor.mjs`, update its vendor lock and dependency lock,
implement secure Keychain/device-key/network adapters, then migrate mobile imports to the
public SDK. Preserve existing records and historical ciphertext. Remove temporary text
polyfills and duplicate cryptographic code only after successful text and multimedia tests
on iOS and Android devices. This source release does not perform those steps.
