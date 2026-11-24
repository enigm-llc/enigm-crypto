# Android native engine — plan, contracts and acceptance

Status (2026-11-23): **not implemented.** Android uses the JavaScript engine (correct results,
roughly 100–500x slower on Hermes for post-quantum operations). iOS ships the native engine
described in [React Native](REACT-NATIVE.md). This document is the work order for a Linux machine
with the Android SDK/NDK and at least one emulator and one physical arm64 device.

Nothing here changes keys, wire formats or the JavaScript API: Android only adds a second
platform binding for the same Rust engine and the same JSI contract.

## 1. Fixed contracts (must not change)

| Contract | Source of truth | Android obligation |
| --- | --- | --- |
| C ABI v2 | `native/include/enigm_crypto_native.h`, `native/src/lib.rs` | Link the same functions; `enigm_crypto_abi_version() == 2`. |
| Return codes | header | `0` ok, `1/0` verify, `-1` input, `-2` key mismatch, `-3` internal, `-4` rejected. |
| JSI binding | `ios/EnigmCrypto.mm` (`install`) and `src/core/engine.ts` (`NativeBinding`) | Install the identical object on `globalThis.__enigmCryptoNative`: `abiVersion: 2` plus the 17 functions in `BINDING_FUNCTIONS`, frozen, defined non-writable/non-configurable. |
| Error strings | same | Throw `ENIGM_NATIVE_KEY_MISMATCH`, `ENIGM_NATIVE_REJECTED` or `ENIGM_NATIVE_INPUT` only; never key material or lengths of secrets in messages. |
| Inputs/outputs | same | Read `Uint8Array` views in place (buffer, byteOffset, byteLength, bounds-checked); return new `ArrayBuffer`s backed by a buffer zeroed on destruction. No strings, JSON or base64 for keys. |
| Module name | `src/core/engine.ts` (`NATIVE_MODULE`) | TurboModule named `EnigmCrypto`; requesting it installs the binding. |
| Selection | `src/core/engine.ts` | No JS change: the library already requests the module, runs the KAT self-test and falls back silently (warning in `__DEV__`). |

Refactor first: move `install()` and its helpers from `ios/EnigmCrypto.mm` into a shared
`cpp/EnigmCryptoJsi.{h,cpp}` used by both platforms, so the binding cannot diverge. iOS must be
rebuilt and re-measured after the move.

## 2. Implementation work

1. **Rust build.** Targets `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`
   (emulator), `i686-linux-android` only if the app still ships x86. Use `cargo-ndk` with NDK
   `27.1.12297006` (the app's `ndkVersion`), `minSdk 24`, pinned Rust `1.99.0`, `--locked`.
   Output `cdylib` `libenigm_crypto_native.so` per ABI into `android/src/main/jniLibs/<abi>/`.
2. **Linking hygiene.** Export only `enigm_*` (version script), `-Wl,-z,max-page-size=16384` for 16 KB
   page devices, stripped symbols. Each `.so` carries its own Rust runtime, so it coexists with the
   app's `libenigm_private_auth.so`; verify no symbol interposition (`llvm-nm -D`).
3. **Android module** (`android/` in this package, autolinked): `build.gradle` (library, namespace
   `io.enigm.crypto`, `newArchEnabled` required), `CMakeLists.txt` building the shared JSI C++ against
   `ReactAndroid::jsi` (prefab) and linking the prebuilt `.so`, and a Kotlin `EnigmCryptoModule`
   TurboModule that installs the binding on the JS runtime. For React Native 0.77 confirm the exact
   API (`TurboModuleWithJSIBindings` / `BindingsInstallerHolder`) before writing code; do not use the
   bridge (`ReactContext.getJavaScriptContextHolder`) path unless the bridgeless API is unavailable,
   and document the choice.
4. **Release packaging.** Add an `android-native` job (Ubuntu, pinned NDK) to `release.yml` and
   `publish.yml` that runs the shared vectors, builds all ABIs, uploads `android/src/main/jniLibs`, and
   make the packing job require it exactly like `ios-native`. Add `android/` paths to `files`.
5. **R8/ProGuard.** Keep rule for the module class if the app minifies.

## 3. Test plan and acceptance

| # | Test | Where | Pass criteria |
| --- | --- | --- | --- |
| 1 | Shared JS→Rust vectors | Linux host (`npm run test:native`) | All groups pass (already in CI). |
| 2 | Cross-compiled vectors | `cargo ndk test` is not possible on host; instead run the vector binary on the emulator via `adb shell` (built with `--tests`) | Same 7 test groups pass on arm64 device and x86_64 emulator. |
| 3 | Exported symbols / alignment | `llvm-nm -D`, `llvm-readelf -l` | Only `enigm_*` exported; LOAD segments aligned to 16 KB. |
| 4 | Autolink + build | Mobile app debug and release builds | `EnigmCrypto` listed by autolinking; no duplicate-symbol or JNI load errors. |
| 5 | Engine selection | Device console (`cryptoBackend()`) | `'native'`; self-test < 20 ms. |
| 6 | Cross-engine bytes | Device console, script equivalent to iOS `cross.js` | With fixed entropy, identity/bundle/envelope bytes identical to the JS engine; each engine opens the other's envelopes. |
| 7 | Rejections | Device console | Tampered envelope → `Envelope signature is invalid.`; GCM tag → `aes-gcm: invalid tag`; X25519 low order → rejected; expanded key → `KEY_FORMAT_CHANGED`; wrong seed → `KEY_MISMATCH`. |
| 8 | Fallback | Build without the module | `cryptoBackend() === 'js'`, one development warning, identical results, no warning in release. |
| 9 | Performance | Physical arm64 device, debug and release | 25 × `open` and `seal` measured against the JS engine and recorded here; target ≥ 50x improvement. |
| 10 | Stability | Device | 10 000 open/seal iterations without crash or memory growth; app background/foreground and JS reload keep the binding usable (a reload creates a new runtime and reinstalls). |
| 11 | App flows | Mobile on Android | Login, device-key rotation from the expanded format, send/receive 1:1 and group, attachments, calls key exchange, profile open — all with the native engine. |

Record results (device model, Android version, build type, numbers) in this file and in the
mobile acceptance notes. Mocked tests or iOS evidence do not count for Android acceptance.

## 4. Migration

- **Keys:** none beyond what iOS already requires. Seeds are platform independent; Android devices
  holding expanded keys rotate through the same Mobile logic (`KEY_FORMAT_CHANGED` → new identity
  with `keyVersion + 1`).
- **Package consumers:** none. Apps update `@enigm/crypto` and rebuild; no JS changes.
- **Data lifecycle:** the native engine stores nothing. No new retention, export or deletion surface.

## 5. Open questions to resolve on the Linux machine

- Exact RN 0.77 Android API for installing JSI bindings from a TurboModule without codegen.
- Whether Hermes on Android guarantees a stable `ArrayBuffer` data pointer for the duration of a
  synchronous host call (expected yes; verify under GC pressure in test 10).
- Whether 32-bit `armeabi-v7a` is still shipped; if not, drop it to reduce size.
