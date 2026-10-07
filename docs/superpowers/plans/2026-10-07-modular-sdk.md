# Modular Enigm Crypto SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Prepare a modular, autonomous TypeScript npm SDK while preserving all existing APIs, cryptographic checks and Enigm message formats.

**Architecture:** Keep one npm package with core, primitives, protocols, codecs, SDK and adapter contracts. Existing root exports remain compatible; new SDK APIs are additive. Enigm-specific contexts and wire formats form an explicitly versioned profile; consumers supply secure entropy, trust configuration and persistence/transport ports.

**Tech Stack:** TypeScript 5.9.3, Noble dependencies at their existing locked versions, Node >=20.19.0 for development, React Native/Hermes 0.77, ESM and CJS. No Swift/Kotlin or native bridges.

**Spec:** Approved modular diagram in this conversation; detailed invariants in `outputs/diseno-integracion-crypto.txt` in the parent workspace. The user subsequently confirmed TypeScript, npm and preserving all current capabilities.

## Global Constraints

- Preserve the root public exports, argument compatibility, protocol version 2 and cipher suite string.
- Preserve current v2/v3 mobile packets, stored keys/sessions and attachment plaintext-as-base64 format.
- Preserve all UTF-8 bytes, JSON transcript field order, NUL-terminated domains and initial BOM semantics.
- No TextEncoder/TextDecoder/Buffer requirement or text-polyfill global mutation in installed public entry points.
- No cryptographic dependency downgrade, weakened verification, deterministic production signatures or invented algorithms.
- No app-specific imports, endpoints, trust keys or platform storage dependencies in source SDK.
- Preserve mobile's pre-existing tracked, staged and untracked changes.
- No npm publication, tag-triggered release or merge without explicit authorization.
- Vendor integration uses the existing script and lock; do not bypass its clean/current-origin-main requirement.
- Remove mobile temporary adapters only after integration tests AND device verification of text and multimedia.

## Review Focus

1. Authenticate content before committing ratchets or consuming one-time keys; failures preserve durable state.
2. Reject altered sender/account/device binding, legacy newly attributed bootstrap and stale/revoked identity state.
3. Preserve old attachments and Unicode contexts, including invalid surrogates and NUL.
4. Import every public entry without web text APIs or Buffer; never replace or install host text globals.
5. Reject checkpoint rollback/equivocation, insufficient witness continuity and invalid consistency proofs.

### Task 1: Lock compatibility and introduce module boundaries

**Files:** `src/core/`, `src/primitives/`, `src/protocols/`, `src/codecs/`, existing `src/*.ts` facades, `src/index.ts`; `test/compatibility.test.ts`, existing protocol/runtime fixtures.

**Interfaces:** Root `@enigm/crypto` remains backward compatible. Add core, primitives, protocols, codecs and SDK barrel modules without removing current functions or types.

- [ ] Capture the existing root export names and typecheck a consumer using current key generation, envelopes, groups, ratchets and transparency APIs.
- [ ] Add compatibility fixtures for mobile message context/locator strings, identity binding transcript, stored sessions and attachment JSON. Derive fixtures from current code before extraction.
- [ ] Add failing tests for new module barrels and verify the existing protocol hash fixtures still pass.
- [ ] Move implementations by responsibility; update internal relative imports. Preserve existing source paths as re-export facades so examples/tests continue to work.
- [ ] Run `npm run check`, `npm test`, examples and protocol hash verification. Commit the independently verified reorganization.

### Task 2: Public runtime without global text polyfills

**Files:** `scripts/build.mjs`, `package.json`, `package-lock.json`, `src/text-encoder-runtime.ts` and its imports, `scripts/verify-text-runtime.mjs`, runtime fixtures, third-party license notices.

**Interfaces:** Existing root ESM/CJS/react-native conditions plus additive `./core`, `./primitives`, `./protocols`, `./codecs`, `./sdk`. Same public function signatures; declarations match each entry.

- [ ] Change cold-import regression assertions to require TextEncoder and TextDecoder to remain absent, and require native implementations to remain identical when present. Verify the new test fails on the existing fallback.
- [ ] Add packed-package consumer tests for import, require, react-native condition and public subpaths; verify no unexported dependency or dev tool is required by an installed consumer.
- [ ] Use explicitly pinned development esbuild 0.25.12 (already present transitively in the lock) to bundle public entry points and eliminate unused, PURE-annotated Noble FROST initialization. Generate declarations through tsc.
- [ ] Remove fallback imports and global installation once cold-import tests pass. Keep Noble versions fixed and preserve licenses/notices for bundled code.
- [ ] Run full tests, existing protocol hashes, packed consumers and the Hermes 0.77 fixture. Document that runtime consumers use the package export map; raw TypeScript dependency imports are development inputs.
- [ ] Commit the verified build/runtime change.

### Task 3: Public Enigm messaging and attachment SDK

**Files:** `src/sdk/enigm-v2/message-types.ts`, `message-contexts.ts`, `messages.ts`, `attachments.ts`, `session-state.ts`, `src/adapters/storage.ts`, `device-keys.ts`, `src/sdk/index.ts`; SDK compatibility and transaction tests.

**Interfaces:** `createEnigmMessageClient(options)` returns `encryptMessage(input)`, `decryptMessage(input)` and `needsMessageSession(input)` using the exact current mobile packet/target/input fields. Ports expose secure key access and exclusive read/write transactions; they do not implement encryption or protocol policy. Attachment APIs preserve current version/nonce/ciphertext JSON and base64 file keys.

- [ ] Define portable types from current MessageCryptoEnigmV2 and MessagingCryptoEnigmV2 without importing mobile aliases, GraphQL types, Keychain or quick-crypto.
- [ ] Write failing tests for sender-local packets, bootstrap, established sessions, historical recovery, duplicate targets, missing bindings, wrong context and legacy attribution rejection.
- [ ] Add failure tests proving malformed ciphertext, failed persistence and failed bootstrap never advance durable state or consume a prekey. Verify complete old-message decoding before moving logic.
- [ ] Extract contexts/locators, message packet policy, ratchet/recovery operations, codecs and secret wiping into source. Host adapters perform storage I/O and exclusion only; keep existing stored schema versions and limits.
- [ ] Add explicit RandomSource propagation through ML-DSA signing and its calling protocols while preserving default old signatures. Validate entropy length and wipe temporary entropy; never replace randomized signing with deterministic mode.
- [ ] Add attachment encode/decode using current base64-text plaintext and exact `enigm-crypto-v2-attachment` context. Keep file reading/writing, limits based on file paths and UI outside source.
- [ ] Test image/audio/video/document binary fixtures via their current base64 payloads, old JSON fixtures, wrong keys, nonce/ciphertext manipulation and expected integrity digests.
- [ ] Run full suite and deterministic upstream protocol hashes; commit the additive SDK.

### Task 4: Complete portable identity/transparency verification

**Files:** `src/sdk/enigm-v2/identity-binding.ts`, `transparency-proof.ts`, `transparency-state.ts`, `src/adapters/transparency.ts`; transparency compatibility tests.

**Interfaces:** `verifyEnigmIdentityBinding(input, config): void`; `createEnigmTransparencyVerifier(options).verifyIdentity(input): Promise<WitnessVerification>`. Inputs retain mobile proof fields; config supplies log key/origin/witnesses/quorum/clock. Host ports provide exclusive secure state persistence and fetched consistency proof data.

- [ ] Capture current binding transcripts and mobile proof fixtures before extraction. Test account/device relabeling and canonical fixed-length encodings.
- [ ] Add failing tests for altered event payload, wrong log signature/inclusion, invalid anchor, revoked state, malformed membership path and oversized proofs.
- [ ] Add failing tests for rollback, equivocation, invalid consistency, missing witness continuity, duplicate witnesses, trust capacity and failed state persistence.
- [ ] Move signature/hash/proof verification and checkpoint acceptance policy into source. Preserve error codes and all current thresholds. Host retains fetch timeout/auth headers and secure persistence only.
- [ ] Run source suite and existing mobile fixtures against source in an isolated test harness; commit verified extraction.

### Task 5: Prepare package and documentation for external consumers

**Files:** `package.json`, README, `docs/SDK.md`, `docs/ADAPTERS.md`, `docs/REACT-NATIVE.md`, NOTICE/license material, portable examples, CI/release workflows, package-consumer tests.

**Interfaces:** Document root and modular imports, pure byte contracts, adapter lifetimes/transactions, supported runtimes and Enigm versioned profile. No npm publish is executed.

- [ ] Add clean tarball-consumer tests for ESM/CJS/types with no application code or dev dependencies present.
- [ ] Add accurate repository/homepage/bugs/public-access metadata. Keep Apache-2.0 and existing security maturity disclosure. Choose a prerelease version after API coverage is verified, not by pretending stability.
- [ ] Keep package allowlist explicit; exclude internal plans, scratch fixtures and private data while retaining public docs, examples, required runtime artifacts and licensing.
- [ ] Document a working SDK example with in-memory adapters clearly labelled unsuitable for production secrets, plus React Native secure-adapter guidance.
- [ ] Extend CI with runtime and tarball consumer checks; preserve pinned actions and provenance/SBOM workflow. Document npm publishing setup as a later authorized action.
- [ ] Run check, complete tests, examples, build, runtime checks, actual Hermes, pack reproducibility, dry-run, audits and signatures. Request independent code review; fix actionable findings.
- [ ] Prepare local commits, reviewable patch/PR material and an explicit readiness report separating source readiness from mobile/device verification and registry publication.

### Task 6: Mobile integration and final acceptance

**Files:** Existing mobile crypto wrappers, platform adapters, firebase attachment functions, device-transfer UTF-8 callers, vendor and lock, installed dependency and relevant tests. Inspect fresh git status before each edit.

**Interfaces:** Mobile wrappers keep their current exports/call sites and delegate to public SDK APIs. Secure platform ports remain in mobile; SDK owns protocol behavior.

- [ ] Preserve a baseline of unrelated mobile changes; apply only scoped modifications without resetting/staging those changes.
- [ ] Once source is reviewed and integrated into origin/main with authorization, build its clean checkout and run `manage-enigm-crypto-vendor.mjs sync --source PATH`. Install using the repo's yarn 1.22.22 workflow and verify both vendor and installed payload with the script.
- [ ] Migrate MessageCrypto and KeyTransparency wrappers; retain Keychain, native entropy, backend/auth transport, file I/O and UI as explicit host adapters. Migrate all remaining global text API callers, including device-transfer and multimedia.
- [ ] Run relevant mobile tests, typecheck, lint and iOS bundle; report unrelated pre-existing failures separately.
- [ ] Verify cold start, send/read Unicode text, existing messages, recovery and image/audio/video/document attachments on device; do not treat earlier workaround success as SDK verification.
- [ ] Only after those checks and user-confirmed device verification, remove temporary text adapters and their index.js initialization. Repeat cold-start/bundle checks and integrity verification.
- [ ] Report pending publishing separately; never publish or merge as an automatic consequence of preparation.

## Completion boundary

Tasks 1–5 prepare the source package. Task 6 completes the requested integration, subject to current-main source availability and real-device confirmation. A working source tarball alone is not proof that mobile integration or npm publication has occurred.

## Execution method

Recommended: native execution in this chat, with an independent whole-branch review. The tasks share protocol and transaction contracts, so one implementer preserves continuity; the review provides a separate security check. Await the user's plan review and execution-method selection before implementation, as required by the planning skill.
