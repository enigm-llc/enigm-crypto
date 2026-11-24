import { gcm } from '@noble/ciphers/aes.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { equal, wipe } from './bytes.js';
import { EnigmKeyError } from './errors.js';

/** Which implementation runs the cryptographic primitives. */
export type CryptoBackend = 'native' | 'js';

/**
 * The primitives behind every protocol. Protocol logic, transcripts, validation and error
 * semantics stay in TypeScript; an engine only computes these standard operations. Both engines
 * must return byte-identical results and reject exactly the same inputs (shared vectors in CI).
 *
 * Private keys are seeds (FIPS 203 `d‖z`, FIPS 204 `ξ`, RFC 8032/7748 32-byte secrets).
 * Operations that expand a post-quantum seed also receive the stored public key and fail with
 * `KEY_MISMATCH` if the seed does not derive it.
 */
export interface PrimitiveEngine {
  readonly backend: CryptoBackend;
  mlDsa65PublicKey(seed: Uint8Array): Uint8Array;
  mlDsa65Sign(
    seed: Uint8Array,
    expectedPublicKey: Uint8Array,
    message: Uint8Array,
    context: Uint8Array,
    entropy: Uint8Array,
  ): Uint8Array;
  mlDsa65Verify(publicKey: Uint8Array, message: Uint8Array, context: Uint8Array, signature: Uint8Array): boolean;
  mlKem768PublicKey(seed: Uint8Array): Uint8Array;
  mlKem768Encapsulate(publicKey: Uint8Array, entropy: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  mlKem768Decapsulate(seed: Uint8Array, expectedPublicKey: Uint8Array, cipherText: Uint8Array): Uint8Array;
  /** RFC 8032 / FIPS 186-5 strict verification with small-order public keys rejected. */
  ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
  ed25519PublicKey(seed: Uint8Array): Uint8Array;
  /** RFC 8032 deterministic signature. */
  ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
  x25519PublicKey(secret: Uint8Array): Uint8Array;
  /** RFC 7748; rejects low-order public keys (`invalid private or public key received`). */
  x25519SharedSecret(secret: Uint8Array, publicKey: Uint8Array): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  sha512(data: Uint8Array): Uint8Array;
  hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array;
  hkdfSha512(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  /** AES-256-GCM, 96-bit nonce: ciphertext ‖ 16-byte tag. */
  aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** Throws `aes-gcm: invalid tag` when authentication fails. */
  aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

export const ML_DSA65_SEED_BYTES = 32;
export const ML_KEM768_SEED_BYTES = 64;
const ML_KEM768_CIPHERTEXT_BYTES = 1088;
const GCM_TAG_ERROR = 'aes-gcm: invalid tag';
const X25519_ERROR = 'invalid private or public key received';

const keyMismatch = (): never => {
  throw new EnigmKeyError('KEY_MISMATCH', 'Private key seed does not match its public key.');
};

export const jsEngine: PrimitiveEngine = Object.freeze<PrimitiveEngine>({
  backend: 'js' as const,
  mlDsa65PublicKey: (seed: Uint8Array) => {
    const keys = ml_dsa65.keygen(seed);
    wipe(keys.secretKey);
    return keys.publicKey;
  },
  mlDsa65Sign: (seed, expectedPublicKey, message, context, entropy) => {
    const keys = ml_dsa65.keygen(seed);
    try {
      if (!equal(keys.publicKey, expectedPublicKey)) keyMismatch();
      return ml_dsa65.sign(message, keys.secretKey, { context, extraEntropy: entropy });
    } finally {
      wipe(keys.secretKey);
    }
  },
  mlDsa65Verify: (publicKey, message, context, signature) =>
    ml_dsa65.verify(signature, message, publicKey, { context }),
  mlKem768PublicKey: (seed: Uint8Array) => {
    const keys = ml_kem768.keygen(seed);
    wipe(keys.secretKey);
    return keys.publicKey;
  },
  mlKem768Encapsulate: (publicKey, entropy) => ml_kem768.encapsulate(publicKey, entropy),
  mlKem768Decapsulate: (seed, expectedPublicKey, cipherText) => {
    const keys = ml_kem768.keygen(seed);
    try {
      if (!equal(keys.publicKey, expectedPublicKey)) keyMismatch();
      return ml_kem768.decapsulate(cipherText, keys.secretKey);
    } finally {
      wipe(keys.secretKey);
    }
  },
  ed25519Verify: (publicKey, message, signature) => {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
  ed25519PublicKey: (seed) => ed25519.getPublicKey(seed),
  ed25519Sign: (seed, message) => ed25519.sign(message, seed),
  x25519PublicKey: (secret) => x25519.getPublicKey(secret),
  x25519SharedSecret: (secret, publicKey) => x25519.getSharedSecret(secret, publicKey),
  sha256: (data) => sha256(data),
  sha512: (data) => sha512(data),
  hmacSha512: (key, message) => hmac(sha512, key, message),
  hkdfSha512: (ikm, salt, info, length) => hkdf(sha512, ikm, salt, info, length),
  aes256GcmEncrypt: (key, nonce, aad, plaintext) => gcm(key, nonce, aad).encrypt(plaintext),
  aes256GcmDecrypt: (key, nonce, aad, ciphertext) => gcm(key, nonce, aad).decrypt(ciphertext),
});

/**
 * Native binding installed by the React Native module (JSI, synchronous, zero-copy typed
 * arrays). The ABI version is checked so a stale binary is never used with this library.
 */
const NATIVE_ABI_VERSION = 2;
type NativeBinding = {
  readonly abiVersion: typeof NATIVE_ABI_VERSION;
  mlDsa65PublicKey(seed: Uint8Array): ArrayBuffer;
  mlDsa65Sign(seed: Uint8Array, expectedPublicKey: Uint8Array, message: Uint8Array, context: Uint8Array, entropy: Uint8Array): ArrayBuffer;
  mlDsa65Verify(publicKey: Uint8Array, message: Uint8Array, context: Uint8Array, signature: Uint8Array): boolean;
  mlKem768PublicKey(seed: Uint8Array): ArrayBuffer;
  mlKem768Encapsulate(publicKey: Uint8Array, entropy: Uint8Array): ArrayBuffer;
  mlKem768Decapsulate(seed: Uint8Array, expectedPublicKey: Uint8Array, cipherText: Uint8Array): ArrayBuffer;
  ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
  ed25519PublicKey(seed: Uint8Array): ArrayBuffer;
  ed25519Sign(seed: Uint8Array, message: Uint8Array): ArrayBuffer;
  x25519PublicKey(secret: Uint8Array): ArrayBuffer;
  x25519SharedSecret(secret: Uint8Array, publicKey: Uint8Array): ArrayBuffer;
  sha256(data: Uint8Array): ArrayBuffer;
  sha512(data: Uint8Array): ArrayBuffer;
  hmacSha512(key: Uint8Array, message: Uint8Array): ArrayBuffer;
  hkdfSha512(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): ArrayBuffer;
  aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): ArrayBuffer;
  aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): ArrayBuffer;
};
const BINDING_FUNCTIONS = [
  'mlDsa65PublicKey', 'mlDsa65Sign', 'mlDsa65Verify', 'mlKem768PublicKey', 'mlKem768Encapsulate',
  'mlKem768Decapsulate', 'ed25519Verify', 'ed25519PublicKey', 'ed25519Sign', 'x25519PublicKey',
  'x25519SharedSecret', 'sha256', 'sha512', 'hmacSha512', 'hkdfSha512', 'aes256GcmEncrypt', 'aes256GcmDecrypt',
] as const;

const NATIVE_GLOBAL = '__enigmCryptoNative';
const NATIVE_MODULE = 'EnigmCrypto';

/**
 * Native errors carry a fixed code only; map it to the error the JS engine raises:
 * key mismatch → `EnigmKeyError`, rejection (GCM tag / X25519 low order) → the given message.
 */
const nativeCall = <T>(operation: () => T, rejected = 'Native cryptographic operation rejected its input.'): T => {
  try {
    return operation();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('ENIGM_NATIVE_KEY_MISMATCH')) keyMismatch();
    if (message.includes('ENIGM_NATIVE_REJECTED')) throw new Error(rejected);
    throw new Error('Native cryptographic operation rejected its input.');
  }
};

const bytesOf = (buffer: ArrayBuffer): Uint8Array => new Uint8Array(buffer);

const nativeEngine = (binding: NativeBinding): PrimitiveEngine =>
  Object.freeze<PrimitiveEngine>({
    backend: 'native' as const,
    mlDsa65PublicKey: (seed) => nativeCall(() => bytesOf(binding.mlDsa65PublicKey(seed))),
    mlDsa65Sign: (seed, expectedPublicKey, message, context, entropy) =>
      nativeCall(() => bytesOf(binding.mlDsa65Sign(seed, expectedPublicKey, message, context, entropy))),
    mlDsa65Verify: (publicKey, message, context, signature) =>
      nativeCall(() => binding.mlDsa65Verify(publicKey, message, context, signature) === true),
    mlKem768PublicKey: (seed) => nativeCall(() => bytesOf(binding.mlKem768PublicKey(seed))),
    mlKem768Encapsulate: (publicKey, entropy) =>
      nativeCall(() => {
        const output = bytesOf(binding.mlKem768Encapsulate(publicKey, entropy));
        if (output.length !== ML_KEM768_CIPHERTEXT_BYTES + 32) throw new Error('length');
        const result = { cipherText: output.slice(0, ML_KEM768_CIPHERTEXT_BYTES), sharedSecret: output.slice(ML_KEM768_CIPHERTEXT_BYTES) };
        wipe(output);
        return result;
      }),
    mlKem768Decapsulate: (seed, expectedPublicKey, cipherText) =>
      nativeCall(() => bytesOf(binding.mlKem768Decapsulate(seed, expectedPublicKey, cipherText))),
    ed25519Verify: (publicKey, message, signature) => {
      try {
        return binding.ed25519Verify(publicKey, message, signature) === true;
      } catch {
        return false;
      }
    },
    ed25519PublicKey: (seed) => nativeCall(() => bytesOf(binding.ed25519PublicKey(seed))),
    ed25519Sign: (seed, message) => nativeCall(() => bytesOf(binding.ed25519Sign(seed, message))),
    x25519PublicKey: (secret) => nativeCall(() => bytesOf(binding.x25519PublicKey(secret)), X25519_ERROR),
    x25519SharedSecret: (secret, publicKey) =>
      nativeCall(() => bytesOf(binding.x25519SharedSecret(secret, publicKey)), X25519_ERROR),
    sha256: (data) => nativeCall(() => bytesOf(binding.sha256(data))),
    sha512: (data) => nativeCall(() => bytesOf(binding.sha512(data))),
    hmacSha512: (key, message) => nativeCall(() => bytesOf(binding.hmacSha512(key, message))),
    hkdfSha512: (ikm, salt, info, length) => nativeCall(() => bytesOf(binding.hkdfSha512(ikm, salt, info, length))),
    aes256GcmEncrypt: (key, nonce, aad, plaintext) =>
      nativeCall(() => bytesOf(binding.aes256GcmEncrypt(key, nonce, aad, plaintext))),
    aes256GcmDecrypt: (key, nonce, aad, ciphertext) =>
      nativeCall(() => bytesOf(binding.aes256GcmDecrypt(key, nonce, aad, ciphertext)), GCM_TAG_ERROR),
  });

type HostGlobal = typeof globalThis & {
  __turboModuleProxy?: (name: string) => unknown;
  nativeModuleProxy?: Record<string, unknown>;
  HermesInternal?: unknown;
  __DEV__?: boolean;
  navigator?: { product?: string };
  [NATIVE_GLOBAL]?: unknown;
};

const isReactNative = (host: HostGlobal): boolean =>
  host.navigator?.product === 'ReactNative' || host.HermesInternal !== undefined;

/** Requesting the TurboModule makes React Native install its JSI binding on this runtime. */
const requestNativeBinding = (host: HostGlobal): unknown => {
  if (host[NATIVE_GLOBAL] !== undefined) return host[NATIVE_GLOBAL];
  try {
    if (typeof host.__turboModuleProxy === 'function') host.__turboModuleProxy(NATIVE_MODULE);
    else void host.nativeModuleProxy?.[NATIVE_MODULE];
  } catch {
    // Missing module: handled below as JS fallback.
  }
  return host[NATIVE_GLOBAL];
};

const isBinding = (value: unknown): value is NativeBinding =>
  typeof value === 'object' &&
  value !== null &&
  (value as { abiVersion?: unknown }).abiVersion === NATIVE_ABI_VERSION &&
  BINDING_FUNCTIONS.every((name) => typeof (value as Record<string, unknown>)[name] === 'function');

/**
 * Known-answer self-test before a native engine is trusted. Expected values were produced by
 * the JS engine (@noble) for these fixed inputs, so the check costs only native work and a
 * few hashes; it also requires rejection of a modified ML-DSA and Ed25519 signature.
 */
const KAT = {
  mlDsaPublicKeySha256: 'd3a1e51ecf491b79ca7691bd269271f8d8e8d94313a6abcc6c8ae8bc34b5f9aa',
  mlKemPublicKeySha256: '99e97dc2aaa8cb2048bbd784634a990a80afe28df11fa9141cb3609aad581a27',
  mlDsaSignatureSha256: '244d678feff72cbb538fa083c2e8c45aef1bc1a45fa979a102c386282a3508ad',
  mlKemCipherTextSha256: 'bf72398b30305acc0891b6d30b4b59af0989c40e7a8202ee1f95e1a7e39b5972',
  mlKemSharedSecret: '972522ce4ae6b0b8b78c33cac9b937a829778bd3afc1fe49b6790070c0e954b5',
  ed25519PublicKey: 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c',
  ed25519Signature:
    '83998e719947612d0e82d427472c685a64b14d9aea67968cbcc39733f27376f3b8ea9858c24e061feb8bcdefce93aa921a6bc8ee1cab17f68d5d1ffc0dc2d800',
  sha256: '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
  sha512Sha256: '91dd3ca2a0316c363683ea417546817d311ce8be80f81a4ded31603a5c73904e',
  hmacSha512Sha256: '8ac8f7378bcb1b7336170b4004a788e6f2949c21f77df0ad65c96bb0ee3a3976',
  hkdfSha512: '34d7e517746e0ae9ce8d557baf6181a822f6f433ef09480dbb52ad6d07ddb0e3468efdf1c3741c22',
  aes256Gcm: 'e3f3840076bbe5c4e0cc5bc908aa7c7b8c4a4c',
  x25519PublicKey: '13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d',
  x25519SharedSecret: '2ffe325b2a26611bf1911325d4a62b33749b8f350d0e88ba91e316acaae66554',
} as const;

const throws = (operation: () => unknown): boolean => {
  try {
    operation();
    return false;
  } catch {
    return true;
  }
};

const hex = (value: Uint8Array): string => {
  let output = '';
  for (const byte of value) output += byte.toString(16).padStart(2, '0');
  return output;
};

const fromHex = (value: string): Uint8Array => {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return output;
};

const selfTest = (candidate: PrimitiveEngine): boolean => {
  try {
    const dsaSeed = new Uint8Array(32).fill(7);
    const kemSeed = new Uint8Array(64).fill(9);
    const message = new Uint8Array([1, 2, 3]);
    const context = new Uint8Array([4, 5]);
    const entropy = new Uint8Array(32).fill(3);
    const dsaPublic = candidate.mlDsa65PublicKey(dsaSeed);
    const kemPublic = candidate.mlKem768PublicKey(kemSeed);
    if (hex(sha256(dsaPublic)) !== KAT.mlDsaPublicKeySha256) return false;
    if (hex(sha256(kemPublic)) !== KAT.mlKemPublicKeySha256) return false;
    const signature = candidate.mlDsa65Sign(dsaSeed, dsaPublic, message, context, entropy);
    if (hex(sha256(signature)) !== KAT.mlDsaSignatureSha256) return false;
    if (!candidate.mlDsa65Verify(dsaPublic, message, context, signature)) return false;
    signature[0] = (signature[0] ?? 0) ^ 1;
    if (candidate.mlDsa65Verify(dsaPublic, message, context, signature)) return false;
    const encapsulated = candidate.mlKem768Encapsulate(kemPublic, entropy);
    if (hex(sha256(encapsulated.cipherText)) !== KAT.mlKemCipherTextSha256) return false;
    if (hex(encapsulated.sharedSecret) !== KAT.mlKemSharedSecret) return false;
    if (hex(candidate.mlKem768Decapsulate(kemSeed, kemPublic, encapsulated.cipherText)) !== KAT.mlKemSharedSecret) return false;
    if (hex(candidate.ed25519PublicKey(dsaSeed)) !== KAT.ed25519PublicKey) return false;
    const edSignature = candidate.ed25519Sign(dsaSeed, message);
    if (hex(edSignature) !== KAT.ed25519Signature) return false;
    const edPublic = fromHex(KAT.ed25519PublicKey);
    if (!candidate.ed25519Verify(edPublic, message, edSignature)) return false;
    edSignature[63] = (edSignature[63] ?? 0) ^ 1;
    if (candidate.ed25519Verify(edPublic, message, edSignature)) return false;
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(12).fill(5);
    const aad = new Uint8Array([4, 5]);
    if (hex(candidate.sha256(message)) !== KAT.sha256) return false;
    if (hex(sha256(candidate.sha512(message))) !== KAT.sha512Sha256) return false;
    if (hex(sha256(candidate.hmacSha512(key, message))) !== KAT.hmacSha512Sha256) return false;
    if (hex(candidate.hkdfSha512(key, message, aad, 40)) !== KAT.hkdfSha512) return false;
    const sealed = candidate.aes256GcmEncrypt(key, nonce, aad, message);
    if (hex(sealed) !== KAT.aes256Gcm) return false;
    if (hex(candidate.aes256GcmDecrypt(key, nonce, aad, sealed)) !== hex(message)) return false;
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 1;
    if (!throws(() => candidate.aes256GcmDecrypt(key, nonce, aad, sealed))) return false;
    if (hex(candidate.x25519PublicKey(key)) !== KAT.x25519PublicKey) return false;
    const other = candidate.x25519PublicKey(new Uint8Array(32).fill(9));
    if (hex(candidate.x25519SharedSecret(key, other)) !== KAT.x25519SharedSecret) return false;
    return throws(() => candidate.x25519SharedSecret(key, new Uint8Array(32)));
  } catch {
    return false;
  }
};

const warnInDevelopment = (host: HostGlobal, reason: string): void => {
  if (host.__DEV__ !== true) return;
  // Development-only diagnostic; production falls back silently with identical results.
  console.warn(
    `[@enigm/crypto] ${reason} Using the JavaScript engine: results are identical, but ` +
      'post-quantum operations are roughly 100–500x slower on Hermes. Rebuild the native app ' +
      '(cd ios && pod install, or a fresh Gradle build) so the EnigmCrypto module is linked, ' +
      'then check cryptoBackend() === "native".',
  );
};

let selected: PrimitiveEngine | undefined;
let override: PrimitiveEngine | undefined;

const select = (): PrimitiveEngine => {
  const host = globalThis as HostGlobal;
  if (!isReactNative(host)) return jsEngine;
  const binding = requestNativeBinding(host);
  if (!isBinding(binding)) {
    warnInDevelopment(host, 'The EnigmCrypto native module is not linked in this app.');
    return jsEngine;
  }
  const candidate = nativeEngine(binding);
  if (!selfTest(candidate)) {
    warnInDevelopment(host, 'The EnigmCrypto native module failed its known-answer self-test.');
    return jsEngine;
  }
  return candidate;
};

/** The active engine, chosen once per runtime. */
export const engine = (): PrimitiveEngine => override ?? (selected ??= select());

/** Which engine runs this runtime's primitives (diagnostics and QA only). */
export const cryptoBackend = (): CryptoBackend => engine().backend;

/** @internal Test hook: force an engine, or `undefined` to restore automatic selection. */
export const setEngineForTesting = (value: PrimitiveEngine | undefined): void => {
  override = value;
};

/** @internal Test hook: discard the cached automatic selection. */
export const resetEngineSelectionForTesting = (): void => {
  selected = undefined;
};
