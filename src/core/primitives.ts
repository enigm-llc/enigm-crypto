/**
 * Drop-in, @noble-shaped entry points for standard primitives, routed through the active
 * engine (`./engine.ts`). Protocol code imports these instead of @noble so the same logic runs
 * natively on React Native and in @noble elsewhere, with byte-identical results.
 *
 * Only the shapes the protocols use are provided. Parameters outside the native fast path
 * (AES key ≠ 32 bytes, nonce ≠ 12 bytes, HMAC/HKDF over another hash) use @noble directly.
 */
import { gcm as nobleGcm } from '@noble/ciphers/aes.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';

import { engine } from './engine.js';

type Hash = ((data: Uint8Array) => Uint8Array) & { readonly outputLen: number; readonly blockLen: number };

export const sha256: Hash = Object.assign((data: Uint8Array) => engine().sha256(data), {
  outputLen: 32,
  blockLen: 64,
});

export const sha512: Hash = Object.assign((data: Uint8Array) => engine().sha512(data), {
  outputLen: 64,
  blockLen: 128,
});

const nobleHashOf = (hash: Hash) => (hash === sha512 ? nobleSha512 : nobleSha256);

export const hmac = (hash: Hash, key: Uint8Array, message: Uint8Array): Uint8Array =>
  hash === sha512 ? engine().hmacSha512(key, message) : nobleHmac(nobleHashOf(hash), key, message);

export const hkdf = (
  hash: Hash,
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array | undefined,
  length: number,
): Uint8Array =>
  hash === sha512
    ? engine().hkdfSha512(ikm, salt ?? new Uint8Array(0), info ?? new Uint8Array(0), length)
    : nobleHkdf(nobleHashOf(hash), ikm, salt, info, length);

export const gcm = (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array = new Uint8Array(0)) => {
  if (key.length !== 32 || nonce.length !== 12) return nobleGcm(key, nonce, aad);
  return {
    encrypt: (plaintext: Uint8Array): Uint8Array => engine().aes256GcmEncrypt(key, nonce, aad, plaintext),
    decrypt: (ciphertext: Uint8Array): Uint8Array => engine().aes256GcmDecrypt(key, nonce, aad, ciphertext),
  };
};

/** Same ownership as @noble: `keygen(seed)` returns the seed itself as `secretKey`. */
export const x25519 = Object.freeze({
  keygen: (seed: Uint8Array) => ({ secretKey: seed, publicKey: engine().x25519PublicKey(seed) }),
  getPublicKey: (secretKey: Uint8Array) => engine().x25519PublicKey(secretKey),
  getSharedSecret: (secretKey: Uint8Array, publicKey: Uint8Array) => engine().x25519SharedSecret(secretKey, publicKey),
});

/** Same ownership as @noble: `keygen(seed)` returns the seed itself as `secretKey`. */
export const ed25519 = Object.freeze({
  keygen: (seed: Uint8Array) => ({ secretKey: seed, publicKey: engine().ed25519PublicKey(seed) }),
  getPublicKey: (secretKey: Uint8Array) => engine().ed25519PublicKey(secretKey),
  sign: (message: Uint8Array, secretKey: Uint8Array) => engine().ed25519Sign(secretKey, message),
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, _options?: { zip215: false }) =>
    engine().ed25519Verify(publicKey, message, signature),
});
