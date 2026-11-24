import { sha256, x25519 } from '../core/primitives.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type PrivateIdentity, type PrivateKemBundle, type PublicIdentity, type PublicKemBundle, type RandomSource } from '../core/types.js';
import { assertLength, clone, equal, frame, utf8, wipe } from '../core/bytes.js';
import { engine, ML_KEM768_SEED_BYTES } from '../core/engine.js';
import { EnigmKeyError } from '../core/errors.js';
import { signHybrid, verifyHybrid } from './identity.js';
import { kemBundleTranscript } from '../protocols/transcript.js';

const kemKeyId = (mlKemPublicKey: Uint8Array, x25519PublicKey: Uint8Array): Uint8Array =>
  sha256(frame(utf8('enigm-kem-key-v2'), mlKemPublicKey, x25519PublicKey));

export const generateKemBundle = (
  identity: PrivateIdentity,
  expiresAt: number,
  randomSource: RandomSource = randomBytes,
): PrivateKemBundle => {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) {
    throw new Error('KEM bundle expiration must be in the future.');
  }
  const mlKemSeed = randomSource(ML_KEM768_SEED_BYTES);
  const x25519Seed = randomSource(32);
  try {
    assertLength(mlKemSeed, ML_KEM768_SEED_BYTES, 'ML-KEM-768 seed');
    assertLength(x25519Seed, 32, 'X25519 seed');
    const mlKemPublicKey = engine().mlKem768PublicKey(mlKemSeed);
    const classical = x25519.keygen(x25519Seed);
    const unsigned = {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      keyId: kemKeyId(mlKemPublicKey, classical.publicKey),
      mlKemPublicKey: clone(mlKemPublicKey),
      x25519PublicKey: clone(classical.publicKey),
      identityKeyId: clone(identity.keyId),
      expiresAt,
    } as const;
    return {
      ...unsigned,
      mlKemSeed: clone(mlKemSeed),
      x25519SecretKey: clone(classical.secretKey),
      signature: signHybrid(identity, kemBundleTranscript(unsigned), randomSource),
    };
  } finally {
    wipe(mlKemSeed, x25519Seed);
  }
};

export const publicKemBundle = (bundle: PrivateKemBundle): PublicKemBundle => ({
  version: bundle.version,
  suite: bundle.suite,
  keyId: clone(bundle.keyId),
  mlKemPublicKey: clone(bundle.mlKemPublicKey),
  x25519PublicKey: clone(bundle.x25519PublicKey),
  identityKeyId: clone(bundle.identityKeyId),
  expiresAt: bundle.expiresAt,
  signature: {
    mlDsa: clone(bundle.signature.mlDsa),
    ed25519: clone(bundle.signature.ed25519),
  },
});

/**
 * Structural check of a private KEM bundle. A bundle without a 64-byte ML-KEM seed (for
 * example an expanded 2400-byte key from an earlier version) fails with
 * `KEY_FORMAT_CHANGED`: generate and publish a new bundle. Whether the seed derives the
 * public key is checked at each decapsulation (`KEY_MISMATCH`).
 */
export const validatePrivateKemBundle = (bundle: PrivateKemBundle): void => {
  const { mlKemSeed, x25519SecretKey } = bundle as Partial<PrivateKemBundle>;
  if (!(mlKemSeed instanceof Uint8Array) || mlKemSeed.length !== ML_KEM768_SEED_BYTES) {
    throw new EnigmKeyError('KEY_FORMAT_CHANGED', 'Private KEM key format changed; generate a new KEM bundle.');
  }
  if (!(x25519SecretKey instanceof Uint8Array) || x25519SecretKey.length !== 32) {
    throw new Error('Invalid private KEM key length.');
  }
};

/**
 * Successful bundle signature verifications, keyed by a hash of every verified byte (signer
 * public keys, signed transcript and signature). Holds no secrets. Only used with the JS
 * engine, where one hybrid verification costs far more than the lookup hash; the native
 * engine verifies directly. Expiry and structure are always checked before the cache.
 */
const VERIFIED_BUNDLES_MAX = 64;
const verifiedBundles = new Map<string, true>();

const verificationCacheKey = (identity: PublicIdentity, transcript: Uint8Array, bundle: PublicKemBundle): string => {
  const digest = sha256(
    frame(
      utf8('enigm-kem-bundle-verified-v1'),
      identity.mlDsaPublicKey,
      identity.ed25519PublicKey,
      transcript,
      bundle.signature.mlDsa,
      bundle.signature.ed25519,
    ),
  );
  let key = '';
  for (const byte of digest) key += byte.toString(16).padStart(2, '0');
  return key;
};

/** Forget cached bundle verifications (call on lock, logout or account switch). */
export const clearVerificationCache = (): void => {
  verifiedBundles.clear();
};

export const verifyKemBundle = (
  identity: PublicIdentity,
  bundle: PublicKemBundle,
  now = Date.now(),
): boolean => {
  if (
    bundle.version !== PROTOCOL_VERSION ||
    bundle.suite !== CIPHER_SUITE ||
    bundle.keyId.length !== 32 ||
    bundle.mlKemPublicKey.length !== ml_kem768.lengths.publicKey ||
    bundle.x25519PublicKey.length !== 32 ||
    bundle.identityKeyId.length !== 32 ||
    bundle.signature.mlDsa.length !== 3309 ||
    bundle.signature.ed25519.length !== 64 ||
    bundle.expiresAt <= now ||
    !equal(bundle.identityKeyId, identity.keyId) ||
    !equal(bundle.keyId, kemKeyId(bundle.mlKemPublicKey, bundle.x25519PublicKey))
  ) {
    return false;
  }
  const { signature, ...unsigned } = bundle;
  const transcript = kemBundleTranscript(unsigned);
  if (engine().backend === 'native') return verifyHybrid(identity, transcript, signature);
  const key = verificationCacheKey(identity, transcript, bundle);
  if (verifiedBundles.has(key)) {
    verifiedBundles.delete(key);
    verifiedBundles.set(key, true);
    return true;
  }
  if (!verifyHybrid(identity, transcript, signature)) return false;
  verifiedBundles.set(key, true);
  if (verifiedBundles.size > VERIFIED_BUNDLES_MAX) {
    const oldest = verifiedBundles.keys().next().value;
    if (oldest !== undefined) verifiedBundles.delete(oldest);
  }
  return true;
};
