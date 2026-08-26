import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type PrivateIdentity, type PrivateKemBundle, type PublicIdentity, type PublicKemBundle, type RandomSource } from './types.js';
import { clone, equal, frame, wipe } from './bytes.js';
import { signHybrid, verifyHybrid } from './identity.js';
import { kemBundleTranscript } from './transcript.js';

const kemKeyId = (mlKemPublicKey: Uint8Array, x25519PublicKey: Uint8Array): Uint8Array =>
  sha256(frame(new TextEncoder().encode('enigm-kem-key-v2'), mlKemPublicKey, x25519PublicKey));

export const generateKemBundle = (
  identity: PrivateIdentity,
  expiresAt: number,
  randomSource: RandomSource = randomBytes,
): PrivateKemBundle => {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) {
    throw new Error('KEM bundle expiration must be in the future.');
  }
  const mlKemSeed = randomSource(64);
  const x25519Seed = randomSource(32);
  try {
    const mlKem = ml_kem768.keygen(mlKemSeed);
    const classical = x25519.keygen(x25519Seed);
    const unsigned = {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      keyId: kemKeyId(mlKem.publicKey, classical.publicKey),
      mlKemPublicKey: clone(mlKem.publicKey),
      x25519PublicKey: clone(classical.publicKey),
      identityKeyId: identity.keyId,
      expiresAt,
    } as const;
    return {
      ...unsigned,
      mlKemSecretKey: clone(mlKem.secretKey),
      x25519SecretKey: clone(classical.secretKey),
      signature: signHybrid(identity, kemBundleTranscript(unsigned)),
    };
  } finally {
    wipe(mlKemSeed, x25519Seed);
  }
};

export const publicKemBundle = (bundle: PrivateKemBundle): PublicKemBundle => ({
  version: bundle.version,
  suite: bundle.suite,
  keyId: bundle.keyId,
  mlKemPublicKey: bundle.mlKemPublicKey,
  x25519PublicKey: bundle.x25519PublicKey,
  identityKeyId: bundle.identityKeyId,
  expiresAt: bundle.expiresAt,
  signature: bundle.signature,
});

export const validatePrivateKemBundle = (bundle: PrivateKemBundle): void => {
  if (
    bundle.mlKemSecretKey.length !== ml_kem768.lengths.secretKey ||
    bundle.x25519SecretKey.length !== 32
  ) {
    throw new Error('Invalid private KEM key length.');
  }
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
  return verifyHybrid(identity, kemBundleTranscript(unsigned), signature);
};
