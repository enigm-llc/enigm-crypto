import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type HybridSignature, type PrivateIdentity, type PublicIdentity, type RandomSource } from './types.js';
import { clone, concat, equal, frame, wipe } from './bytes.js';
import { identityTranscript } from './transcript.js';

const ML_DSA_CONTEXT = new TextEncoder().encode('Enigm-PQ-V2-Identity');

export const identityKeyId = (mlDsaPublicKey: Uint8Array, ed25519PublicKey: Uint8Array): Uint8Array =>
  sha256(identityTranscript(mlDsaPublicKey, ed25519PublicKey));

export const generateIdentity = (randomSource: RandomSource = randomBytes): PrivateIdentity => {
  const mlDsaSeed = randomSource(32);
  const ed25519Seed = randomSource(32);
  try {
    const mlDsa = ml_dsa65.keygen(mlDsaSeed);
    const classical = ed25519.keygen(ed25519Seed);
    const keyId = identityKeyId(mlDsa.publicKey, classical.publicKey);
    return {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      keyId,
      mlDsaPublicKey: clone(mlDsa.publicKey),
      mlDsaSecretKey: clone(mlDsa.secretKey),
      ed25519PublicKey: clone(classical.publicKey),
      ed25519SecretKey: clone(classical.secretKey),
    };
  } finally {
    wipe(mlDsaSeed, ed25519Seed);
  }
};

export const publicIdentity = (identity: PrivateIdentity): PublicIdentity => ({
  version: identity.version,
  suite: identity.suite,
  keyId: clone(identity.keyId),
  mlDsaPublicKey: clone(identity.mlDsaPublicKey),
  ed25519PublicKey: clone(identity.ed25519PublicKey),
});

export const signHybrid = (identity: PrivateIdentity, message: Uint8Array): HybridSignature => {
  validatePrivateIdentity(identity);
  const transcript = frame(new TextEncoder().encode('enigm-hybrid-signature-v2'), message);
  return {
    mlDsa: ml_dsa65.sign(transcript, identity.mlDsaSecretKey, { context: ML_DSA_CONTEXT }),
    ed25519: ed25519.sign(transcript, identity.ed25519SecretKey),
  };
};

export const verifyHybrid = (
  identity: PublicIdentity,
  message: Uint8Array,
  signature: HybridSignature,
): boolean => {
  try {
    validatePublicIdentity(identity);
    if (
      signature.mlDsa.length !== ml_dsa65.lengths.signature ||
      signature.ed25519.length !== 64
    ) {
      return false;
    }
    const transcript = frame(new TextEncoder().encode('enigm-hybrid-signature-v2'), message);
    return (
      ml_dsa65.verify(signature.mlDsa, transcript, identity.mlDsaPublicKey, {
        context: ML_DSA_CONTEXT,
      }) && ed25519.verify(signature.ed25519, transcript, identity.ed25519PublicKey, { zip215: false })
    );
  } catch {
    return false;
  }
};

export const validatePublicIdentity = (identity: PublicIdentity): void => {
  if (identity.version !== PROTOCOL_VERSION || identity.suite !== CIPHER_SUITE) {
    throw new Error('Unsupported identity cipher suite.');
  }
  if (
    identity.keyId.length !== 32 ||
    identity.mlDsaPublicKey.length !== ml_dsa65.lengths.publicKey ||
    identity.ed25519PublicKey.length !== 32
  ) {
    throw new Error('Invalid identity key length.');
  }
  const expected = identityKeyId(identity.mlDsaPublicKey, identity.ed25519PublicKey);
  if (!equal(expected, identity.keyId)) throw new Error('Identity key identifier mismatch.');
};

export const validatePrivateIdentity = (identity: PrivateIdentity): void => {
  validatePublicIdentity(identity);
  if (
    identity.mlDsaSecretKey.length !== ml_dsa65.lengths.secretKey ||
    identity.ed25519SecretKey.length !== 32
  ) {
    throw new Error('Invalid private identity key length.');
  }
};

export const identityFingerprint = (identity: PublicIdentity): Uint8Array => {
  validatePublicIdentity(identity);
  return sha256(concat(identity.keyId, identity.mlDsaPublicKey, identity.ed25519PublicKey));
};
