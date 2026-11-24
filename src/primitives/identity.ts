import { ed25519, sha256 } from '../core/primitives.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { engine, ML_DSA65_SEED_BYTES } from '../core/engine.js';
import { EnigmKeyError } from '../core/errors.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type HybridSignature, type PrivateIdentity, type PublicIdentity, type RandomSource } from '../core/types.js';
import { clone, concat, equal, frame, utf8, wipe, assertLength } from '../core/bytes.js';
import { identityTranscript } from '../protocols/transcript.js';

const ML_DSA_CONTEXT = utf8('Enigm-PQ-V2-Identity');

export const identityKeyId = (mlDsaPublicKey: Uint8Array, ed25519PublicKey: Uint8Array): Uint8Array =>
  sha256(identityTranscript(mlDsaPublicKey, ed25519PublicKey));

export const generateIdentity = (randomSource: RandomSource = randomBytes): PrivateIdentity => {
  const mlDsaSeed = randomSource(ML_DSA65_SEED_BYTES);
  const ed25519Seed = randomSource(32);
  try {
    assertLength(mlDsaSeed, ML_DSA65_SEED_BYTES, 'ML-DSA-65 seed');
    assertLength(ed25519Seed, 32, 'Ed25519 seed');
    const mlDsaPublicKey = engine().mlDsa65PublicKey(mlDsaSeed);
    const classical = ed25519.keygen(ed25519Seed);
    const keyId = identityKeyId(mlDsaPublicKey, classical.publicKey);
    return {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      keyId,
      mlDsaPublicKey,
      mlDsaSeed: clone(mlDsaSeed),
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

export const signHybrid = (identity: PrivateIdentity, message: Uint8Array, randomSource: RandomSource = randomBytes): HybridSignature => {
  validatePrivateIdentity(identity);
  const transcript = frame(utf8('enigm-hybrid-signature-v2'), message);
  const entropy = randomSource(32);
  try {
    assertLength(entropy, 32, 'ML-DSA signing entropy');
    return {
      mlDsa: engine().mlDsa65Sign(identity.mlDsaSeed, identity.mlDsaPublicKey, transcript, ML_DSA_CONTEXT, entropy),
      ed25519: ed25519.sign(transcript, identity.ed25519SecretKey),
    };
  } finally { wipe(entropy); }
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
    const transcript = frame(utf8('enigm-hybrid-signature-v2'), message);
    const primitives = engine();
    return (
      primitives.mlDsa65Verify(identity.mlDsaPublicKey, transcript, ML_DSA_CONTEXT, signature.mlDsa) &&
      primitives.ed25519Verify(identity.ed25519PublicKey, transcript, signature.ed25519)
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

/**
 * Structural check of a private identity. A key without a 32-byte ML-DSA seed (for example
 * an expanded key stored by an earlier version) fails with `KEY_FORMAT_CHANGED`: regenerate it.
 * Whether the seed derives the public key is checked at each signature (`KEY_MISMATCH`).
 */
export const validatePrivateIdentity = (identity: PrivateIdentity): void => {
  validatePublicIdentity(identity);
  const { mlDsaSeed, ed25519SecretKey } = identity as Partial<PrivateIdentity>;
  if (!(mlDsaSeed instanceof Uint8Array) || mlDsaSeed.length !== ML_DSA65_SEED_BYTES) {
    throw new EnigmKeyError('KEY_FORMAT_CHANGED', 'Private identity key format changed; generate a new identity.');
  }
  if (!(ed25519SecretKey instanceof Uint8Array) || ed25519SecretKey.length !== 32) {
    throw new Error('Invalid private identity key length.');
  }
};

export const identityFingerprint = (identity: PublicIdentity): Uint8Array => {
  validatePublicIdentity(identity);
  return sha256(concat(identity.keyId, identity.mlDsaPublicKey, identity.ed25519PublicKey));
};
