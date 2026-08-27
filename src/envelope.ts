import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type HybridEnvelope, type OpenOptions, type SealOptions } from './types.js';
import { assertLength, clone, equal, frame, utf8, wipe } from './bytes.js';
import { signHybrid, validatePrivateIdentity, validatePublicIdentity, verifyHybrid } from './identity.js';
import { validatePrivateKemBundle, verifyKemBundle } from './kem.js';
import { envelopeAssociatedData, envelopeSignatureTranscript } from './transcript.js';

const ZERO_SALT = new Uint8Array(sha512.outputLen);
const MAX_FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1000;

const rejectZeroX25519Secret = (secret: Uint8Array): void => {
  let aggregate = 0;
  for (const byte of secret) aggregate |= byte;
  if (aggregate === 0) throw new Error('Invalid X25519 shared secret.');
};

const deriveEnvelopeKey = (
  mlKemSecret: Uint8Array,
  x25519Secret: Uint8Array,
  associatedData: Uint8Array,
  supplementalSecret?: Uint8Array,
): Uint8Array => {
  rejectZeroX25519Secret(x25519Secret);
  const input = supplementalSecret
    ? frame(mlKemSecret, x25519Secret, supplementalSecret)
    : frame(mlKemSecret, x25519Secret);
  return hkdf(
    sha512,
    input,
    sha512(frame(utf8('enigm-pq-v2-salt'), associatedData)),
    frame(utf8('enigm-pq-v2-envelope-key'), utf8(CIPHER_SUITE), associatedData),
    32,
  );
};

export const seal = (options: SealOptions): HybridEnvelope => {
  const now = options.now ?? Date.now();
  validatePrivateIdentity(options.sender);
  validatePublicIdentity(options.recipientIdentity);
  if (!verifyKemBundle(options.recipientIdentity, options.recipient, now)) {
    throw new Error('Recipient KEM bundle signature is invalid.');
  }
  if (options.recipient.expiresAt <= now) throw new Error('Recipient KEM bundle has expired.');
  if (options.supplementalSecret && options.supplementalSecret.length < 32) {
    throw new Error('Supplemental secret must contain at least 32 bytes.');
  }

  const randomSource = options.randomSource ?? randomBytes;
  const ephemeral = x25519.keygen(randomSource(32));
  const encapsulated = ml_kem768.encapsulate(options.recipient.mlKemPublicKey, randomSource(32));
  const classicalSecret = x25519.getSharedSecret(ephemeral.secretKey, options.recipient.x25519PublicKey);
  const nonce = randomSource(12);
  assertLength(nonce, 12, 'Envelope nonce');
  const unsignedHeader = {
    senderIdentityKeyId: clone(options.sender.keyId),
    recipientKemKeyId: clone(options.recipient.keyId),
    mlKemCiphertext: encapsulated.cipherText,
    ephemeralX25519PublicKey: ephemeral.publicKey,
    nonce,
    createdAt: now,
    supplementalSecretUsed: options.supplementalSecret !== undefined,
  };
  const associatedData = envelopeAssociatedData(unsignedHeader, options.context);
  const key = deriveEnvelopeKey(
    encapsulated.sharedSecret,
    classicalSecret,
    associatedData,
    options.supplementalSecret,
  );
  try {
    const unsigned: Omit<HybridEnvelope, 'signature'> = {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      ...unsignedHeader,
      ciphertext: gcm(key, nonce, associatedData).encrypt(options.plaintext),
    };
    return {
      ...unsigned,
      signature: signHybrid(options.sender, envelopeSignatureTranscript(unsigned, options.context)),
    };
  } finally {
    wipe(ephemeral.secretKey, encapsulated.sharedSecret, classicalSecret, key);
  }
};

export const open = (options: OpenOptions): Uint8Array => {
  const now = options.now ?? Date.now();
  const { envelope } = options;
  validatePublicIdentity(options.sender);
  validatePublicIdentity(options.recipientIdentity);
  validatePrivateKemBundle(options.recipient);
  if (envelope.version !== PROTOCOL_VERSION || envelope.suite !== CIPHER_SUITE) {
    throw new Error('Unsupported envelope cipher suite.');
  }
  if (
    !Number.isSafeInteger(envelope.createdAt) ||
    envelope.createdAt < 0 ||
    envelope.createdAt >= options.recipient.expiresAt ||
    envelope.createdAt > now + MAX_FUTURE_CLOCK_SKEW_MS
  ) {
    throw new Error('Envelope creation time is invalid.');
  }
  if (!equal(envelope.senderIdentityKeyId, options.sender.keyId)) {
    throw new Error('Envelope sender identity mismatch.');
  }
  if (!equal(envelope.recipientKemKeyId, options.recipient.keyId)) {
    throw new Error('Envelope recipient key mismatch.');
  }
  if (!verifyKemBundle(options.recipientIdentity, options.recipient, envelope.createdAt)) {
    throw new Error('Recipient KEM bundle signature is invalid.');
  }
  if (envelope.supplementalSecretUsed !== (options.supplementalSecret !== undefined)) {
    throw new Error('Envelope supplemental protection mismatch.');
  }
  assertLength(envelope.nonce, 12, 'Envelope nonce');
  const { signature, ...unsigned } = envelope;
  if (!verifyHybrid(options.sender, envelopeSignatureTranscript(unsigned, options.context), signature)) {
    throw new Error('Envelope signature is invalid.');
  }

  const associatedData = envelopeAssociatedData(envelope, options.context);
  const mlKemSecret = ml_kem768.decapsulate(envelope.mlKemCiphertext, options.recipient.mlKemSecretKey);
  const classicalSecret = x25519.getSharedSecret(
    options.recipient.x25519SecretKey,
    envelope.ephemeralX25519PublicKey,
  );
  const key = deriveEnvelopeKey(mlKemSecret, classicalSecret, associatedData, options.supplementalSecret);
  try {
    return gcm(key, envelope.nonce, associatedData).decrypt(envelope.ciphertext);
  } finally {
    wipe(mlKemSecret, classicalSecret, key);
  }
};

export const deriveExportKey = (secret: Uint8Array, context: Uint8Array, length = 32): Uint8Array => {
  if (secret.length < 32) throw new Error('Export secret must contain at least 32 bytes.');
  if (!Number.isSafeInteger(length) || length < 16 || length > 64) {
    throw new Error('Export key length must be between 16 and 64 bytes.');
  }
  return hkdf(sha512, secret, ZERO_SALT, frame(utf8('enigm-pq-v2-export'), context), length);
};
