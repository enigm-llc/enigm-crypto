import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { assertLength, clone, equal, frame, u64, utf8, wipe } from './bytes.js';
import { signHybrid, validatePrivateIdentity, validatePublicIdentity, verifyHybrid } from './identity.js';
import { validatePrivateKemBundle, verifyKemBundle } from './kem.js';
import {
  CIPHER_SUITE,
  PROTOCOL_VERSION,
  type HybridSignature,
  type OpenSealedSenderOptions,
  type OpenedSealedSender,
  type PublicIdentity,
  type SealSenderOptions,
  type SealedSenderEnvelope,
} from './types.js';

const OUTER_DOMAIN = utf8('enigm-sealed-sender-outer-v1');
const INNER_DOMAIN = utf8('enigm-sealed-sender-inner-v1');
const WIRE_MAGIC = utf8('ENIGMSS2');
const MAX_PLAINTEXT_BYTES = 1024 * 1024;
const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
const MAX_FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1000;

const rejectZeroX25519Secret = (secret: Uint8Array): void => {
  let aggregate = 0;
  for (const byte of secret) aggregate |= byte;
  if (aggregate === 0) throw new Error('Invalid X25519 shared secret.');
};

const outerAssociatedData = (
  envelope: Pick<
    SealedSenderEnvelope,
    | 'recipientKemKeyId'
    | 'mlKemCiphertext'
    | 'ephemeralX25519PublicKey'
    | 'nonce'
    | 'createdAt'
    | 'supplementalSecretUsed'
  >,
  context: Uint8Array,
): Uint8Array =>
  frame(
    OUTER_DOMAIN,
    utf8(String(PROTOCOL_VERSION)),
    utf8(CIPHER_SUITE),
    envelope.recipientKemKeyId,
    envelope.mlKemCiphertext,
    envelope.ephemeralX25519PublicKey,
    envelope.nonce,
    u64(envelope.createdAt),
    new Uint8Array([envelope.supplementalSecretUsed ? 1 : 0]),
    sha256(context),
  );

const innerTranscript = (
  sender: PublicIdentity,
  recipientKemKeyId: Uint8Array,
  plaintext: Uint8Array,
  context: Uint8Array,
  createdAt: number,
): Uint8Array =>
  frame(
    INNER_DOMAIN,
    sender.keyId,
    recipientKemKeyId,
    u64(createdAt),
    sha256(context),
    sha256(plaintext),
  );

const encodeInner = (
  sender: PublicIdentity,
  plaintext: Uint8Array,
  signature: HybridSignature,
): Uint8Array =>
  frame(
    sender.keyId,
    sender.mlDsaPublicKey,
    sender.ed25519PublicKey,
    plaintext,
    signature.mlDsa,
    signature.ed25519,
  );

class InnerReader {
  private offset = 0;

  constructor(private readonly input: Uint8Array) {}

  read(maximum: number, exact?: number): Uint8Array {
    if (this.offset + 4 > this.input.length) throw new Error('Truncated sealed sender payload.');
    const length = new DataView(this.input.buffer, this.input.byteOffset + this.offset, 4).getUint32(0, false);
    this.offset += 4;
    if (length > maximum || (exact !== undefined && length !== exact) || this.offset + length > this.input.length) {
      throw new Error('Invalid sealed sender field length.');
    }
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  finish(): void {
    if (this.offset !== this.input.length) throw new Error('Trailing sealed sender payload data.');
  }
}

const decodeSafeInteger = (value: Uint8Array): number => {
  if (value.length !== 8) throw new Error('Invalid sealed sender creation time.');
  const decoded = new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(0, false);
  if (decoded > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Invalid sealed sender creation time.');
  return Number(decoded);
};

const validateEnvelopeHeader = (envelope: SealedSenderEnvelope): void => {
  if (envelope.version !== PROTOCOL_VERSION || envelope.suite !== CIPHER_SUITE) {
    throw new Error('Unsupported sealed sender cipher suite.');
  }
  assertLength(envelope.recipientKemKeyId, 32, 'Sealed sender recipient key identifier');
  assertLength(envelope.mlKemCiphertext, 1088, 'Sealed sender ML-KEM ciphertext');
  assertLength(envelope.ephemeralX25519PublicKey, 32, 'Sealed sender X25519 public key');
  assertLength(envelope.nonce, 12, 'Sealed sender nonce');
  if (!Number.isSafeInteger(envelope.createdAt) || envelope.createdAt < 0) {
    throw new Error('Invalid sealed sender creation time.');
  }
  if (envelope.ciphertext.length > MAX_PLAINTEXT_BYTES + 8_192) {
    throw new Error('Sealed sender ciphertext is too large.');
  }
};

export const encodeSealedSenderEnvelope = (envelope: SealedSenderEnvelope): Uint8Array => {
  validateEnvelopeHeader(envelope);
  return frame(
    WIRE_MAGIC,
    utf8(String(PROTOCOL_VERSION)),
    utf8(CIPHER_SUITE),
    envelope.recipientKemKeyId,
    envelope.mlKemCiphertext,
    envelope.ephemeralX25519PublicKey,
    envelope.nonce,
    u64(envelope.createdAt),
    envelope.ciphertext,
    new Uint8Array([envelope.supplementalSecretUsed ? 1 : 0]),
  );
};

export const decodeSealedSenderEnvelope = (encoded: Uint8Array): SealedSenderEnvelope => {
  if (encoded.length > MAX_ENVELOPE_BYTES) throw new Error('Sealed sender envelope is too large.');
  const reader = new InnerReader(encoded);
  if (!equal(reader.read(WIRE_MAGIC.length, WIRE_MAGIC.length), WIRE_MAGIC)) {
    throw new Error('Invalid sealed sender object magic.');
  }
  if (new TextDecoder('utf-8', { fatal: true }).decode(reader.read(2)) !== String(PROTOCOL_VERSION)) {
    throw new Error('Unsupported sealed sender protocol version.');
  }
  if (new TextDecoder('utf-8', { fatal: true }).decode(reader.read(128)) !== CIPHER_SUITE) {
    throw new Error('Unsupported sealed sender cipher suite.');
  }
  const flags = {
    recipientKemKeyId: reader.read(32, 32),
    mlKemCiphertext: reader.read(1088, 1088),
    ephemeralX25519PublicKey: reader.read(32, 32),
    nonce: reader.read(12, 12),
    createdAt: decodeSafeInteger(reader.read(8, 8)),
    ciphertext: reader.read(MAX_PLAINTEXT_BYTES + 8_192),
    supplementalSecretUsed: reader.read(1, 1),
  };
  reader.finish();
  if (flags.supplementalSecretUsed[0] !== 0 && flags.supplementalSecretUsed[0] !== 1) {
    throw new Error('Invalid sealed sender flags.');
  }
  const envelope: SealedSenderEnvelope = {
    version: PROTOCOL_VERSION,
    suite: CIPHER_SUITE,
    ...flags,
    supplementalSecretUsed: flags.supplementalSecretUsed[0] === 1,
  };
  validateEnvelopeHeader(envelope);
  return envelope;
};

const decodeInner = (encoded: Uint8Array): {
  sender: PublicIdentity;
  plaintext: Uint8Array;
  signature: HybridSignature;
} => {
  const reader = new InnerReader(encoded);
  const sender: PublicIdentity = {
    version: PROTOCOL_VERSION,
    suite: CIPHER_SUITE,
    keyId: reader.read(32, 32),
    mlDsaPublicKey: reader.read(1952, 1952),
    ed25519PublicKey: reader.read(32, 32),
  };
  const plaintext = reader.read(MAX_PLAINTEXT_BYTES);
  const signature = {
    mlDsa: reader.read(3309, 3309),
    ed25519: reader.read(64, 64),
  };
  reader.finish();
  validatePublicIdentity(sender);
  return { sender, plaintext, signature };
};

const deriveKey = (
  mlKemSecret: Uint8Array,
  x25519Secret: Uint8Array,
  associatedData: Uint8Array,
  supplementalSecret?: Uint8Array,
): Uint8Array => {
  rejectZeroX25519Secret(x25519Secret);
  return hkdf(
    sha512,
    supplementalSecret
      ? frame(mlKemSecret, x25519Secret, supplementalSecret)
      : frame(mlKemSecret, x25519Secret),
    sha512(frame(OUTER_DOMAIN, associatedData)),
    frame(utf8('enigm-sealed-sender-key-v1'), utf8(CIPHER_SUITE), associatedData),
    32,
  );
};

export const sealSender = (options: SealSenderOptions): SealedSenderEnvelope => {
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Sealed sender creation time is invalid.');
  if (options.plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error('Sealed sender plaintext is too large.');
  validatePrivateIdentity(options.sender);
  validatePublicIdentity(options.recipientIdentity);
  if (!verifyKemBundle(options.recipientIdentity, options.recipient, now)) {
    throw new Error('Recipient KEM bundle signature is invalid.');
  }
  if (options.supplementalSecret && options.supplementalSecret.length < 32) {
    throw new Error('Supplemental secret must contain at least 32 bytes.');
  }

  const randomSource = options.randomSource ?? randomBytes;
  const ephemeral = x25519.keygen(randomSource(32));
  const encapsulated = ml_kem768.encapsulate(options.recipient.mlKemPublicKey, randomSource(32));
  const classicalSecret = x25519.getSharedSecret(ephemeral.secretKey, options.recipient.x25519PublicKey);
  const nonce = randomSource(12);
  assertLength(nonce, 12, 'Sealed sender nonce');
  const header = {
    recipientKemKeyId: clone(options.recipient.keyId),
    mlKemCiphertext: encapsulated.cipherText,
    ephemeralX25519PublicKey: ephemeral.publicKey,
    nonce,
    createdAt: now,
    supplementalSecretUsed: options.supplementalSecret !== undefined,
  };
  const associatedData = outerAssociatedData(header, options.context);
  const publicSender: PublicIdentity = {
    version: options.sender.version,
    suite: options.sender.suite,
    keyId: clone(options.sender.keyId),
    mlDsaPublicKey: clone(options.sender.mlDsaPublicKey),
    ed25519PublicKey: clone(options.sender.ed25519PublicKey),
  };
  const signature = signHybrid(
    options.sender,
    innerTranscript(publicSender, header.recipientKemKeyId, options.plaintext, options.context, now),
  );
  const inner = encodeInner(publicSender, options.plaintext, signature);
  const key = deriveKey(encapsulated.sharedSecret, classicalSecret, associatedData, options.supplementalSecret);
  try {
    return {
      version: PROTOCOL_VERSION,
      suite: CIPHER_SUITE,
      ...header,
      ciphertext: gcm(key, nonce, associatedData).encrypt(inner),
    };
  } finally {
    wipe(ephemeral.secretKey, encapsulated.sharedSecret, classicalSecret, key, inner);
  }
};

export const openSealedSender = (options: OpenSealedSenderOptions): OpenedSealedSender => {
  const now = options.now ?? Date.now();
  const { envelope } = options;
  validatePublicIdentity(options.recipientIdentity);
  validatePrivateKemBundle(options.recipient);
  validateEnvelopeHeader(envelope);
  if (
    !Number.isSafeInteger(envelope.createdAt) ||
    envelope.createdAt < 0 ||
    envelope.createdAt >= options.recipient.expiresAt ||
    envelope.createdAt > now + MAX_FUTURE_CLOCK_SKEW_MS
  ) {
    throw new Error('Sealed sender creation time is invalid.');
  }
  if (!equal(envelope.recipientKemKeyId, options.recipient.keyId)) {
    throw new Error('Sealed sender recipient key mismatch.');
  }
  if (!verifyKemBundle(options.recipientIdentity, options.recipient, envelope.createdAt)) {
    throw new Error('Recipient KEM bundle signature is invalid.');
  }
  if (envelope.supplementalSecretUsed !== (options.supplementalSecret !== undefined)) {
    throw new Error('Sealed sender supplemental protection mismatch.');
  }
  const associatedData = outerAssociatedData(envelope, options.context);
  const mlKemSecret = ml_kem768.decapsulate(envelope.mlKemCiphertext, options.recipient.mlKemSecretKey);
  const classicalSecret = x25519.getSharedSecret(
    options.recipient.x25519SecretKey,
    envelope.ephemeralX25519PublicKey,
  );
  const key = deriveKey(mlKemSecret, classicalSecret, associatedData, options.supplementalSecret);
  let inner: Uint8Array | undefined;
  try {
    inner = gcm(key, envelope.nonce, associatedData).decrypt(envelope.ciphertext);
    const decoded = decodeInner(inner);
    if (options.expectedSenderIdentity) {
      validatePublicIdentity(options.expectedSenderIdentity);
      if (!equal(decoded.sender.keyId, options.expectedSenderIdentity.keyId)) {
        throw new Error('Sealed sender identity does not match the expected sender.');
      }
    }
    const transcript = innerTranscript(
      decoded.sender,
      envelope.recipientKemKeyId,
      decoded.plaintext,
      options.context,
      envelope.createdAt,
    );
    if (!verifyHybrid(decoded.sender, transcript, decoded.signature)) {
      throw new Error('Sealed sender signature is invalid.');
    }
    return { sender: decoded.sender, plaintext: decoded.plaintext };
  } finally {
    wipe(mlKemSecret, classicalSecret, key);
    if (inner) wipe(inner);
  }
};
