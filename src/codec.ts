import {
  CIPHER_SUITE,
  PROTOCOL_VERSION,
  type HybridEnvelope,
  type PublicIdentity,
  type PublicKemBundle,
} from './types.js';
import { equal, frame, utf8 } from './bytes.js';
import { validatePublicIdentity } from './identity.js';

const MAGIC = utf8('ENIGMPQ2');
const MAX_PUBLIC_OBJECT_BYTES = 32 * 1024;
const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
const MAX_FIELD_BYTES = 1024 * 1024;

class FrameReader {
  private offset = 0;

  constructor(private readonly input: Uint8Array) {}

  read(maxLength = MAX_FIELD_BYTES): Uint8Array {
    if (this.offset + 4 > this.input.length) throw new Error('Truncated frame length.');
    const length = new DataView(
      this.input.buffer,
      this.input.byteOffset + this.offset,
      4,
    ).getUint32(0, false);
    this.offset += 4;
    if (length > maxLength || this.offset + length > this.input.length) {
      throw new Error('Invalid framed field length.');
    }
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  readExact(length: number, label: string): Uint8Array {
    const value = this.read(length);
    if (value.length !== length) throw new Error(`${label} must contain exactly ${length} bytes.`);
    return value;
  }

  finish(): void {
    if (this.offset !== this.input.length) throw new Error('Trailing bytes after framed object.');
  }
}

const decodeText = (value: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(value);

const decodeVersionAndSuite = (reader: FrameReader): void => {
  if (!equal(reader.readExact(MAGIC.length, 'Object magic'), MAGIC)) {
    throw new Error('Invalid Enigm V2 object magic.');
  }
  if (decodeText(reader.read(2)) !== String(PROTOCOL_VERSION)) {
    throw new Error('Unsupported Enigm protocol version.');
  }
  if (decodeText(reader.read(128)) !== CIPHER_SUITE) throw new Error('Unsupported cipher suite.');
};

const encodePrefix = (): readonly Uint8Array[] => [MAGIC, utf8(String(PROTOCOL_VERSION)), utf8(CIPHER_SUITE)];

const decodeSafeInteger = (value: Uint8Array, label: string): number => {
  if (value.length !== 8) throw new Error(`${label} must contain eight bytes.`);
  const decoded = new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(0, false);
  if (decoded > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} is outside the safe range.`);
  return Number(decoded);
};

const encodeSafeInteger = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid safe integer.');
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), false);
  return output;
};

export const encodePublicIdentity = (identity: PublicIdentity): Uint8Array => {
  validatePublicIdentity(identity);
  return frame(...encodePrefix(), identity.keyId, identity.mlDsaPublicKey, identity.ed25519PublicKey);
};

export const decodePublicIdentity = (encoded: Uint8Array): PublicIdentity => {
  if (encoded.length > MAX_PUBLIC_OBJECT_BYTES) throw new Error('Public identity is too large.');
  const reader = new FrameReader(encoded);
  decodeVersionAndSuite(reader);
  const identity: PublicIdentity = {
    version: PROTOCOL_VERSION,
    suite: CIPHER_SUITE,
    keyId: reader.readExact(32, 'Identity key identifier'),
    mlDsaPublicKey: reader.readExact(1952, 'ML-DSA-65 public key'),
    ed25519PublicKey: reader.readExact(32, 'Ed25519 public key'),
  };
  reader.finish();
  validatePublicIdentity(identity);
  return identity;
};

export const encodePublicKemBundle = (bundle: PublicKemBundle): Uint8Array =>
  frame(
    ...encodePrefix(),
    bundle.keyId,
    bundle.mlKemPublicKey,
    bundle.x25519PublicKey,
    bundle.identityKeyId,
    encodeSafeInteger(bundle.expiresAt),
    bundle.signature.mlDsa,
    bundle.signature.ed25519,
  );

export const decodePublicKemBundle = (encoded: Uint8Array): PublicKemBundle => {
  if (encoded.length > MAX_PUBLIC_OBJECT_BYTES) throw new Error('Public KEM bundle is too large.');
  const reader = new FrameReader(encoded);
  decodeVersionAndSuite(reader);
  const bundle: PublicKemBundle = {
    version: PROTOCOL_VERSION,
    suite: CIPHER_SUITE,
    keyId: reader.readExact(32, 'KEM key identifier'),
    mlKemPublicKey: reader.readExact(1184, 'ML-KEM-768 public key'),
    x25519PublicKey: reader.readExact(32, 'X25519 public key'),
    identityKeyId: reader.readExact(32, 'KEM identity key identifier'),
    expiresAt: decodeSafeInteger(reader.readExact(8, 'KEM bundle expiration'), 'KEM bundle expiration'),
    signature: {
      mlDsa: reader.readExact(3309, 'ML-DSA-65 signature'),
      ed25519: reader.readExact(64, 'Ed25519 signature'),
    },
  };
  reader.finish();
  return bundle;
};

export const encodeEnvelope = (envelope: HybridEnvelope): Uint8Array =>
  frame(
    ...encodePrefix(),
    envelope.senderIdentityKeyId,
    envelope.recipientKemKeyId,
    envelope.mlKemCiphertext,
    envelope.ephemeralX25519PublicKey,
    envelope.nonce,
    encodeSafeInteger(envelope.createdAt),
    envelope.ciphertext,
    new Uint8Array([envelope.supplementalSecretUsed ? 1 : 0]),
    envelope.signature.mlDsa,
    envelope.signature.ed25519,
  );

export const decodeEnvelope = (encoded: Uint8Array): HybridEnvelope => {
  if (encoded.length > MAX_ENVELOPE_BYTES) throw new Error('Envelope is too large.');
  const reader = new FrameReader(encoded);
  decodeVersionAndSuite(reader);
  const senderIdentityKeyId = reader.readExact(32, 'Sender identity key identifier');
  const recipientKemKeyId = reader.readExact(32, 'Recipient KEM key identifier');
  const mlKemCiphertext = reader.readExact(1088, 'ML-KEM-768 ciphertext');
  const ephemeralX25519PublicKey = reader.readExact(32, 'Ephemeral X25519 public key');
  const nonce = reader.readExact(12, 'Envelope nonce');
  const createdAt = decodeSafeInteger(reader.readExact(8, 'Envelope creation time'), 'Envelope creation time');
  const ciphertext = reader.read(MAX_FIELD_BYTES);
  const flags = reader.readExact(1, 'Envelope flags');
  if (flags.length !== 1 || (flags[0] !== 0 && flags[0] !== 1)) {
    throw new Error('Envelope flags are invalid.');
  }
  const envelope: HybridEnvelope = {
    version: PROTOCOL_VERSION,
    suite: CIPHER_SUITE,
    senderIdentityKeyId,
    recipientKemKeyId,
    mlKemCiphertext,
    ephemeralX25519PublicKey,
    nonce,
    createdAt,
    ciphertext,
    supplementalSecretUsed: flags[0] === 1,
    signature: {
      mlDsa: reader.readExact(3309, 'ML-DSA-65 signature'),
      ed25519: reader.readExact(64, 'Ed25519 signature'),
    },
  };
  reader.finish();
  return envelope;
};
