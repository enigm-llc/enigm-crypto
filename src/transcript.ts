import { sha256 } from '@noble/hashes/sha2.js';

import { CIPHER_SUITE, PROTOCOL_VERSION, type HybridEnvelope, type PublicKemBundle } from './types.js';
import { frame, u64, utf8 } from './bytes.js';

const DOMAIN = utf8('io.enigm.crypto');

export const identityTranscript = (
  mlDsaPublicKey: Uint8Array,
  ed25519PublicKey: Uint8Array,
): Uint8Array => frame(DOMAIN, utf8('identity'), utf8(CIPHER_SUITE), mlDsaPublicKey, ed25519PublicKey);

export const kemBundleTranscript = (bundle: Omit<PublicKemBundle, 'signature'>): Uint8Array =>
  frame(
    DOMAIN,
    utf8('kem-bundle'),
    utf8(String(PROTOCOL_VERSION)),
    utf8(CIPHER_SUITE),
    bundle.keyId,
    bundle.mlKemPublicKey,
    bundle.x25519PublicKey,
    bundle.identityKeyId,
    u64(bundle.expiresAt),
  );

export const envelopeAssociatedData = (
  envelope: Pick<
    HybridEnvelope,
    | 'senderIdentityKeyId'
    | 'recipientKemKeyId'
    | 'mlKemCiphertext'
    | 'ephemeralX25519PublicKey'
    | 'nonce'
    | 'supplementalSecretUsed'
  >,
  context: Uint8Array,
): Uint8Array =>
  frame(
    DOMAIN,
    utf8('envelope'),
    utf8(String(PROTOCOL_VERSION)),
    utf8(CIPHER_SUITE),
    envelope.senderIdentityKeyId,
    envelope.recipientKemKeyId,
    envelope.mlKemCiphertext,
    envelope.ephemeralX25519PublicKey,
    envelope.nonce,
    new Uint8Array([envelope.supplementalSecretUsed ? 1 : 0]),
    sha256(context),
  );

export const envelopeSignatureTranscript = (
  envelope: Omit<HybridEnvelope, 'signature'>,
  context: Uint8Array,
): Uint8Array => frame(envelopeAssociatedData(envelope, context), sha256(envelope.ciphertext));
