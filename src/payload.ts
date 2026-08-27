import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { assertLength, frame, utf8 } from './bytes.js';
import { PROTOCOL_VERSION, type RandomSource } from './types.js';

export type ContentCiphertext = {
  version: typeof PROTOCOL_VERSION;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

const associatedData = (context: Uint8Array): Uint8Array =>
  frame(utf8('enigm-pq-v2-content'), sha256(context));

export const generateContentKey = (randomSource: RandomSource = randomBytes): Uint8Array => {
  const key = randomSource(32);
  assertLength(key, 32, 'Content key');
  return key;
};

export const encryptContent = (
  key: Uint8Array,
  plaintext: Uint8Array,
  context: Uint8Array,
  randomSource: RandomSource = randomBytes,
): ContentCiphertext => {
  assertLength(key, 32, 'Content key');
  const nonce = randomSource(12);
  assertLength(nonce, 12, 'Content nonce');
  return {
    version: PROTOCOL_VERSION,
    nonce,
    ciphertext: gcm(key, nonce, associatedData(context)).encrypt(plaintext),
  };
};

export const decryptContent = (
  key: Uint8Array,
  encrypted: ContentCiphertext,
  context: Uint8Array,
): Uint8Array => {
  assertLength(key, 32, 'Content key');
  if (encrypted.version !== PROTOCOL_VERSION) throw new Error('Unsupported content version.');
  assertLength(encrypted.nonce, 12, 'Content nonce');
  return gcm(key, encrypted.nonce, associatedData(context)).decrypt(encrypted.ciphertext);
};
