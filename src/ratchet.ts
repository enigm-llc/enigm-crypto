import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import {
  PROTOCOL_VERSION,
  type ChainState,
  type RandomSource,
  type SkippedMessageKey,
} from './types.js';
import { assertLength, clone, equal, frame, u32, utf8, wipe } from './bytes.js';

export type RatchetCiphertext = {
  version: typeof PROTOCOL_VERSION;
  chainId: Uint8Array;
  counter: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

export const initializeChain = (rootKey: Uint8Array, context: Uint8Array): ChainState => {
  if (rootKey.length < 32) throw new Error('Root key must contain at least 32 bytes.');
  const chainKey = hmac(sha512, rootKey, frame(utf8('enigm-pq-v2-chain-start'), context)).slice(0, 32);
  return {
    version: PROTOCOL_VERSION,
    chainId: sha256(frame(utf8('enigm-pq-v2-chain-id'), chainKey, context)).slice(0, 16),
    counter: 0,
    chainKey,
  };
};

const deriveStep = (state: ChainState): { messageKey: Uint8Array; next: ChainState } => {
  if (state.version !== PROTOCOL_VERSION || !Number.isSafeInteger(state.counter) || state.counter < 0) {
    throw new Error('Invalid ratchet state.');
  }
  assertLength(state.chainKey, 32, 'Chain key');
  assertLength(state.chainId, 16, 'Chain identifier');
  const counter = u32(state.counter);
  const messageKey = hmac(sha512, state.chainKey, frame(utf8('message-key'), counter)).slice(0, 32);
  const chainKey = hmac(sha512, state.chainKey, frame(utf8('next-chain-key'), counter)).slice(0, 32);
  return {
    messageKey,
    next: { ...state, chainId: clone(state.chainId), counter: state.counter + 1, chainKey },
  };
};

export const advanceChain = (
  state: ChainState,
  steps: number,
  maximumSteps = 2_000,
): { next: ChainState; skipped: SkippedMessageKey[] } => {
  if (!Number.isSafeInteger(steps) || steps < 0 || steps > maximumSteps) {
    throw new Error('Ratchet advance is outside the permitted window.');
  }
  let current: ChainState = {
    ...state,
    chainId: clone(state.chainId),
    chainKey: clone(state.chainKey),
  };
  const skipped: SkippedMessageKey[] = [];
  for (let index = 0; index < steps; index += 1) {
    const { messageKey, next } = deriveStep(current);
    skipped.push({
      chainId: clone(current.chainId),
      counter: current.counter,
      messageKey,
    });
    wipe(current.chainKey);
    current = next;
  }
  return { next: current, skipped };
};

const messageAssociatedData = (
  chainId: Uint8Array,
  counter: number,
  context: Uint8Array,
): Uint8Array => frame(utf8('enigm-pq-v2-ratchet-message'), chainId, u32(counter), sha256(context));

export const ratchetEncrypt = (
  state: ChainState,
  plaintext: Uint8Array,
  context: Uint8Array,
  randomSource: RandomSource = randomBytes,
): { message: RatchetCiphertext; next: ChainState } => {
  const { messageKey, next } = deriveStep(state);
  const nonce = randomSource(12);
  assertLength(nonce, 12, 'Ratchet nonce');
  try {
    return {
      message: {
        version: PROTOCOL_VERSION,
        chainId: clone(state.chainId),
        counter: state.counter,
        nonce,
        ciphertext: gcm(
          messageKey,
          nonce,
          messageAssociatedData(state.chainId, state.counter, context),
        ).encrypt(plaintext),
      },
      next,
    };
  } finally {
    wipe(messageKey);
  }
};

export const ratchetDecrypt = (
  state: ChainState,
  message: RatchetCiphertext,
  context: Uint8Array,
): { plaintext: Uint8Array; next: ChainState } => {
  if (message.version !== PROTOCOL_VERSION || message.counter !== state.counter) {
    throw new Error('Unexpected ratchet message counter.');
  }
  if (!equal(message.chainId, state.chainId)) throw new Error('Unexpected ratchet chain identifier.');
  assertLength(message.nonce, 12, 'Ratchet nonce');
  const { messageKey, next } = deriveStep(state);
  try {
    return {
      plaintext: gcm(
        messageKey,
        message.nonce,
        messageAssociatedData(message.chainId, message.counter, context),
      ).decrypt(message.ciphertext),
      next,
    };
  } finally {
    wipe(messageKey);
  }
};

export const ratchetDecryptWithMessageKey = (
  messageKey: Uint8Array,
  message: RatchetCiphertext,
  context: Uint8Array,
): Uint8Array => {
  assertLength(messageKey, 32, 'Message key');
  if (message.version !== PROTOCOL_VERSION || !Number.isSafeInteger(message.counter) || message.counter < 0) {
    throw new Error('Invalid ratchet message.');
  }
  assertLength(message.chainId, 16, 'Ratchet chain identifier');
  assertLength(message.nonce, 12, 'Ratchet nonce');
  return gcm(
    messageKey,
    message.nonce,
    messageAssociatedData(message.chainId, message.counter, context),
  ).decrypt(message.ciphertext);
};
