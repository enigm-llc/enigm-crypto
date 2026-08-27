import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

import { assertLength, clone, equal, frame, u32, utf8, wipe } from './bytes.js';
import {
  advanceChain,
  initializeChain,
  ratchetDecrypt,
  ratchetDecryptWithMessageKey,
  ratchetEncrypt,
  type RatchetCiphertext,
} from './ratchet.js';
import {
  PROTOCOL_VERSION,
  type RandomSource,
  type SessionRole,
  type SessionState,
  type SkippedMessageKey,
} from './types.js';

export const MAX_SKIP_DISTANCE = 2_000;
export const MAX_STORED_SKIPPED_KEYS = 1_000;

const sessionContext = (context: Uint8Array, epoch: number): Uint8Array =>
  frame(utf8('enigm-pq-v2-session'), context, u32(epoch));

const directionalContext = (context: Uint8Array, direction: 'initiator' | 'responder'): Uint8Array =>
  frame(context, utf8(direction));

export const validateSessionState = (state: SessionState): void => {
  if (
    state.version !== PROTOCOL_VERSION ||
    !Number.isSafeInteger(state.epoch) ||
    state.epoch < 0 ||
    state.skipped.length > MAX_STORED_SKIPPED_KEYS
  ) {
    throw new Error('Invalid session state.');
  }
  assertLength(state.sessionId, 32, 'Session identifier');
  assertLength(state.rootKey, 32, 'Session root key');
  assertLength(state.send.chainId, 16, 'Send chain identifier');
  assertLength(state.send.chainKey, 32, 'Send chain key');
  assertLength(state.receive.chainId, 16, 'Receive chain identifier');
  assertLength(state.receive.chainKey, 32, 'Receive chain key');
  if (
    !Number.isSafeInteger(state.send.counter) ||
    state.send.counter < 0 ||
    !Number.isSafeInteger(state.receive.counter) ||
    state.receive.counter < 0
  ) {
    throw new Error('Invalid session chain counter.');
  }
  for (const skipped of state.skipped) {
    assertLength(skipped.chainId, 16, 'Skipped chain identifier');
    assertLength(skipped.messageKey, 32, 'Skipped message key');
    if (!Number.isSafeInteger(skipped.counter) || skipped.counter < 0) {
      throw new Error('Invalid skipped message counter.');
    }
  }
};

export const initializeSession = (
  rootKey: Uint8Array,
  context: Uint8Array,
  role: SessionRole,
): SessionState => {
  assertLength(rootKey, 32, 'Session root key');
  const root = hmac(sha512, rootKey, frame(utf8('enigm-pq-v2-session-root'), context)).slice(0, 32);
  const id = sha256(frame(utf8('enigm-pq-v2-session-id'), root, context));
  const initiator = initializeChain(root, directionalContext(sessionContext(context, 0), 'initiator'));
  const responder = initializeChain(root, directionalContext(sessionContext(context, 0), 'responder'));
  return {
    version: PROTOCOL_VERSION,
    sessionId: id,
    epoch: 0,
    rootKey: root,
    send: role === 'initiator' ? initiator : responder,
    receive: role === 'initiator' ? responder : initiator,
    skipped: [],
  };
};

export const sessionEncrypt = (
  state: SessionState,
  plaintext: Uint8Array,
  context: Uint8Array,
  randomSource?: RandomSource,
): { message: RatchetCiphertext; next: SessionState } => {
  validateSessionState(state);
  const encrypted = ratchetEncrypt(
    state.send,
    plaintext,
    sessionContext(context, state.epoch),
    randomSource,
  );
  return { message: encrypted.message, next: { ...state, send: encrypted.next } };
};

const skippedIndex = (skipped: readonly SkippedMessageKey[], message: RatchetCiphertext): number =>
  skipped.findIndex((item) => item.counter === message.counter && equal(item.chainId, message.chainId));

export const sessionDecrypt = (
  state: SessionState,
  message: RatchetCiphertext,
  context: Uint8Array,
): { plaintext: Uint8Array; next: SessionState } => {
  validateSessionState(state);
  const existingIndex = skippedIndex(state.skipped, message);
  if (existingIndex >= 0) {
    const existing = state.skipped[existingIndex];
    if (!existing) throw new Error('Skipped session key is unavailable.');
    const plaintext = ratchetDecryptWithMessageKey(
      existing.messageKey,
      message,
      sessionContext(context, state.epoch),
    );
    wipe(existing.messageKey);
    return {
      plaintext,
      next: { ...state, skipped: state.skipped.filter((_, index) => index !== existingIndex) },
    };
  }
  if (!equal(message.chainId, state.receive.chainId) || message.counter < state.receive.counter) {
    throw new Error('Replayed or unknown session message.');
  }
  const distance = message.counter - state.receive.counter;
  const advanced = advanceChain(state.receive, distance, MAX_SKIP_DISTANCE);
  if (state.skipped.length + advanced.skipped.length > MAX_STORED_SKIPPED_KEYS) {
    advanced.skipped.forEach((item) => wipe(item.messageKey));
    wipe(advanced.next.chainKey);
    throw new Error('Skipped message key capacity exceeded.');
  }
  try {
    const decrypted = ratchetDecrypt(
      advanced.next,
      message,
      sessionContext(context, state.epoch),
    );
    return {
      plaintext: decrypted.plaintext,
      next: {
        ...state,
        receive: decrypted.next,
        skipped: [...state.skipped, ...advanced.skipped],
      },
    };
  } catch (error) {
    advanced.skipped.forEach((item) => wipe(item.messageKey));
    wipe(advanced.next.chainKey);
    throw error;
  }
};

export const rekeySession = (
  state: SessionState,
  freshHybridSecret: Uint8Array,
  context: Uint8Array,
  role: SessionRole,
): SessionState => {
  validateSessionState(state);
  if (freshHybridSecret.length < 32) throw new Error('A fresh hybrid secret is required for rekeying.');
  const epoch = state.epoch + 1;
  const rootKey = hmac(
    sha512,
    state.rootKey,
    frame(utf8('enigm-pq-v2-session-rekey'), freshHybridSecret, context, u32(epoch)),
  ).slice(0, 32);
  const scoped = sessionContext(context, epoch);
  const initiator = initializeChain(rootKey, directionalContext(scoped, 'initiator'));
  const responder = initializeChain(rootKey, directionalContext(scoped, 'responder'));
  state.skipped.forEach((item) => wipe(item.messageKey));
  wipe(state.rootKey, state.send.chainKey, state.receive.chainKey);
  return {
    version: PROTOCOL_VERSION,
    sessionId: clone(state.sessionId),
    epoch,
    rootKey,
    send: role === 'initiator' ? initiator : responder,
    receive: role === 'initiator' ? responder : initiator,
    skipped: [],
  };
};

export const wipeSession = (state: SessionState): void => {
  state.skipped.forEach((item) => wipe(item.messageKey));
  wipe(state.rootKey, state.send.chainKey, state.receive.chainKey);
};
