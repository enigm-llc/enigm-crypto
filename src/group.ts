import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { assertLength, clone, frame, u32, utf8, wipe } from './bytes.js';
import { PROTOCOL_VERSION, type GroupEpochState, type RandomSource } from './types.js';

export type GroupEpochCiphertext = {
  version: typeof PROTOCOL_VERSION;
  groupId: Uint8Array;
  epoch: number;
  purpose: 'metadata' | 'message';
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

const canonicalMembers = (memberDeviceIds: readonly string[]): Uint8Array => {
  if (memberDeviceIds.length < 1 || memberDeviceIds.length > 10_000) {
    throw new Error('Invalid group member count.');
  }
  const normalized = [...new Set(memberDeviceIds)].sort();
  if (normalized.length !== memberDeviceIds.length || normalized.some((id) => id.length < 1 || id.length > 256)) {
    throw new Error('Invalid or duplicate group member device identifier.');
  }
  return frame(...normalized.map(utf8));
};

const deriveMembersHash = (memberDeviceIds: readonly string[]): Uint8Array =>
  sha256(frame(utf8('enigm-pq-v2-group-members'), canonicalMembers(memberDeviceIds)));

export const validateGroupEpochState = (state: GroupEpochState): void => {
  if (
    state.version !== PROTOCOL_VERSION ||
    !Number.isSafeInteger(state.epoch) ||
    state.epoch < 1 ||
    state.groupId.length < 16 ||
    state.groupId.length > 128
  ) {
    throw new Error('Invalid group epoch state.');
  }
  assertLength(state.epochSecret, 32, 'Group epoch secret');
  assertLength(state.membersHash, 32, 'Group members hash');
};

export const createGroupEpoch = (
  groupId: Uint8Array,
  memberDeviceIds: readonly string[],
  randomSource: RandomSource = randomBytes,
): GroupEpochState => {
  if (groupId.length < 16 || groupId.length > 128) throw new Error('Invalid group identifier.');
  const membersHash = deriveMembersHash(memberDeviceIds);
  const secret = randomSource(32);
  assertLength(secret, 32, 'Group epoch secret');
  return {
    version: PROTOCOL_VERSION,
    groupId: clone(groupId),
    epoch: 1,
    epochSecret: secret,
    membersHash,
  };
};

export const rotateGroupEpoch = (
  previous: GroupEpochState,
  memberDeviceIds: readonly string[],
  randomSource: RandomSource = randomBytes,
): GroupEpochState => {
  validateGroupEpochState(previous);
  if (previous.epoch >= 0xffff_ffff) throw new Error('Group epoch is exhausted.');
  const membersHash = deriveMembersHash(memberDeviceIds);
  const secret = randomSource(32);
  assertLength(secret, 32, 'Group epoch secret');
  wipe(previous.epochSecret);
  return {
    version: PROTOCOL_VERSION,
    groupId: clone(previous.groupId),
    epoch: previous.epoch + 1,
    epochSecret: secret,
    membersHash,
  };
};

const groupKey = (state: GroupEpochState, purpose: GroupEpochCiphertext['purpose']): Uint8Array => {
  validateGroupEpochState(state);
  return hmac(
    sha512,
    state.epochSecret,
    frame(utf8('enigm-pq-v2-group-key'), state.groupId, u32(state.epoch), state.membersHash, utf8(purpose)),
  ).slice(0, 32);
};

const associatedData = (state: GroupEpochState, purpose: GroupEpochCiphertext['purpose']): Uint8Array =>
  frame(utf8('enigm-pq-v2-group-ciphertext'), state.groupId, u32(state.epoch), state.membersHash, utf8(purpose));

export const encryptGroupEpoch = (
  state: GroupEpochState,
  purpose: GroupEpochCiphertext['purpose'],
  plaintext: Uint8Array,
  randomSource: RandomSource = randomBytes,
): GroupEpochCiphertext => {
  const key = groupKey(state, purpose);
  const nonce = randomSource(12);
  assertLength(nonce, 12, 'Group nonce');
  try {
    return {
      version: PROTOCOL_VERSION,
      groupId: clone(state.groupId),
      epoch: state.epoch,
      purpose,
      nonce,
      ciphertext: gcm(key, nonce, associatedData(state, purpose)).encrypt(plaintext),
    };
  } finally {
    wipe(key);
  }
};

export const decryptGroupEpoch = (
  state: GroupEpochState,
  encrypted: GroupEpochCiphertext,
): Uint8Array => {
  if (
    encrypted.version !== PROTOCOL_VERSION ||
    encrypted.epoch !== state.epoch ||
    encrypted.purpose !== 'metadata' && encrypted.purpose !== 'message' ||
    encrypted.groupId.length !== state.groupId.length ||
    !encrypted.groupId.every((value, index) => value === state.groupId[index])
  ) {
    throw new Error('Group ciphertext does not belong to this epoch.');
  }
  assertLength(encrypted.nonce, 12, 'Group nonce');
  const key = groupKey(state, encrypted.purpose);
  try {
    return gcm(key, encrypted.nonce, associatedData(state, encrypted.purpose)).decrypt(encrypted.ciphertext);
  } finally {
    wipe(key);
  }
};
