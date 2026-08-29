import { sha256 } from '@noble/hashes/sha2.js';

import { assertLength, clone, equal, frame, u64, utf8 } from './bytes.js';
import { signHybrid, verifyHybrid } from './identity.js';
import type { HybridSignature, PrivateIdentity, PublicIdentity } from './types.js';

const ZERO_HASH = new Uint8Array(32);
const EVENT_DOMAIN = utf8('enigm-key-transparency-event-v1');
const CHECKPOINT_DOMAIN = utf8('enigm-key-transparency-checkpoint-v1');

export type KeyTransparencyAction = 'ACTIVATE' | 'REVOKE';

export type KeyTransparencyEvent = {
  version: 1;
  sequence: number;
  previousHash: Uint8Array;
  accountCommitment: Uint8Array;
  deviceCommitment: Uint8Array;
  identityKeyId: Uint8Array;
  action: KeyTransparencyAction;
  occurredAt: number;
};

export type KeyTransparencyCheckpoint = {
  version: 1;
  size: number;
  headHash: Uint8Array;
  issuedAt: number;
};

export type SignedKeyTransparencyCheckpoint = {
  checkpoint: KeyTransparencyCheckpoint;
  signerKeyId: Uint8Array;
  signature: HybridSignature;
};

export type KeyTransparencyObservation = 'ADVANCED' | 'INITIAL' | 'UNCHANGED';

const actionByte = (action: KeyTransparencyAction): Uint8Array => {
  if (action === 'ACTIVATE') return new Uint8Array([1]);
  if (action === 'REVOKE') return new Uint8Array([2]);
  throw new Error('Unsupported key transparency action.');
};

const validateTime = (value: number, label: string): void => {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
};

export const keyTransparencyEventHash = (event: KeyTransparencyEvent): Uint8Array => {
  if (event.version !== 1 || !Number.isSafeInteger(event.sequence) || event.sequence < 1) {
    throw new Error('Invalid key transparency event version or sequence.');
  }
  validateTime(event.occurredAt, 'Key transparency event time');
  assertLength(event.previousHash, 32, 'Previous event hash');
  assertLength(event.accountCommitment, 32, 'Account commitment');
  assertLength(event.deviceCommitment, 32, 'Device commitment');
  assertLength(event.identityKeyId, 32, 'Identity key identifier');

  return sha256(
    frame(
      EVENT_DOMAIN,
      u64(event.sequence),
      event.previousHash,
      event.accountCommitment,
      event.deviceCommitment,
      event.identityKeyId,
      actionByte(event.action),
      u64(event.occurredAt),
    ),
  );
};

const checkpointTranscript = (checkpoint: KeyTransparencyCheckpoint): Uint8Array => {
  if (checkpoint.version !== 1 || !Number.isSafeInteger(checkpoint.size) || checkpoint.size < 0) {
    throw new Error('Invalid key transparency checkpoint version or size.');
  }
  validateTime(checkpoint.issuedAt, 'Key transparency checkpoint time');
  assertLength(checkpoint.headHash, 32, 'Key transparency checkpoint hash');
  if (checkpoint.size === 0 && !equal(checkpoint.headHash, ZERO_HASH)) {
    throw new Error('An empty key transparency checkpoint must use the zero hash.');
  }
  return frame(CHECKPOINT_DOMAIN, u64(checkpoint.size), checkpoint.headHash, u64(checkpoint.issuedAt));
};

export const emptyKeyTransparencyCheckpoint = (issuedAt = 0): KeyTransparencyCheckpoint => {
  validateTime(issuedAt, 'Key transparency checkpoint time');
  return { version: 1, size: 0, headHash: clone(ZERO_HASH), issuedAt };
};

export const extendKeyTransparencyCheckpoint = (
  trusted: KeyTransparencyCheckpoint,
  events: readonly KeyTransparencyEvent[],
  issuedAt: number,
): KeyTransparencyCheckpoint => {
  checkpointTranscript(trusted);
  validateTime(issuedAt, 'Key transparency checkpoint time');

  let size = trusted.size;
  let headHash = clone(trusted.headHash);
  for (const event of events) {
    if (event.sequence !== size + 1 || !equal(event.previousHash, headHash)) {
      throw new Error('Key transparency consistency proof is not contiguous.');
    }
    headHash = keyTransparencyEventHash(event);
    size = event.sequence;
  }
  return { version: 1, size, headHash, issuedAt };
};

export const signKeyTransparencyCheckpoint = (
  signer: PrivateIdentity,
  checkpoint: KeyTransparencyCheckpoint,
): SignedKeyTransparencyCheckpoint => ({
  checkpoint: { ...checkpoint, headHash: clone(checkpoint.headHash) },
  signerKeyId: clone(signer.keyId),
  signature: signHybrid(signer, checkpointTranscript(checkpoint)),
});

export const verifyKeyTransparencyCheckpoint = (
  signer: PublicIdentity,
  signed: SignedKeyTransparencyCheckpoint,
): boolean =>
  equal(signed.signerKeyId, signer.keyId) &&
  verifyHybrid(signer, checkpointTranscript(signed.checkpoint), signed.signature);

export const observeKeyTransparencyCheckpoint = (
  previous: KeyTransparencyCheckpoint | null,
  next: KeyTransparencyCheckpoint,
): KeyTransparencyObservation => {
  checkpointTranscript(next);
  if (!previous) return 'INITIAL';
  checkpointTranscript(previous);
  if (next.size < previous.size) throw new Error('Key transparency checkpoint rollback detected.');
  if (next.size === previous.size) {
    if (!equal(next.headHash, previous.headHash)) {
      throw new Error('Key transparency checkpoint equivocation detected.');
    }
    return 'UNCHANGED';
  }
  return 'ADVANCED';
};

