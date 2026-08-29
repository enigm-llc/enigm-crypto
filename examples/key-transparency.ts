import { ed25519 } from '@noble/curves/ed25519.js';

import {
  appendRfc6962Entry,
  c2spVerifierKey,
  emptyKeyTransparencyStateHash,
  emptyKeyTransparencyCheckpoint,
  extendKeyTransparencyCheckpoint,
  generateIdentity,
  keyTransparencyEventHash,
  keyTransparencyLogEntry,
  keyTransparencyStateNodeHash,
  observeKeyTransparencyCheckpoint,
  publicIdentity,
  signC2spCheckpoint,
  signKeyTransparencyCheckpoint,
  verifyKeyTransparencyCheckpoint,
} from '../src/index.js';

const signer = generateIdentity();
const trusted = emptyKeyTransparencyCheckpoint(Date.now());
const event = {
  version: 1 as const,
  sequence: 1,
  previousHash: trusted.headHash,
  accountCommitment: crypto.getRandomValues(new Uint8Array(32)),
  deviceCommitment: crypto.getRandomValues(new Uint8Array(32)),
  identityKeyId: crypto.getRandomValues(new Uint8Array(32)),
  action: 'ACTIVATE' as const,
  occurredAt: Date.now(),
};
const checkpoint = extendKeyTransparencyCheckpoint(trusted, [event], Date.now());
const signed = signKeyTransparencyCheckpoint(signer, checkpoint);

if (!verifyKeyTransparencyCheckpoint(publicIdentity(signer), signed)) {
  throw new Error('Checkpoint verification failed.');
}
if (observeKeyTransparencyCheckpoint(trusted, checkpoint) !== 'ADVANCED') {
  throw new Error('Checkpoint did not advance.');
}
process.stdout.write(`head sha256:${Buffer.from(keyTransparencyEventHash(event)).toString('hex')}\n`);

const logSecretKey = crypto.getRandomValues(new Uint8Array(32));
const logPublicKey = ed25519.getPublicKey(logSecretKey);
const emptyState = emptyKeyTransparencyStateHash();
const stateRoot = keyTransparencyStateNodeHash(
  event.identityKeyId,
  event.action,
  emptyState,
  emptyState,
);
const logEntry = keyTransparencyLogEntry(event, stateRoot);
const tree = appendRfc6962Entry([], 0, logEntry);
const publicCheckpoint = {
  origin: 'keys.example.test/v1',
  size: tree.treeSize,
  rootHash: tree.rootHash,
};
const signedNote = signC2spCheckpoint(publicCheckpoint, {
  name: publicCheckpoint.origin,
  publicKey: logPublicKey,
  secretKey: logSecretKey,
});

process.stdout.write(`${c2spVerifierKey(publicCheckpoint.origin, logPublicKey)}\n${signedNote}`);
