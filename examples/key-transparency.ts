import {
  emptyKeyTransparencyCheckpoint,
  extendKeyTransparencyCheckpoint,
  generateIdentity,
  keyTransparencyEventHash,
  observeKeyTransparencyCheckpoint,
  publicIdentity,
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

