import assert from 'node:assert/strict';
import test from 'node:test';
import * as legacy from '../src/index.ts';
test('modular entries preserve the existing public implementations', async () => {
  for (const [module, names] of [
    ['core', ['utf8', 'frame', 'wipe']],
    ['primitives', ['generateIdentity', 'generateKemBundle', 'signHybrid']],
    ['protocols', ['seal', 'open', 'sealSender', 'initializeSession', 'sessionEncrypt', 'createGroupEpoch', 'verifyRfc6962Inclusion']],
    ['codecs', ['encodeEnvelope', 'decodePublicIdentity']],
  ] as const) {
    const entry = await import(`../src/${module}/index.ts`);
    for (const name of names) assert.equal(entry[name], legacy[name as keyof typeof legacy]);
  }
});
