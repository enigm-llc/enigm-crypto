import { performance } from 'node:perf_hooks';

import { generateIdentity, generateKemBundle, open, publicIdentity, publicKemBundle, seal, utf8 } from '../src/index.ts';

const measure = (label: string, action: () => void): void => {
  const started = performance.now();
  action();
  process.stdout.write(`${label}: ${(performance.now() - started).toFixed(2)} ms\n`);
};

const alice = generateIdentity();
const bob = generateIdentity();
const bobKem = generateKemBundle(bob, Date.now() + 60_000);
const context = utf8('benchmark');
let envelope: ReturnType<typeof seal>;

measure('seal 1 KiB session payload', () => {
  envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: new Uint8Array(1024),
    context,
  });
});

measure('open 1 KiB session payload', () => {
  open({
    sender: publicIdentity(alice),
    recipientIdentity: publicIdentity(bob),
    recipient: bobKem,
    envelope,
    context,
  });
});
