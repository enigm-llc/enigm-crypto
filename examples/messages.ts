import { randomFillSync } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  encodeBase64, encodePublicKemBundle, equal, generateIdentity, generateKemBundle,
  publicKemBundle, utf8, wipe,
} from '@enigm/crypto';
import {
  createEnigmDeviceClient, createEnigmMessageClient, createEnigmSessionClient,
} from '@enigm/crypto/sdk';
import { createDemoStore } from './demo-storage.js';

const randomSource = (length: number): Uint8Array => randomFillSync(new Uint8Array(length));
const expiry = Date.now() + 60_000;
const alice = generateIdentity(randomSource);
const bob = generateIdentity(randomSource);
const material = {
  alice: { identity: alice, bundles: [{ bundle: generateKemBundle(alice, expiry, randomSource), lastResort: true }] },
  bob: { identity: bob, bundles: [{ bundle: generateKemBundle(bob, expiry, randomSource), lastResort: false }] },
};
const consumed = new Set<string>();
const device = createEnigmDeviceClient({
  randomSource,
  store: {
    load: accountId => {
      if (accountId !== 'alice' && accountId !== 'bob') return Promise.reject(new Error('Unknown demo account'));
      // Production storage must provide independently owned private byte buffers.
      return Promise.resolve(structuredClone(material[accountId]));
    },
    consume: (accountId, keyId) => {
      const key = `${accountId}:${keyId}`;
      if (consumed.has(key)) return Promise.reject(new Error('One-time key already consumed'));
      consumed.add(key);
      return Promise.resolve();
    },
  },
});
const sessions = createEnigmSessionClient({ store: createDemoStore(), randomSource });

// Simulated log authority, not a production trust bootstrap. Obtain signed bindings
// and full witnessed transparency proofs through authenticated host adapters instead.
// This demo trusts the generated recipient keys out of band; it does not demonstrate
// private discovery, revocation freshness or server-blind participant routing.
const logSecret = randomSource(32);
const logPublicKey = encodeBase64(ed25519.getPublicKey(logSecret));
const senderBinding = {
  identityKeyId: encodeBase64(alice.keyId),
  accountCommitment: encodeBase64(randomSource(32)),
  deviceCommitment: encodeBase64(randomSource(32)),
  bindingSignature: '',
};
senderBinding.bindingSignature = encodeBase64(ed25519.sign(utf8(JSON.stringify([
  'enigm-key-transparency-binding-v2', 'alice', 'alice-device',
  senderBinding.identityKeyId, senderBinding.accountCommitment, senderBinding.deviceCommitment,
])), logSecret));
const messages = createEnigmMessageClient({ device, sessions, randomSource, logPublicKey });
const target = {
  userId: 'bob', deviceId: 'bob-device',
  encodedIdentity: await device.publicIdentityEncoded('bob'),
  encodedBundle: encodeBase64(encodePublicKemBundle(publicKemBundle(material.bob.bundles[0]!.bundle))),
  identityKeyId: encodeBase64(bob.keyId),
};
const roundTrip = async (messageId: string): Promise<void> => {
  const plaintext = utf8('Authenticated SDK message 😀');
  let opened: Uint8Array | undefined;
  try {
    const encrypted = await messages.encryptMessage({
      accountId: 'alice', conversationId: 'demo', messageId, senderDeviceId: 'alice-device',
      senderBinding, plaintext, targets: [target],
    });
    opened = await messages.decryptMessage({
      accountId: 'bob', conversationId: 'demo', messageId, currentDeviceId: 'bob-device',
      expectedSenderUserId: 'alice', encrypted,
    });
    if (!equal(plaintext, opened)) throw new Error('Message round trip failed');
  } finally {
    wipe(plaintext);
    if (opened) wipe(opened);
  }
};
try {
  await roundTrip('bootstrap');
  await roundTrip('established');
  if (consumed.size !== 1) throw new Error('Unexpected prekey lifecycle');
  console.log('Message SDK bootstrap and established-session round trips verified.');
} finally {
  wipe(logSecret);
  for (const state of Object.values(material)) {
    wipe(state.identity.ed25519SecretKey, state.identity.mlDsaSecretKey);
    for (const item of state.bundles) wipe(item.bundle.x25519SecretKey, item.bundle.mlKemSecretKey);
  }
  await sessions.delete('alice');
  await sessions.delete('bob');
}
