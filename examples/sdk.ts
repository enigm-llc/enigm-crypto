import { randomFillSync } from 'node:crypto';
import { utf8, decodeUtf8, equal, wipe } from '@enigm/crypto/core';
import { encryptEnigmAttachment, decryptEnigmAttachment, createEnigmSessionClient } from '@enigm/crypto/sdk';

const randomBytes = (length: number): Uint8Array => randomFillSync(new Uint8Array(length));

// fileKey is a serialized string: do not log or retain it beyond its lifecycle.
// The host encrypts this file key inside a message before transporting it.
const original = utf8('Attachment SDK: imagen, audio, vídeo o documento 😀');
const { encrypted, fileKey } = encryptEnigmAttachment(original, randomBytes);
const recovered = decryptEnigmAttachment(encrypted, fileKey);
if (!equal(original, recovered)) throw new Error('Attachment round trip failed');
console.log(decodeUtf8(recovered));
wipe(original); wipe(recovered);

import { createDemoStore } from './demo-storage.js';
// Demonstration only; production requires encrypted platform storage.
const store = createDemoStore();
const sessions = createEnigmSessionClient({ store, randomSource: randomBytes });
const root = randomBytes(32);
const context = utf8('sdk-example:conversation:1|alice-device|bob-device');
try {
  await sessions.initializeSession('alice', 'conversation-1', root, context, 'initiator');
  await sessions.initializeSession('bob', 'conversation-1', root, context, 'responder');
  const plaintext = utf8('Session SDK 😀');
  const packet = await sessions.encrypt('alice', 'conversation-1', plaintext, context);
  const opened = await sessions.decryptAndCommit('bob', 'conversation-1', packet, context, value => value.slice());
  if (!equal(opened, plaintext)) throw new Error('Session SDK round trip failed');
  console.log(decodeUtf8(opened));
  wipe(plaintext, opened);
} finally {
  wipe(root);
  await sessions.delete('alice');
  await sessions.delete('bob');
}
