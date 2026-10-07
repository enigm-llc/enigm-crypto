import { randomFillSync } from 'node:crypto';
import { utf8, decodeUtf8, equal, wipe } from '../src/core/index.js';
import { encryptEnigmAttachment, decryptEnigmAttachment } from '../src/sdk/index.js';

const randomBytes = (length: number): Uint8Array => randomFillSync(new Uint8Array(length));

// fileKey is a serialized string: do not log or retain it beyond its lifecycle.
// The host encrypts this file key inside a message before transporting it.
const original = utf8('Attachment SDK: imagen, audio, vídeo o documento 😀');
const { encrypted, fileKey } = encryptEnigmAttachment(original, randomBytes);
const recovered = decryptEnigmAttachment(encrypted, fileKey);
if (!equal(original, recovered)) throw new Error('Attachment round trip failed');
console.log(decodeUtf8(recovered));
wipe(original); wipe(recovered);

import { createEnigmSessionClient, type SecureStateStore } from '../src/sdk/index.js';
// Volatile example storage only. Production must use encrypted platform storage.
const rows = new Map<string, string>();
const queues = new Map<string, Promise<unknown>>();
const store: SecureStateStore = {
  read: async id => rows.get(id) ?? null,
  write: async (id, value) => { rows.set(id, value); },
  delete: async id => { rows.delete(id); },
  exclusive: <T>(id: string, action: () => Promise<T>): Promise<T> => {
    const operation = (queues.get(id) ?? Promise.resolve()).catch(() => {}).then(action);
    queues.set(id, operation);
    return operation;
  },
};
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
