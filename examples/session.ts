import {
  equal, generateContentKey, initializeSession, sessionDecrypt, sessionEncrypt, utf8, wipe, wipeSession,
} from '@enigm/crypto';

const rootKey = generateContentKey();
const context = utf8('example|conversation:42|devices:a,b');
let initiator = initializeSession(rootKey, context, 'initiator');
let responder = initializeSession(rootKey, context, 'responder');
const expectedPlaintext = utf8('first session message');
let opened: Uint8Array | undefined;
try {
  const sent = sessionEncrypt(initiator, expectedPlaintext, context);
  wipeSession(initiator);
  initiator = sent.next;
  const received = sessionDecrypt(responder, sent.message, context);
  wipeSession(responder);
  responder = received.next;
  opened = received.plaintext;
  if (!equal(opened, expectedPlaintext)) throw new Error('Session round-trip failed.');
  if (initiator.send.counter !== 1 || responder.receive.counter !== 1) throw new Error('Session counters did not advance.');
  console.log('Session round-trip verified.');
} finally {
  wipe(rootKey, expectedPlaintext);
  if (opened) wipe(opened);
  wipeSession(initiator);
  wipeSession(responder);
}
