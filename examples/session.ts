import {
  equal,
  generateContentKey,
  initializeSession,
  sessionDecrypt,
  sessionEncrypt,
  utf8,
} from '../src/index.js';

const rootKey = generateContentKey();
const context = utf8('example|conversation:42|devices:a,b');
let initiator = initializeSession(rootKey, context, 'initiator');
let responder = initializeSession(rootKey, context, 'responder');
const expectedPlaintext = utf8('first session message');

const sent = sessionEncrypt(initiator, expectedPlaintext, context);
initiator = sent.next;

const received = sessionDecrypt(responder, sent.message, context);
responder = received.next;

if (!equal(received.plaintext, expectedPlaintext)) throw new Error('Session round-trip failed.');
if (initiator.send.counter !== 1 || responder.receive.counter !== 1) {
  throw new Error('Session counters did not advance.');
}
process.stdout.write('session round-trip verified\n');
