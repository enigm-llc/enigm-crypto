import { generateContentKey, initializeSession, sessionDecrypt, sessionEncrypt, utf8 } from '../src/index.js';

const rootKey = generateContentKey();
const context = utf8('example|conversation:42|devices:a,b');
let initiator = initializeSession(rootKey, context, 'initiator');
let responder = initializeSession(rootKey, context, 'responder');

const sent = sessionEncrypt(initiator, utf8('first session message'), context);
initiator = sent.next;

const received = sessionDecrypt(responder, sent.message, context);
responder = received.next;

console.log(new TextDecoder().decode(received.plaintext), initiator.send.counter, responder.receive.counter);
