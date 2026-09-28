import {
  equal,
  generateIdentity,
  generateKemBundle,
  open,
  publicIdentity,
  publicKemBundle,
  seal,
  utf8,
} from '../src/index.js';

const sender = generateIdentity();
const recipient = generateIdentity();
const recipientBundle = generateKemBundle(recipient, Date.now() + 60_000);
const context = utf8('example|conversation:42|sender:device-a|recipient:device-b|message:1');
const expectedPlaintext = utf8('authenticated hybrid envelope');

const envelope = seal({
  sender,
  recipientIdentity: publicIdentity(recipient),
  recipient: publicKemBundle(recipientBundle),
  plaintext: expectedPlaintext,
  context,
});

const plaintext = open({
  sender: publicIdentity(sender),
  recipientIdentity: publicIdentity(recipient),
  recipient: recipientBundle,
  envelope,
  context,
});

if (!equal(plaintext, expectedPlaintext)) throw new Error('Envelope round-trip failed.');
process.stdout.write('authenticated hybrid envelope round-trip verified\n');
