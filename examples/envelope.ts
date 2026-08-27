import {
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

const envelope = seal({
  sender,
  recipientIdentity: publicIdentity(recipient),
  recipient: publicKemBundle(recipientBundle),
  plaintext: utf8('authenticated hybrid envelope'),
  context,
});

const plaintext = open({
  sender: publicIdentity(sender),
  recipientIdentity: publicIdentity(recipient),
  recipient: recipientBundle,
  envelope,
  context,
});

console.log(new TextDecoder().decode(plaintext));
