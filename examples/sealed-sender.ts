import {
  generateIdentity,
  generateKemBundle,
  openSealedSender,
  publicIdentity,
  publicKemBundle,
  sealSender,
  utf8,
} from '../src/index.ts';

const sender = generateIdentity();
const recipient = generateIdentity();
const recipientBundle = generateKemBundle(recipient, Date.now() + 60_000);
const context = utf8('example:sealed-sender:message:1');

const envelope = sealSender({
  sender,
  recipientIdentity: publicIdentity(recipient),
  recipient: publicKemBundle(recipientBundle),
  plaintext: utf8('authenticated without exposing the sender to the relay'),
  context,
});

const opened = openSealedSender({
  recipientIdentity: publicIdentity(recipient),
  recipient: recipientBundle,
  envelope,
  context,
  expectedSenderIdentity: publicIdentity(sender),
});

console.log(new TextDecoder().decode(opened.plaintext));
