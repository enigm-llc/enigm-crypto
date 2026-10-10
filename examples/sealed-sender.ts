import {
  equal,
  generateIdentity,
  generateKemBundle,
  openSealedSender,
  publicIdentity,
  publicKemBundle,
  sealSender,
  utf8,
  wipe,
} from '@enigm/crypto';

const sender = generateIdentity();
const recipient = generateIdentity();
const recipientBundle = generateKemBundle(recipient, Date.now() + 60_000);
const context = utf8('example:sealed-sender:message:1');
const expectedPlaintext = utf8('authenticated without exposing the sender to the relay');

let recovered: Uint8Array | undefined;
try {
  const envelope = sealSender({
    sender,
    recipientIdentity: publicIdentity(recipient),
    recipient: publicKemBundle(recipientBundle),
    plaintext: expectedPlaintext,
    context,
  });

  const opened = openSealedSender({
    recipientIdentity: publicIdentity(recipient),
    recipient: recipientBundle,
    envelope,
    context,
    expectedSenderIdentity: publicIdentity(sender),
  });

  recovered = opened.plaintext;
  if (!equal(opened.plaintext, expectedPlaintext)) {
    throw new Error('Sealed sender round-trip failed.');
  }
  process.stdout.write('sealed sender round-trip verified\n');
} finally {
  wipe(expectedPlaintext, sender.mlDsaSecretKey, sender.ed25519SecretKey,
    recipient.mlDsaSecretKey, recipient.ed25519SecretKey,
    recipientBundle.mlKemSecretKey, recipientBundle.x25519SecretKey);
  if (recovered) wipe(recovered);
}
