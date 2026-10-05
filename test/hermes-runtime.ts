// Bundle with the react-native condition and execute in the RN 0.77 Hermes VM.
// This deterministic entropy is ONLY for a test, never for application keys.
import * as api from '@enigm/crypto';

const check = (value: boolean): void => { if (!value) throw new Error('Hermes runtime assertion failed'); };
const equal = (left: Uint8Array, right: Uint8Array): void => check(api.equal(left, right));
let counter = 0;
const entropy = (length: number): Uint8Array => {
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index++) output[index] = (counter++ * 73 + 19) & 255;
  return output;
};
// Hermes has no CSPRNG by default; the app must supply an OS-backed provider.
Object.defineProperty(globalThis, 'crypto', { value: {
  getRandomValues: (output: Uint8Array) => { output.set(entropy(output.length)); return output; },
} });
check(typeof globalThis.TextDecoder === 'undefined');
equal(api.utf8('ñ😀\0\ud800'), Uint8Array.of(0xc3, 0xb1, 0xf0, 0x9f, 0x98, 0x80, 0, 0xef, 0xbf, 0xbd));
const alice = api.generateIdentity(entropy);
const bob = api.generateIdentity(entropy);
const recipientIdentity = api.publicIdentity(bob);
const sender = api.publicIdentity(alice);
const kem = api.generateKemBundle(bob, 4_000_000_000_000, entropy);
const recipient = api.publicKemBundle(kem);
const context = api.utf8('español 中文 😀');
const plaintext = api.utf8('mensaje\0');
check(api.verifyHybrid(sender, context, api.signHybrid(alice, context)));
equal(api.decodePublicIdentity(api.encodePublicIdentity(sender)).keyId, sender.keyId);
check(api.verifyKemBundle(recipientIdentity, api.decodePublicKemBundle(api.encodePublicKemBundle(recipient)), 2_000_000_000_000));
const options = { sender: alice, recipientIdentity, recipient, context, plaintext, now: 2_000_000_000_000, randomSource: entropy };
const envelope = api.decodeEnvelope(api.encodeEnvelope(api.seal(options)));
equal(api.open({ sender, recipientIdentity, recipient: kem, envelope, context, now: options.now }), plaintext);
const sealed = api.decodeSealedSenderEnvelope(api.encodeSealedSenderEnvelope(api.sealSender(options)));
equal(api.openSealedSender({ recipientIdentity, recipient: kem, envelope: sealed, context,
  expectedSenderIdentity: sender, now: options.now }).plaintext, plaintext);
for (const [magic, decode] of [['ENIGMPQ2', api.decodeEnvelope], ['ENIGMSS2', api.decodeSealedSenderEnvelope]] as const) {
  let rejected = false;
  try { decode(api.frame(api.utf8(magic), Uint8Array.of(0xc0, 0x80))); }
  catch (error) { rejected = error instanceof TypeError; }
  check(rejected);
}
(globalThis as unknown as { print: (value: string) => void }).print('Hermes RN 0.77: cold import, UTF-8, identity, KEM, signatures, codecs and both encrypted envelope protocols passed.');
