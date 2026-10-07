// Bundle with the react-native condition and execute in the RN 0.77 Hermes VM.
// This deterministic entropy is ONLY for a test, never for application keys.
import * as api from '@enigm/crypto';

let assertion = 0;
const check = (value: boolean): void => { assertion++; if (!value) throw new Error(`Hermes runtime assertion ${assertion} failed`); };
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
const attachment = api.encryptEnigmAttachment(Uint8Array.of(0, 255, 128, 10), entropy);
equal(api.decryptEnigmAttachment(attachment.encrypted, attachment.fileKey), Uint8Array.of(0, 255, 128, 10));
check(typeof globalThis.TextEncoder === 'undefined');
check(typeof globalThis.TextDecoder === 'undefined');
check(typeof (globalThis as unknown as { Buffer?: unknown }).Buffer === 'undefined');
(globalThis as unknown as { print: (value: string) => void }).print('Hermes RN 0.77: cold import, UTF-8, identity, KEM, signatures, codecs and both encrypted envelope protocols and SDK binary attachments passed.');

import binding from './fixtures/hermes-binding.json';
const runSdk = async (): Promise<void> => {
  const sdkAlice = api.generateIdentity(n => new Uint8Array(n).fill(1));
  const sdkBob = api.generateIdentity(n => new Uint8Array(n).fill(2));
  const bundles = {
    alice: api.generateKemBundle(sdkAlice, 4_000_000_000_000, entropy),
    bob: api.generateKemBundle(sdkBob, 4_000_000_000_000, entropy),
  };
  let consumed = 0;
  const device = api.createEnigmDeviceClient({randomSource:entropy, now:()=>2_000_000_000_000,store:{
    load: async (id: string) => {
      const identity = id === 'alice' ? sdkAlice : sdkBob;
      const bundle = id === 'alice' ? bundles.alice : bundles.bob;
      return {identity:{...identity,mlDsaSecretKey:identity.mlDsaSecretKey.slice(),ed25519SecretKey:identity.ed25519SecretKey.slice()},bundles:[{lastResort:id==='alice',bundle:{...bundle,mlKemSecretKey:bundle.mlKemSecretKey.slice(),x25519SecretKey:bundle.x25519SecretKey.slice()}}]};
    },
    consume:async()=>{ consumed++; },
  }});
  const rows = new Map<string,string>();
  const sessions = api.createEnigmSessionClient({randomSource:entropy,store:{
    read:async id=>rows.get(id)??null,write:async(id,value)=>{rows.set(id,value);},delete:async id=>{rows.delete(id);},exclusive:async(_id,action)=>action(),
  }});
  const messages = api.createEnigmMessageClient({device,sessions,randomSource:entropy,logPublicKey:binding.logPublicKey});
  const target={userId:'bob',deviceId:'bob-device',encodedIdentity:await device.publicIdentityEncoded('bob'),encodedBundle:api.encodeBase64(api.encodePublicKemBundle(api.publicKemBundle(bundles.bob))),identityKeyId:api.encodeBase64(sdkBob.keyId)};
  for (const messageId of ['bootstrap','established']) {
    const plaintext=api.utf8(`Hermes texto 😀 ${messageId}`);
    const encrypted=await messages.encryptMessage({accountId:'alice',conversationId:'hermes',messageId,senderDeviceId:'alice-device',senderBinding:binding.senderBinding,plaintext,targets:[target]});
    equal(await messages.decryptMessage({accountId:'bob',conversationId:'hermes',messageId,currentDeviceId:'bob-device',expectedSenderUserId:'alice',encrypted}),plaintext);
  }
  check(consumed===1);
  check(typeof globalThis.TextEncoder==='undefined' && typeof globalThis.TextDecoder==='undefined');
  (globalThis as unknown as {print:(value:string)=>void}).print('Hermes SDK: authenticated text bootstrap and established sessions passed.');
};
runSdk().catch(error=>{ throw error; });
