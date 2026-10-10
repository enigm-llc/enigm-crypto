// Test-only deterministic entropy: never use this source in an application.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
const mode = process.argv[2];
const nativeEncoder = globalThis.TextEncoder;
const nativeDecoder = globalThis.TextDecoder;
let counter = 0;
const entropy = length => {
  const output = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 32) {
    const block = createHash('sha256').update(`test-only:${counter++}`).digest();
    output.set(block.subarray(0, Math.min(32, length - offset)), offset);
  }
  return output;
};
Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
  getRandomValues: output => { output.set(entropy(output.length)); return output; },
} });
if (mode !== 'native') {
  delete globalThis.TextEncoder;
  delete globalThis.TextDecoder;
  delete globalThis.Buffer;
}
const api = mode === 'cjs'
  ? createRequire(import.meta.url)('@enigm/crypto')
  : await import('@enigm/crypto').then(module => module.default ?? module);
if (mode === 'native') {
  assert.equal(globalThis.TextEncoder, nativeEncoder);
  assert.equal(globalThis.TextDecoder, nativeDecoder);
} else {
  assert.equal(globalThis.TextDecoder, undefined);
  assert.equal(globalThis.TextEncoder, undefined);
  assert.equal(globalThis.Buffer, undefined);
}
const alice = api.generateIdentity(entropy);
const bob = api.generateIdentity(entropy);
const expiresAt = 4_000_000_000_000;
const now = 2_000_000_000_000;
const kem = api.generateKemBundle(bob, expiresAt, entropy);
const alicePublic = api.publicIdentity(alice);
const bobPublic = api.publicIdentity(bob);
const kemPublic = api.publicKemBundle(kem);
const context = api.utf8('español 😀 中文\0\ud800');
const plaintext = api.utf8('mensaje privado 😀');
const signature = api.signHybrid(alice, context);
assert(api.verifyHybrid(alicePublic, context, signature));
assert(!api.verifyHybrid(alicePublic, Uint8Array.of(1), signature));
assert(api.verifyKemBundle(bobPublic, kemPublic, now));
const identityWire = api.encodePublicIdentity(alicePublic);
assert.deepEqual(api.decodePublicIdentity(identityWire), alicePublic);
const kemWire = api.encodePublicKemBundle(kemPublic);
assert.deepEqual(api.decodePublicKemBundle(kemWire), kemPublic);
const options = { sender: alice, recipientIdentity: bobPublic, recipient: kemPublic,
  context, plaintext, now, randomSource: entropy };
const wire = api.encodeEnvelope(api.seal(options));
assert.deepEqual(api.open({ recipient: kem, sender: alicePublic, recipientIdentity: bobPublic,
  envelope: api.decodeEnvelope(wire), context, now }), plaintext);
const sealedWire = api.encodeSealedSenderEnvelope(api.sealSender(options));
assert.deepEqual(api.openSealedSender({ recipientIdentity: bobPublic, recipient: kem,
  envelope: api.decodeSealedSenderEnvelope(sealedWire), context,
  expectedSenderIdentity: alicePublic, now }).plaintext, plaintext);

// Replace the framed version/suite without changing any other bytes.
const replaceField = (wire, field, bytes) => {
  let offset = 0;
  for (let index = 0; index < field; index++) offset += 4 + new DataView(wire.buffer, wire.byteOffset + offset, 4).getUint32(0);
  const length = new DataView(wire.buffer, wire.byteOffset + offset, 4).getUint32(0);
  return api.concat(wire.subarray(0, offset), api.frame(bytes), wire.subarray(offset + 4 + length));
};
for (const [encoded, decode] of [[identityWire, api.decodePublicIdentity], [kemWire, api.decodePublicKemBundle],
  [wire, api.decodeEnvelope], [sealedWire, api.decodeSealedSenderEnvelope]]) {
  for (const field of [1, 2]) {
    for (const invalid of [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xc2]]) {
      assert.throws(() => decode(replaceField(encoded, field, Uint8Array.from(invalid))),
        field === 1 && invalid.length > 2 ? Error : TypeError);
    }
    const text = field === 1 ? String(api.PROTOCOL_VERSION) : api.CIPHER_SUITE;
    if (field === 2) assert.deepEqual(decode(replaceField(encoded, field, api.utf8('\ufeff' + text))), decode(encoded));
  }
}
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
console.log(JSON.stringify([identityWire, kemWire, wire, sealedWire, signature.mlDsa,
  signature.ed25519, context].map(digest)));
