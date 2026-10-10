import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeBase64, decodeBase64 } from '../src/core/base64.ts';
test('canonical base64 works without Buffer and rejects alternate encodings', () => {
  for (let length = 0; length < 256; length++) {
    const bytes = Uint8Array.from({length}, (_, index) => index);
    const encoded = Buffer.from(bytes).toString('base64');
    assert.equal(encodeBase64(bytes), encoded);
    assert.deepEqual(decodeBase64(encoded), bytes);
  }
  for (const bad of ['Zg', 'Zh==', 'Zm9=', 'Zg==\n', '!!!!']) assert.throws(() => decodeBase64(bad));
});

test('bounded base64 rejects oversized decoded data before allocation and accepts the exact boundary', () => {
  const encoded = encodeBase64(new Uint8Array(33));
  assert.throws(() => decodeBase64(encoded, 32), /too large/);
  assert.deepEqual(decodeBase64(encoded, 33), new Uint8Array(33));
  assert.deepEqual(decodeBase64('', 0), new Uint8Array());
  assert.throws(() => decodeBase64('AA==', -1), /limit/);
});
