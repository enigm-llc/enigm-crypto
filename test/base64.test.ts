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
