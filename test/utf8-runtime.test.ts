import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';

test('cold source import and UTF-8 encoding work without web text APIs', () => {
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    const encoder = new TextEncoder();
    const values = ['', 'ASCII', 'español', '😀', '中文日本語', '\\0', '\\ud800', '\\udc00', '\\ud800A', '\\ud800\\ud800\\udc00'];
    const expected = values.map(value => encoder.encode(value));
    delete globalThis.TextEncoder;
    delete globalThis.TextDecoder;
    delete globalThis.Buffer;
    const api = await import('./src/index.ts');
    values.forEach((value, index) => assert.deepEqual(api.utf8(value), expected[index]));
    const fallback = new globalThis.TextEncoder();
    assert.equal(fallback.encoding, 'utf-8');
    assert.deepEqual(fallback.encode(), new Uint8Array());
    for (const value of values) {
      for (let size = 0; size <= value.length * 3 + 1; size++) {
        const actual = new Uint8Array(size).fill(0xaa);
        const wanted = new Uint8Array(size).fill(0xaa);
        assert.deepEqual(fallback.encodeInto(value, actual), encoder.encodeInto(value, wanted));
        assert.deepEqual(actual, wanted);
      }
    }
    assert.equal(globalThis.TextDecoder, undefined);
  `], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
