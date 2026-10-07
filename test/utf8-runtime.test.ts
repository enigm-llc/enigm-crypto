import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';

test('cold core import and UTF-8 encoding work without web text APIs', () => {
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    const encoder = new TextEncoder();
    const values = ['', 'ASCII', 'español', '😀', '中文日本語', '\\0', '\\ud800', '\\udc00', '\\ud800A', '\\ud800\\ud800\\udc00'];
    const expected = values.map(value => encoder.encode(value));
    delete globalThis.TextEncoder;
    delete globalThis.TextDecoder;
    delete globalThis.Buffer;
    const api = await import('./src/core/bytes.ts');
    values.forEach((value, index) => assert.deepEqual(api.utf8(value), expected[index]));
    assert.equal(globalThis.TextEncoder, undefined);
    assert.equal(globalThis.TextDecoder, undefined);
  `], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
