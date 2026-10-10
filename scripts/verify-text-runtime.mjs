import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const run = (mode, conditions = []) => {
  const result = spawnSync(process.execPath,
    [...conditions, 'test/runtime-protocols.mjs', mode], { encoding: 'utf8' });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};
const native = run('native');
// Captured with the same test-only entropy on upstream 44bb45575bb5ad3ea9ae125aa021af49395380f5.
const expected = readFileSync(new URL('../test/runtime-protocols.expected.json', import.meta.url), 'utf8').trim();
assert.equal(native, expected, 'protocol bytes/signatures changed from upstream');
for (const [mode, conditions] of [['esm', []], ['cjs', []], ['rn', ['--conditions=react-native']]]) {
  assert.equal(run(mode, conditions), native, `${mode}: protocol bytes/signatures differ`);
}
console.log('ESM, CJS and react-native: cold imports, strict decoding and identical protocol/signature bytes passed.');
