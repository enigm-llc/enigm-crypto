import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const modules = process.argv[2];
if (!modules) throw new Error('Usage: node scripts/verify-hermes-runtime.mjs /path/to/rn-app/node_modules');
const require = createRequire(import.meta.url);
// Use esbuild from the existing locked tsx development toolchain.
const { build } = createRequire(require.resolve('tsx/package.json'))('esbuild');
const mobileRequire = createRequire(join(resolve(modules), 'package.json'));
const babel = mobileRequire('@babel/core');
const preset = mobileRequire.resolve('@react-native/babel-preset');
const hermes = join(resolve(modules), 'react-native/sdks/hermesc/osx-bin/hermes');
const temporary = await mkdtemp(join(tmpdir(), 'enigm-hermes-'));
try {
  const bundle = join(temporary, 'bundle.js');
  const transformed = join(temporary, 'hermes.js');
  await build({ entryPoints: ['test/hermes-runtime.ts'], outfile: bundle,
    bundle: true, platform: 'neutral', conditions: ['react-native'], target: 'es2020' });
  const result = babel.transformSync(await readFile(bundle, 'utf8'), {
    presets: [[preset, { enableBabelRuntime: false }]], babelrc: false, configFile: false,
  });
  await writeFile(transformed, 'delete globalThis.TextEncoder;\ndelete globalThis.TextDecoder;\n' + result.code);
  const execution = spawnSync(hermes, [transformed], { encoding: 'utf8' });
  assert.equal(execution.status, 0, execution.stderr);
  assert.match(execution.stdout, /Hermes SDK: authenticated text bootstrap and established sessions passed\./, execution.stderr);
  console.log(execution.stdout.trim());
} finally {
  await rm(temporary, { recursive: true, force: true });
}
