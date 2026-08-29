import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = new URL('..', import.meta.url).pathname;
const temporary = await mkdtemp(join(tmpdir(), 'enigm-crypto-pack-'));
const pack = (directory) => {
  const result = spawnSync('npm', ['pack', '--ignore-scripts', '--pack-destination', directory], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(result.stderr || 'npm pack failed.');
};
const digest = async (path) =>
  createHash('sha256').update(await readFile(path)).digest('hex');

try {
  const first = join(temporary, 'first');
  const second = join(temporary, 'second');
  await Promise.all([
    import('node:fs/promises').then(({ mkdir }) => mkdir(first)),
    import('node:fs/promises').then(({ mkdir }) => mkdir(second)),
  ]);
  pack(first);
  pack(second);
  const [firstFiles, secondFiles] = await Promise.all([readdir(first), readdir(second)]);
  if (firstFiles.length !== 1 || secondFiles.length !== 1 || firstFiles[0] !== secondFiles[0]) {
    throw new Error('Package output is not stable.');
  }
  const [firstHash, secondHash] = await Promise.all([
    digest(join(first, firstFiles[0])),
    digest(join(second, secondFiles[0])),
  ]);
  if (firstHash !== secondHash) throw new Error('Package tarball is not reproducible.');
  process.stdout.write(`${firstFiles[0]} sha256:${firstHash}\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

