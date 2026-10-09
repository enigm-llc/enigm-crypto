import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const validateReleaseMetadata = (metadata, lock, tag) => {
  if (metadata.name !== '@enigm/crypto' || metadata.license !== 'Apache-2.0' || metadata.private === true)
    throw new Error('Invalid public package identity or license.');
  if (!/^[1-9]\d*\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(metadata.version))
    throw new Error('This workflow permits final release versions starting at 1.0.0 only.');
  if (tag !== undefined && tag !== `v${metadata.version}`) throw new Error('Release tag does not match package version.');
  if (metadata.publishConfig?.access !== 'public' || metadata.publishConfig?.tag !== 'latest' ||
      metadata.publishConfig?.registry !== 'https://registry.npmjs.org')
    throw new Error('Invalid public npm release configuration.');
  if (metadata.repository?.url !== 'git+https://github.com/enigm-llc/enigm-crypto.git')
    throw new Error('Repository URL does not match release provenance.');
  if (lock.name !== metadata.name || lock.version !== metadata.version ||
      lock.packages?.['']?.name !== metadata.name || lock.packages?.['']?.version !== metadata.version)
    throw new Error('Package lock root does not match release metadata.');
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (metadata.scripts?.[hook]) throw new Error('Consumer install lifecycle hooks are forbidden.');
  }
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--tag')) throw new Error('Usage: verify-release.mjs [--tag vVERSION]');
  const root = new URL('../', import.meta.url);
  const metadata = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
  const lock = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8'));
  validateReleaseMetadata(metadata, lock, args[1]);
  console.log(`Release metadata verified: ${metadata.name}@${metadata.version}, public latest release target.`);
}
