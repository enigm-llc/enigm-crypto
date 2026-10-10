import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { validateReleaseMetadata } from '../scripts/verify-release.mjs';
const require=createRequire(import.meta.url);
const metadata=require('../package.json');
const lock=require('../package-lock.json');
test('release metadata binds package version, tag, public registry and locked root', () => {
 assert.doesNotThrow(()=>validateReleaseMetadata(metadata,lock,`v${metadata.version}`));
 for(const mutate of [
  (m:typeof metadata)=>{m.name='@other/crypto';},
  (m:typeof metadata)=>{m.publishConfig.registry='https://registry.example.test';},
  (m:typeof metadata)=>{m.publishConfig.access='restricted';},
  (m:typeof metadata)=>{m.publishConfig.tag='next';},
  (m:typeof metadata)=>{m.version='1.0.0-alpha.0';},
  (m:typeof metadata)=>{m.repository.url='git+https://github.com/other/crypto.git';},
  (m:typeof metadata)=>{m.scripts.postinstall='node collect.js';},
 ]) { const changed=structuredClone(metadata);mutate(changed);assert.throws(()=>validateReleaseMetadata(changed,lock,`v${changed.version}`)); }
 assert.throws(()=>validateReleaseMetadata(metadata,lock,'v0.2.1-alpha.0'),/tag/);
 const changedLock=structuredClone(lock);changedLock.packages[''].version='0.1.0';
 assert.throws(()=>validateReleaseMetadata(metadata,changedLock,`v${metadata.version}`),/lock/);
});

test('final release accepts matching stable metadata and rejects prerelease versions', () => {
 const finalMetadata=structuredClone(metadata);
 finalMetadata.version='1.0.0';finalMetadata.publishConfig.tag='latest';
 const finalLock=structuredClone(lock);finalLock.version='1.0.0';finalLock.packages[''].version='1.0.0';
 assert.doesNotThrow(()=>validateReleaseMetadata(finalMetadata,finalLock,'v1.0.0'));
 for(const version of ['0.2.0','1.0.0-alpha.0','01.0.0','1.00.0','1.0.0+build']) {
  const changed=structuredClone(finalMetadata);changed.version=version;
  const changedLock=structuredClone(finalLock);changedLock.version=version;changedLock.packages[''].version=version;
  assert.throws(()=>validateReleaseMetadata(changed,changedLock,`v${version}`),/final release versions/);
 }
});
