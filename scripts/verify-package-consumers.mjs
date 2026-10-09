import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir, access } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, isAbsolute } from 'node:path';
// npm run provides its already-running CLI path; direct invocation also supports
// standard Node and distribution layouts. No executable is searched through PATH.
const npmCliCandidates = [
 ...(process.env.npm_execpath && isAbsolute(process.env.npm_execpath) ? [process.env.npm_execpath] : []),
 join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
 join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
 '/usr/share/nodejs/npm/bin/npm-cli.js',
];
const npmCli = (await Promise.all(npmCliCandidates.map(async path => {
 try { await access(path); return path; } catch { return null; }
}))).find(Boolean);
if (!npmCli) throw new Error('npm CLI not found; run this check through npm run test:package.');
const tarExecutable = process.platform === 'win32'
 ? join(process.env.SystemRoot ?? String.raw`C:\Windows`, 'System32', 'tar.exe')
 : '/usr/bin/tar';
const temporary=await mkdtemp(join(tmpdir(),'enigm-consumer-'));
const tsxLoader = createRequire(import.meta.url).resolve('tsx');
// Resolve relative npm cache configuration before changing the consumer cwd.
const consumerEnv = { ...process.env };
if (consumerEnv.npm_config_cache) consumerEnv.npm_config_cache = resolve(consumerEnv.npm_config_cache);
try {
 execFileSync(process.execPath,[npmCli,'pack','--ignore-scripts','--pack-destination',temporary],{stdio:'pipe'});
 const tarball=(await readdir(temporary)).find(name=>name.endsWith('.tgz'));
 const installed=join(temporary,'node_modules/@enigm/crypto');await mkdir(installed,{recursive:true});
 execFileSync(tarExecutable,['-xzf',join(temporary,tarball),'--strip-components=1','-C',installed]);
 // Deliberately no dependencies or development tools installed in the consumer.
 for(const mode of ['import','require','react-native']){
  const source=`delete globalThis.TextEncoder;delete globalThis.TextDecoder;delete globalThis.Buffer;
    const api=${mode==='require'?"require('@enigm/crypto')":"await import('@enigm/crypto').then(m=>m.default??m)"};
    if(typeof api.seal!=='function'||typeof api.createEnigmMessageClient!=='function')throw Error('Missing root API');
    if(globalThis.TextEncoder||globalThis.TextDecoder||globalThis.Buffer)throw Error('Global mutation');`;
  execFileSync(process.execPath,[...(mode==='react-native'?['--conditions=react-native']:[]),...(mode==='require'?[]:['--input-type=module']),'-e',source],{cwd:temporary,stdio:'pipe'});
 }
 for(const name of ['core','primitives','protocols','codecs','sdk']){
  execFileSync(process.execPath,['--input-type=module','-e',`delete globalThis.TextEncoder;delete globalThis.TextDecoder;delete globalThis.Buffer;const api=await import('@enigm/crypto/${name}');if(!Object.keys(api).length)throw Error('Empty module');if(globalThis.TextEncoder||globalThis.TextDecoder)throw Error('Global mutation');`],{cwd:temporary,stdio:'pipe'});
 }
 await writeFile(join(temporary,'consumer.mts'),"import { generateIdentity, createEnigmMessageClient } from '@enigm/crypto';\nimport { utf8 } from '@enigm/crypto/core';\nimport { encryptEnigmAttachment } from '@enigm/crypto/sdk';\nvoid generateIdentity;void createEnigmMessageClient;void encryptEnigmAttachment;utf8('hello');\n");
 await writeFile(join(temporary,'consumer.cts'),"import crypto = require('@enigm/crypto');\ncrypto.utf8('hello');\nvoid crypto.createEnigmMessageClient;\n");
 execFileSync(process.execPath,[resolve('node_modules/typescript/bin/tsc'),'--noEmit','--strict','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2022',join(temporary,'consumer.mts'),join(temporary,'consumer.cts')],{cwd:temporary,stdio:'pipe'});
 assert((await readdir(join(temporary,'node_modules'))).length===1);
 console.log('Packed consumers passed: ESM, CJS, React Native, modular imports and TypeScript; no host text globals; bundled imports execute without external dependency resolution.');
 const consumer = join(temporary, 'npm-installed');
 await mkdir(consumer);
 await writeFile(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
 execFileSync(process.execPath, [npmCli, 'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', join(temporary, tarball)], {
  cwd: consumer, env: consumerEnv, stdio: 'inherit',
 });
 const consumerPackage = join(consumer, 'node_modules/@enigm/crypto');
 const manifest = JSON.parse(await readFile(join(consumerPackage, 'package.json'), 'utf8'));
 for (const [name, version] of Object.entries(manifest.dependencies ?? {})) {
  const dependency = JSON.parse(await readFile(join(consumer, 'node_modules', name, 'package.json'), 'utf8'));
  assert.equal(dependency.version, version, `Installed dependency version differs: ${name}`);
 }
 const exampleNames = (await readdir(join(consumerPackage, 'examples'))).filter(name => name.endsWith('.ts')).sort();
 const entryNames = exampleNames.filter(name => name !== 'demo-storage.ts');
 assert(exampleNames.length > 0, 'No shipped examples');
 const publicExamples = join(consumer, 'examples');
 await mkdir(publicExamples);
 const publicExamplePaths = [];
 for (const name of exampleNames) {
  // Copy without rewriting so public imports and local example helpers are checked exactly as shipped.
  const source = await readFile(join(consumerPackage, 'examples', name), 'utf8');
  assert(!/['"]\.\.\/src\//.test(source), `Development-source import in shipped example ${name}`);
  const examplePath = join(publicExamples, name);
  await writeFile(examplePath, source);
  publicExamplePaths.push(examplePath);
 }
 for (const name of entryNames) execFileSync(process.execPath, ['--import', tsxLoader, join(publicExamples, name)], { cwd: consumer, stdio: 'inherit' });
 execFileSync(process.execPath, [resolve('node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--typeRoots', resolve('node_modules/@types'), ...publicExamplePaths], { cwd: consumer, stdio: 'inherit' });
 console.log(`Offline npm tarball installation passed with declared dependencies; ${entryNames.length} exact shipped example entrypoints executed and all example sources typechecked. The example runner and typechecker are repository development tools.`);
}finally{await rm(temporary,{recursive:true,force:true});}
