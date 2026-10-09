import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir, access } from 'node:fs/promises';
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
 console.log('Packed consumers passed: ESM, CJS, React Native, modular imports and TypeScript; no host text globals or runtime dependencies.');
}finally{await rm(temporary,{recursive:true,force:true});}
