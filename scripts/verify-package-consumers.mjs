import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const temporary=await mkdtemp(join(tmpdir(),'enigm-consumer-'));
try {
 execFileSync('npm',['pack','--ignore-scripts','--pack-destination',temporary],{stdio:'pipe'});
 const tarball=(await readdir(temporary)).find(name=>name.endsWith('.tgz'));
 const installed=join(temporary,'node_modules/@enigm/crypto');await mkdir(installed,{recursive:true});
 execFileSync('tar',['-xzf',join(temporary,tarball),'--strip-components=1','-C',installed]);
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
