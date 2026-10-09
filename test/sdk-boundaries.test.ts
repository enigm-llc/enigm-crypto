import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnigmTransparencyVerifier } from '../src/sdk/index.ts';
import { buildProof } from './fixtures/transparency.ts';
const setup=(configuration:Record<string,unknown>={})=>{
 const rows=new Map<string,string>();
 const store={read:async(key:string)=>rows.get(key)??null,write:async(key:string,value:string)=>{rows.set(key,value);},delete:async(key:string)=>{rows.delete(key);},exclusive:async<T>(_id:string,action:()=>Promise<T>)=>action()};
 return {rows,verifier:createEnigmTransparencyVerifier({store,origin:'keys.localhost/v1',logPublicKey:'Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=',witnesses:[],quorum:0,fetchConsistencyProof:async()=>({version:1,oldSize:1,newSize:2,proof:[]}),...configuration})};
};
test('invalid checkpoint consistency is rejected before durable advance',async()=>{
 const {rows,verifier}=setup();await verifier.verifyIdentity({accountId:'local',...buildProof()});
 const before=JSON.stringify([...rows]);
 await assert.rejects(verifier.verifyIdentity({accountId:'local',...buildProof(2)}),/INVALID_CONSISTENCY_PROOF/);
 assert.equal(JSON.stringify([...rows]),before);
});
test('missing witness quorum cannot bootstrap trust and invalid quorum configuration fails closed',async()=>{
 const options={witnesses:[{name:'witness.test/v1',publicKey:'Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo='}],quorum:1};
 const {rows,verifier}=setup(options);
 await assert.rejects(verifier.verifyIdentity({accountId:'local',...buildProof()}),/WITNESS_QUORUM_UNAVAILABLE/);
 assert.equal(rows.size,0);
 assert.throws(()=>setup({quorum:1}),/INVALID_WITNESS_CONFIGURATION/);
});
test('trust reset shares the account lock with checkpoint acceptance', async () => {
 let locked = false;
 const store = {
  read: async () => null,
  write: async () => {},
  delete: async () => { assert.equal(locked, true, 'delete must hold account lock'); },
  exclusive: async <T>(id: string, action: () => Promise<T>) => {
   assert.equal(id, 'local'); locked = true;
   try { return await action(); } finally { locked = false; }
  },
 };
 const verifier = createEnigmTransparencyVerifier({store,origin:'keys.localhost/v1',logPublicKey:'Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=',witnesses:[],quorum:0,fetchConsistencyProof:async()=>null});
 await verifier.deleteState('local');
});

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, utf8, encodeBase64, decodeBase64, c2spCheckpointText, encodeC2spWitnessTimestamp } from '../src/index.ts';
const witnessed = (fixture: ReturnType<typeof buildProof>) => {
 const secret=new Uint8Array(32).fill(12), publicKey=ed25519.getPublicKey(secret), name='witness.test/v1', timestamp=1_800_000_000;
 const checkpoint={origin:'keys.localhost/v1',size:fixture.proof.treeSize,rootHash:decodeBase64(fixture.proof.rootHash)};
 const keyId=sha256(concat(utf8(name),Uint8Array.of(10,4),publicKey)).slice(0,4);
 const signature=ed25519.sign(utf8(`cosignature/v1\ntime ${timestamp}\n${c2spCheckpointText(checkpoint)}`),secret);
 const line=`— ${name} ${encodeBase64(concat(keyId,encodeC2spWitnessTimestamp(timestamp),signature))}\n`;
 fixture.proof.witnessCosignatures=[line];fixture.proof.stateAnchor.witnessCosignatures=[line];
 return {name,publicKey:encodeBase64(publicKey)};
};
test('witnesses are counted once and loss of quorum permits only previously witnessed identities',async()=>{
 const fixture=buildProof();const witness=witnessed(fixture);
 const {verifier,rows}=setup({witnesses:[witness,witness],quorum:1,now:()=>1_800_000_000_000});
 assert.equal((await verifier.verifyIdentity({accountId:'local',...fixture})).verified,1);
 const uncosigned=buildProof();
 assert.equal((await verifier.verifyIdentity({accountId:'local',...uncosigned})).quorumMet,false);
 assert.ok(rows.size>0);
 const fresh=setup({witnesses:[witness],quorum:1,now:()=>1_800_000_000_000});
 await assert.rejects(fresh.verifier.verifyIdentity({accountId:'local',...uncosigned}),/WITNESS_QUORUM_UNAVAILABLE/);
 assert.throws(()=>setup({witnesses:[witness,witness],quorum:2}),/INVALID_WITNESS_CONFIGURATION/);
});
test('oversized and malformed identity proofs cannot write trust',async()=>{
 for(const mutate of [
  (proof:ReturnType<typeof buildProof>['proof'])=>{proof.inclusionProof=Array(64).fill(encodeBase64(new Uint8Array(32)));},
  (proof:ReturnType<typeof buildProof>['proof'])=>{proof.stateMembership.path=Array(129).fill({side:'LEFT',parentIdentityKeyCommitment:encodeBase64(new Uint8Array(32)),parentAction:'ACTIVATE',siblingHash:encodeBase64(new Uint8Array(32))});},
  (proof:ReturnType<typeof buildProof>['proof'])=>{proof.stateMembership.path=[{side:'INVALID',parentIdentityKeyCommitment:encodeBase64(new Uint8Array(32)),parentAction:'ACTIVATE',siblingHash:encodeBase64(new Uint8Array(32))}];},
 ]) {
  const {verifier,rows}=setup();const fixture=buildProof();mutate(fixture.proof);
  await assert.rejects(verifier.verifyIdentity({accountId:'local',...fixture}));assert.equal(rows.size,0);
 }
});
test('trust capacity and failed checkpoint persistence reject acceptance',async()=>{
 const fixture=buildProof();const witness=witnessed(fixture);
 const {verifier,rows}=setup({witnesses:[witness],quorum:1,now:()=>1_800_000_000_000});
 const identities=Array.from({length:4096},(_,n)=>{const value=new Uint8Array(32);new DataView(value.buffer).setUint32(0,n);return encodeBase64(value);});
 rows.set(`trust:${Buffer.from(sha256(utf8('local'))).toString('hex')}`,JSON.stringify(identities));
 const before=JSON.stringify([...rows]);
 await assert.rejects(verifier.verifyIdentity({accountId:'local',...fixture}),/TRUSTED_IDENTITY_CAPACITY/);assert.equal(JSON.stringify([...rows]),before);
 const failed=setup({store:{read:async()=>null,write:async()=>{throw new Error('storage unavailable');},delete:async()=>{},exclusive:async<T>(_id:string,action:()=>Promise<T>)=>action()}});
 await assert.rejects(failed.verifier.verifyIdentity({accountId:'local',...buildProof()}),/storage unavailable/);
});

test('historical witness signatures cannot bootstrap new trust beyond the freshness window', async () => {
 const fixture = buildProof(); const witness = witnessed(fixture);
 const { verifier, rows } = setup({witnesses:[witness],quorum:1,now:()=>1_800_000_000_000 + 10 * 365 * 86400 * 1000});
 await assert.rejects(verifier.verifyIdentity({accountId:'local',...fixture}),/WITNESS_QUORUM_UNAVAILABLE/);
 assert.equal(rows.size,0);
});
test('configured witness freshness includes its exact boundary and rejects older signatures', async () => {
 const fixture = buildProof(); const witness = witnessed(fixture);
 const configuration = {witnesses:[witness],quorum:1,maximumWitnessAgeSeconds:100};
 await setup({...configuration,now:()=>1_800_000_100_000}).verifier.verifyIdentity({accountId:'local',...fixture});
 await assert.rejects(setup({...configuration,now:()=>1_800_000_101_000}).verifier.verifyIdentity({accountId:'local',...fixture}),/WITNESS_QUORUM_UNAVAILABLE/);
 for (const maximumWitnessAgeSeconds of [0,-1,Infinity,1.5]) {
  assert.throws(()=>setup({...configuration,maximumWitnessAgeSeconds}),/INVALID_WITNESS_CONFIGURATION/);
 }
});

test('stale witnesses preserve only explicit prior-identity continuity, not fresh quorum', async () => {
 const fixture=buildProof(); const witness=witnessed(fixture);
 let now=1_800_000_000_000;
 const {verifier}=setup({witnesses:[witness],quorum:1,now:()=>now,maximumWitnessAgeSeconds:100});
 assert.equal((await verifier.verifyIdentity({accountId:'local',...fixture})).quorumMet,true);
 now+=101_000;
 const result=await verifier.verifyIdentity({accountId:'local',...fixture});
 assert.equal(result.quorumMet,false);
 assert.equal(result.verified,0);
});
