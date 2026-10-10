import test from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, generateKemBundle, publicKemBundle, encodePublicKemBundle, encodeBase64, createEnigmDeviceClient } from '../src/index.ts';
test('device SDK selects a live last-resort bundle while retaining expired keys for delayed delivery', async () => {
 const entropy=(length:number)=>new Uint8Array(length).fill(7);
 const identity=generateIdentity(entropy);
 const now=Date.now()+2000;
 const expired=generateKemBundle(identity,now-1000,entropy);
 const active=generateKemBundle(identity,now+10000,length=>new Uint8Array(length).fill(9));
 const client=createEnigmDeviceClient({randomSource:entropy,now:()=>now,store:{load:async()=>structuredClone({identity,bundles:[{bundle:expired,lastResort:true},{bundle:active,lastResort:true}]}),consume:async()=>{throw new Error('last resort must not be consumed');},consumeForSession:async()=>{throw new Error('last resort must not be consumed');}}});
 assert.equal(await client.publicLastResortBundleEncoded('alice'),encodeBase64(encodePublicKemBundle(publicKemBundle(active))));
});

test('device SDK bounds encoded public keys and envelopes before wire decoding', async () => {
 const entropy=(length:number)=>new Uint8Array(length).fill(7);
 const identity=generateIdentity(entropy), bundle=generateKemBundle(identity,Date.now()+10000,entropy);
 let consumed=false;
 const client=createEnigmDeviceClient({randomSource:entropy,store:{load:()=>Promise.resolve(structuredClone({identity,bundles:[{bundle,lastResort:false}]})),consume:()=>{consumed=true;return Promise.resolve();}}});
 const oversizedPublic=encodeBase64(new Uint8Array(32*1024+1));
 await assert.rejects(client.sealSession('alice',oversizedPublic,'',Uint8Array.of(1),Uint8Array.of(2)),/too large/);
 const oversizedEnvelope=encodeBase64(new Uint8Array(2*1024*1024+1));
 await assert.rejects(client.openSessionEncodedPending('alice','',oversizedEnvelope,Uint8Array.of(2)),/too large/);
 await assert.rejects(client.consumeOpenedSessionKeyForSession('alice','key','claim'),/idempotent session claims/);
 assert.equal(consumed,false);
 assert.ok(identity.mlDsaSecretKey.some(byte=>byte!==0));
});
