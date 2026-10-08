import test from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, generateKemBundle, publicKemBundle, encodePublicKemBundle, encodeBase64, createEnigmDeviceClient } from '../src/index.ts';
test('device SDK selects a live last-resort bundle while retaining expired keys for delayed delivery', async () => {
 const entropy=(length:number)=>new Uint8Array(length).fill(7);
 const identity=generateIdentity(entropy);
 const now=Date.now()+2000;
 const expired=generateKemBundle(identity,now-1000,entropy);
 const active=generateKemBundle(identity,now+10000,length=>new Uint8Array(length).fill(9));
 const client=createEnigmDeviceClient({randomSource:entropy,now:()=>now,store:{load:async()=>structuredClone({identity,bundles:[{bundle:expired,lastResort:true},{bundle:active,lastResort:true}]}),consume:async()=>{throw new Error('last resort must not be consumed');}}});
 assert.equal(await client.publicLastResortBundleEncoded('alice'),encodeBase64(encodePublicKemBundle(publicKemBundle(active))));
});
