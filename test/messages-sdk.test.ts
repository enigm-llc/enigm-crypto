import assert from "node:assert/strict";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  generateIdentity,
  generateKemBundle,
  publicIdentity,
  encodePublicIdentity,
  encodePublicKemBundle,
  publicKemBundle,
  utf8,
} from "../src/index.ts";
import { decodeBase64, encodeBase64 } from "../src/core/base64.ts";
import {
  createEnigmSessionClient,
  createEnigmDeviceClient,
  createEnigmMessageClient,
} from "../src/sdk/index.ts";
const random = (length: number) => new Uint8Array(length).fill(7);
const alterBase64Byte = (value: string): string => {
  const decoded = decodeBase64(value);
  decoded[decoded.length - 1] ^= 1;
  return encodeBase64(decoded);
};
const memory = () => {
  const rows = new Map<string, string>();
  const queues = new Map<string, Promise<unknown>>();
  return {
    rows,
    read: async (id: string) => rows.get(id) ?? null,
    write: async (id: string, value: string) => {
      rows.set(id, value);
    },
    delete: async (id: string) => {
      rows.delete(id);
    },
    exclusive: <T>(id: string, action: () => Promise<T>): Promise<T> => {
      const operation = (queues.get(id) ?? Promise.resolve())
        .catch(() => {})
        .then(action);
      queues.set(id, operation);
      return operation;
    },
  };
};
const setup = (settings: { failSessionConsumeOnce?: boolean } = {}) => {
  const alice = generateIdentity((length) => new Uint8Array(length).fill(1));
  const bob = generateIdentity((length) => new Uint8Array(length).fill(2));
  const expiry = Date.now() + 600000;
  const material = {
    alice: {
      identity: alice,
      bundles: [
        { bundle: generateKemBundle(alice, expiry, random), lastResort: true },
      ],
    },
    bob: {
      identity: bob,
      bundles: [
        { bundle: generateKemBundle(bob, expiry, random), lastResort: false },
      ],
    },
  };
  const consumed: string[] = [];
  const sessionClaims = new Map<string, string>();
  const finalizedSessionClaims = new Set<string>();
  let sessionConsumeAttempts = 0;
  const device = createEnigmDeviceClient({
    randomSource: random,
    store: {
      load: async (id) => structuredClone(material[id as "alice" | "bob"]),
      consume: async (_account, id) => {
        consumed.push(id);
      },
      reserveForSession: async (_account, id, claimId) => {
        const existing = sessionClaims.get(id);
        if (existing !== undefined && existing !== claimId) {
          throw new Error("One-time key already claimed by another session");
        }
        if (existing === undefined) sessionClaims.set(id, claimId);
      },
      consumeForSession: async (_account, id, claimId) => {
        sessionConsumeAttempts += 1;
        if (settings.failSessionConsumeOnce && sessionConsumeAttempts === 1) {
          throw new Error("Simulated one-time key store failure");
        }
        const existing = sessionClaims.get(id);
        if (existing !== undefined && existing !== claimId) {
          throw new Error("One-time key already claimed by another session");
        }
        if (existing === undefined) sessionClaims.set(id, claimId);
        if (!finalizedSessionClaims.has(id)) {
          finalizedSessionClaims.add(id);
          consumed.push(id);
        }
      },
    },
  });
  const store = memory();
  const sessions = createEnigmSessionClient({ store, randomSource: random });
  const logSecret = new Uint8Array(32).fill(11);
  const logPublicKey = encodeBase64(ed25519.getPublicKey(logSecret));
  const client = createEnigmMessageClient({
    device,
    sessions,
    randomSource: random,
    logPublicKey,
  });
  const senderBinding = {
    identityKeyId: encodeBase64(alice.keyId),
    accountCommitment: encodeBase64(new Uint8Array(32).fill(3)),
    deviceCommitment: encodeBase64(new Uint8Array(32).fill(4)),
    bindingSignature: "",
  };
  senderBinding.bindingSignature = encodeBase64(
    ed25519.sign(
      utf8(
        JSON.stringify([
          "enigm-key-transparency-binding-v2",
          "alice",
          "alice-device",
          senderBinding.identityKeyId,
          senderBinding.accountCommitment,
          senderBinding.deviceCommitment,
        ])
      ),
      logSecret
    )
  );
  return {
    client,
    device,
    sessions,
    store,
    consumed,
    sessionClaims,
    get sessionConsumeAttempts() { return sessionConsumeAttempts; },
    senderBinding,
    bob,
    bobPrekeyId: encodeBase64(material.bob.bundles[0]!.bundle.keyId),
    alice,
    bobBundle: encodeBase64(
      encodePublicKemBundle(publicKemBundle(material.bob.bundles[0]!.bundle))
    ),
  };
};
test("message SDK round-trips sender-local, bootstrap and established-session packets", async () => {
  const f = setup();
  const targets = [
    { userId: "alice", deviceId: "alice-device" },
    {
      userId: "bob",
      deviceId: "bob-device",
      encodedIdentity: await f.device.publicIdentityEncoded("bob"),
      encodedBundle: f.bobBundle,
      identityKeyId: encodeBase64(f.bob.keyId),
    },
  ];
  for (const messageId of ["one", "two"]) {
    const encrypted = await f.client.encryptMessage({
      accountId: "alice",
      conversationId: "c",
      messageId,
      senderDeviceId: "alice-device",
      senderBinding: f.senderBinding,
      plaintext: utf8("hola 😀 " + messageId),
      targets,
    });
    for (const [accountId, currentDeviceId] of [
      ["alice", "alice-device"],
      ["bob", "bob-device"],
    ]) {
      const opened = await f.client.decryptMessage({
        accountId,
        conversationId: "c",
        messageId,
        currentDeviceId,
        expectedSenderUserId: "alice",
        encrypted,
      });
      assert.deepEqual(opened, utf8("hola 😀 " + messageId));
    }
  }
  assert.equal(f.consumed.length, 1);
});
test("tampered bootstrap cannot commit state or consume its one-time key", async () => {
  const f = setup();
  const encrypted = await f.client.encryptMessage({
    accountId: "alice",
    conversationId: "c",
    messageId: "m",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("secret"),
    targets: [
      {
        userId: "bob",
        deviceId: "bob-device",
        encodedIdentity: encodeBase64(
          encodePublicIdentity(publicIdentity(f.bob))
        ),
        encodedBundle: f.bobBundle,
        identityKeyId: encodeBase64(f.bob.keyId),
      },
    ],
  });
  encrypted.ciphertext = "AAAA";
  await assert.rejects(
    f.client.decryptMessage({
      accountId: "bob",
      conversationId: "c",
      messageId: "m",
      currentDeviceId: "bob-device",
      expectedSenderUserId: "alice",
      encrypted,
    })
  );
  assert.equal(f.store.rows.has("bob"), false);
  assert.equal(f.consumed.length, 0);
});

test("bootstrap resumes an idempotent one-time key claim before using the committed session", async () => {
  const f = setup({ failSessionConsumeOnce: true });
  const encrypted = await f.client.encryptMessage({
    accountId: "alice",
    conversationId: "c",
    messageId: "m",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("recoverable"),
    targets: [{
      userId: "bob",
      deviceId: "bob-device",
      encodedIdentity: encodeBase64(encodePublicIdentity(publicIdentity(f.bob))),
      encodedBundle: f.bobBundle,
      identityKeyId: encodeBase64(f.bob.keyId),
    }],
  });
  const input = {
    accountId: "bob",
    conversationId: "c",
    messageId: "m",
    currentDeviceId: "bob-device",
    expectedSenderUserId: "alice",
    encrypted,
  };
  await assert.rejects(f.client.decryptMessage(input), /key store failure/);
  const pending = JSON.parse(f.store.rows.get("bob")!);
  assert.equal(Object.keys(pending.pendingPrekeyUses).length, 1);
  await assert.rejects(f.sessions.exportTransferState("bob", "bob-device"), /pending/);
  assert.deepEqual(await f.client.decryptMessage(input), utf8("recoverable"));
  const finalized = JSON.parse(f.store.rows.get("bob")!);
  assert.equal(finalized.pendingPrekeyUses, undefined);
  assert.equal(f.sessionConsumeAttempts, 2);
  assert.equal(f.consumed.length, 1);
});

test("message recovery envelopes authenticate before bootstrap and ratchet commits", async () => {
  const f = setup();
  const base = {
    accountId: "alice",
    conversationId: "c",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("authenticated recovery"),
    targets: [{
      userId: "bob",
      deviceId: "bob-device",
      encodedIdentity: await f.device.publicIdentityEncoded("bob"),
      encodedBundle: f.bobBundle,
      identityKeyId: encodeBase64(f.bob.keyId),
    }],
  };
  const receive = {
    accountId: "bob",
    conversationId: "c",
    currentDeviceId: "bob-device",
    expectedSenderUserId: "alice",
  };
  const first = await f.client.encryptMessage({ ...base, messageId: "one" });
  for (const field of ["nonce", "ciphertext"] as const) {
    const altered = structuredClone(first);
    const recovery = altered.keyPackets[0]!.recoveryContentKey;
    recovery[field] = alterBase64Byte(recovery[field]);
    await assert.rejects(
      f.client.decryptMessage({ ...receive, messageId: "one", encrypted: altered })
    );
    assert.equal(f.store.rows.has("bob"), false);
    assert.equal(f.consumed.length, 0);
  }
  assert.deepEqual(
    await f.client.decryptMessage({ ...receive, messageId: "one", encrypted: first }),
    base.plaintext
  );

  const second = await f.client.encryptMessage({
    ...base,
    messageId: "two",
    plaintext: utf8("established recovery"),
  });
  const before = f.store.rows.get("bob");
  for (const field of ["nonce", "ciphertext"] as const) {
    const altered = structuredClone(second);
    const recovery = altered.keyPackets[0]!.recoveryContentKey;
    recovery[field] = alterBase64Byte(recovery[field]);
    await assert.rejects(
      f.client.decryptMessage({ ...receive, messageId: "two", encrypted: altered })
    );
    assert.equal(f.store.rows.get("bob"), before);
  }
  assert.deepEqual(
    await f.client.decryptMessage({ ...receive, messageId: "two", encrypted: second }),
    utf8("established recovery")
  );
  assert.deepEqual(
    await f.client.decryptMessage({ ...receive, messageId: "two", encrypted: second }),
    utf8("established recovery")
  );
});

test("direct local packets authenticate recovery before returning plaintext", async () => {
  const f = setup();
  const encrypted = await f.client.encryptMessage({
    accountId: "alice",
    conversationId: "local",
    messageId: "one",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("local recovery"),
    targets: [{ userId: "alice", deviceId: "alice-device" }],
  });
  const altered = structuredClone(encrypted);
  altered.keyPackets[0]!.recoveryContentKey.ciphertext = alterBase64Byte(
    altered.keyPackets[0]!.recoveryContentKey.ciphertext
  );
  const before = f.store.rows.get("alice");
  const input = {
    accountId: "alice",
    conversationId: "local",
    messageId: "one",
    currentDeviceId: "alice-device",
    expectedSenderUserId: "alice",
  };
  await assert.rejects(f.client.decryptMessage({ ...input, encrypted: altered }));
  assert.equal(f.store.rows.get("alice"), before);
  assert.deepEqual(
    await f.client.decryptMessage({ ...input, encrypted }),
    utf8("local recovery")
  );
});

test("completed one-time key claims reject reuse before writing another session", async () => {
  const f = setup();
  const target = {
    userId: "bob",
    deviceId: "bob-device",
    encodedIdentity: await f.device.publicIdentityEncoded("bob"),
    encodedBundle: f.bobBundle,
    identityKeyId: encodeBase64(f.bob.keyId),
  };
  const encrypt = (conversationId: string) => f.client.encryptMessage({
    accountId: "alice",
    conversationId,
    messageId: "one",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8(conversationId),
    targets: [target],
  });
  const first = await encrypt("first");
  await f.client.decryptMessage({
    accountId: "bob",
    conversationId: "first",
    messageId: "one",
    currentDeviceId: "bob-device",
    expectedSenderUserId: "alice",
    encrypted: first,
  });
  const before = f.store.rows.get("bob")!;
  const second = await encrypt("second");
  await assert.rejects(
    f.client.decryptMessage({
      accountId: "bob",
      conversationId: "second",
      messageId: "one",
      currentDeviceId: "bob-device",
      expectedSenderUserId: "alice",
      encrypted: second,
    }),
    /claimed by another session/
  );
  assert.equal(f.store.rows.get("bob"), before);
  const stored = JSON.parse(before);
  assert.equal(Object.keys(stored.sessions).length, 1);
  assert.equal(stored.pendingPrekeyUses, undefined);
  assert.equal(Object.keys(stored.completedPrekeyClaims).length, 1);
  const transferred = JSON.parse(
    await f.sessions.exportTransferState("bob", "bob-device")
  );
  assert.deepEqual(transferred.completedPrekeyClaims, stored.completedPrekeyClaims);
});

test("authoritative reservations protect legacy state without local claim tombstones", async () => {
  const f = setup();
  f.sessionClaims.set(f.bobPrekeyId, "f".repeat(64));
  const encrypted = await f.client.encryptMessage({
    accountId: "alice",
    conversationId: "legacy",
    messageId: "one",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("legacy reservation"),
    targets: [{
      userId: "bob",
      deviceId: "bob-device",
      encodedIdentity: await f.device.publicIdentityEncoded("bob"),
      encodedBundle: f.bobBundle,
      identityKeyId: encodeBase64(f.bob.keyId),
    }],
  });
  await assert.rejects(
    f.client.decryptMessage({
      accountId: "bob",
      conversationId: "legacy",
      messageId: "one",
      currentDeviceId: "bob-device",
      expectedSenderUserId: "alice",
      encrypted,
    }),
    /claimed by another session/
  );
  assert.equal(f.store.rows.has("bob"), false);
  assert.equal(f.consumed.length, 0);
});

test("message SDK rejects altered sender attribution and duplicate targets", async () => {
  const f = setup();
  const input = {
    accountId: "alice",
    conversationId: "c",
    messageId: "m",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("message"),
    targets: [{ userId: "alice", deviceId: "alice-device" }],
  };
  await assert.rejects(
    f.client.encryptMessage({
      ...input,
      targets: [...input.targets, ...input.targets],
    }),
    /Duplicate/
  );
  const encrypted = await f.client.encryptMessage(input);
  await assert.rejects(
    f.client.decryptMessage({
      accountId: "alice",
      conversationId: "c",
      messageId: "m",
      currentDeviceId: "alice-device",
      expectedSenderUserId: "mallory",
      encrypted,
    }),
    /attribution/
  );
  const modified = structuredClone(encrypted);
  modified.keyPackets[0]!.senderIdentityBindingSignature = encodeBase64(
    new Uint8Array(64)
  );
  await assert.rejects(
    f.client.decryptMessage({
      accountId: "alice",
      conversationId: "c",
      messageId: "m",
      currentDeviceId: "alice-device",
      expectedSenderUserId: "alice",
      encrypted: modified,
    }),
    /IDENTITY_BINDING_MISMATCH/
  );
});
test('established sessions reject substituted sender accounts before advancement', async () => {
 const f=setup();
 const base={accountId:'alice',conversationId:'c',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:utf8('authenticated'),targets:[{userId:'bob',deviceId:'bob-device',encodedIdentity:await f.device.publicIdentityEncoded('bob'),encodedBundle:f.bobBundle,identityKeyId:encodeBase64(f.bob.keyId)}]};
 const receive={accountId:'bob',conversationId:'c',currentDeviceId:'bob-device',expectedSenderUserId:'alice'};
 const first=await f.client.encryptMessage({...base,messageId:'one'});
 await f.client.decryptMessage({...receive,messageId:'one',encrypted:first});
 const second=await f.client.encryptMessage({...base,messageId:'two'});
 const before=f.store.rows.get('bob');
 const forged=structuredClone(second);forged.keyPackets[0]!.senderUserId='mallory';
 await assert.rejects(f.client.decryptMessage({...receive,expectedSenderUserId:'mallory',messageId:'two',encrypted:forged}),/attribution/);
 assert.equal(f.store.rows.get('bob'),before);
 assert.deepEqual(await f.client.decryptMessage({...receive,messageId:'two',encrypted:second}),base.plaintext);
});
test('legacy stored sessions gain attribution only from an authenticated matching bootstrap', async () => {
 const f=setup();
 const base={accountId:'alice',conversationId:'c',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:utf8('legacy'),targets:[{userId:'bob',deviceId:'bob-device',encodedIdentity:await f.device.publicIdentityEncoded('bob'),encodedBundle:f.bobBundle,identityKeyId:encodeBase64(f.bob.keyId)}]};
 const receive={accountId:'bob',conversationId:'c',currentDeviceId:'bob-device',expectedSenderUserId:'alice'};
 const first=await f.client.encryptMessage({...base,messageId:'one'});
 await f.client.decryptMessage({...receive,messageId:'one',encrypted:first});
 const legacy=JSON.parse(f.store.rows.get('bob')!);delete legacy.sessionSenders;f.store.rows.set('bob',JSON.stringify(legacy));
 const second=await f.client.encryptMessage({...base,messageId:'two'});
 const before=f.store.rows.get('bob');
 await assert.rejects(f.client.decryptMessage({...receive,messageId:'two',encrypted:second}),/attribution/);
 assert.equal(f.store.rows.get('bob'),before);
 const forged=structuredClone(first);forged.keyPackets[0]!.senderUserId='mallory';
 await assert.rejects(f.client.decryptMessage({...receive,expectedSenderUserId:'mallory',messageId:'one',encrypted:forged}));
 assert.equal(f.store.rows.get('bob'),before);
 assert.deepEqual(await f.client.decryptMessage({...receive,messageId:'one',encrypted:first}),base.plaintext);
 assert.deepEqual(await f.client.decryptMessage({...receive,messageId:'two',encrypted:second}),base.plaintext);
 assert.equal(f.consumed.length,1);
});
test('receive transaction rechecks attribution after concurrent state replacement', async () => {
 const f=setup();
 const base={accountId:'alice',conversationId:'c',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:utf8('race'),targets:[{userId:'bob',deviceId:'bob-device',encodedIdentity:await f.device.publicIdentityEncoded('bob'),encodedBundle:f.bobBundle,identityKeyId:encodeBase64(f.bob.keyId)}]};
 const receive={accountId:'bob',conversationId:'c',currentDeviceId:'bob-device',expectedSenderUserId:'alice'};
 await f.client.decryptMessage({...receive,messageId:'one',encrypted:await f.client.encryptMessage({...base,messageId:'one'})});
 const encrypted=await f.client.encryptMessage({...base,messageId:'two'});
 const original=f.sessions.assertSessionSender.bind(f.sessions);
 f.sessions.assertSessionSender=async(...args)=>{
  await original(...args);
  const state=JSON.parse(f.store.rows.get('bob')!);
  Object.values(state.sessionSenders).forEach((value)=>{(value as {accountId:string}).accountId='mallory';});
  f.store.rows.set('bob',JSON.stringify(state));
 };
 await assert.rejects(f.client.decryptMessage({...receive,messageId:'two',encrypted}),/attribution/);
});

test('message SDK bounds untrusted packet counts and ciphertext before state access', async () => {
 const f=setup();
 const input={accountId:'bob',conversationId:'c',messageId:'one',currentDeviceId:'bob-device',encrypted:{version:3 as const,nonce:'',ciphertext:'',keyPackets:[]}};
 await assert.rejects(f.client.decryptMessage(input),/target count/);
 await assert.rejects(f.client.decryptMessage({...input,encrypted:{...input.encrypted,keyPackets:Array(101).fill({recipientDeviceId:'bob-device'})}}),/target count/);
 await assert.rejects(f.client.decryptMessage({...input,encrypted:{...input.encrypted,nonce:encodeBase64(new Uint8Array(12)),ciphertext:'A'.repeat(4*Math.ceil((1024*1024+20)/3)),keyPackets:[{recipientDeviceId:'bob-device'} as never]}}),/too large/);
 assert.equal(f.store.rows.size,0);
});
test('delimiter-bearing SDK identifiers cannot alias the deployed session locator', () => {
 const f=setup();
 assert.throws(()=>f.client.needsMessageSession('alice','a:b','c','d'),/identifier/);
 assert.throws(()=>f.client.needsMessageSession('alice','a','b:c','d'),/identifier/);
 assert.throws(()=>f.client.needsMessageSession('alice','a','b|c','d'),/identifier/);
 assert.throws(()=>f.client.needsMessageSession('alice','a\ud800','b','c'),/surrogate/);
});

test('selected content-key fields are bounded and message limits accept the exact configured boundary', async () => {
 const f=setup();
 const valid=await f.client.encryptMessage({accountId:'alice',conversationId:'c',messageId:'one',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:Uint8Array.of(1),targets:[{userId:'bob',deviceId:'bob-device',encodedIdentity:await f.device.publicIdentityEncoded('bob'),encodedBundle:f.bobBundle,identityKeyId:encodeBase64(f.bob.keyId)}]});
 const before=JSON.stringify([...f.store.rows]);
 for (const target of ['recoveryContentKey','wrappedContentKey'] as const) {
  const encrypted=structuredClone(valid); encrypted.keyPackets[0]![target]!.ciphertext=encodeBase64(new Uint8Array(49));
  await assert.rejects(f.client.decryptMessage({accountId:'bob',conversationId:'c',messageId:'one',currentDeviceId:'bob-device',expectedSenderUserId:'alice',encrypted}),/too large/);
  assert.equal(JSON.stringify([...f.store.rows]),before);
 }
 const client=createEnigmMessageClient({device:f.device,sessions:f.sessions,randomSource:random,logPublicKey:encodeBase64(ed25519.getPublicKey(new Uint8Array(32).fill(11))),maximumMessageBytes:1});
 assert.deepEqual(await client.decryptMessage({accountId:'bob',conversationId:'c',messageId:'one',currentDeviceId:'bob-device',expectedSenderUserId:'alice',encrypted:valid}),Uint8Array.of(1));
 await assert.rejects(client.encryptMessage({accountId:'alice',conversationId:'c',messageId:'two',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:Uint8Array.of(1,2),targets:[]}),/too large/);
 for(const maximumMessageBytes of [0,-1,Infinity,1.5,32*1024*1024+1]) assert.throws(()=>createEnigmMessageClient({device:f.device,sessions:f.sessions,randomSource:random,logPublicKey:'',maximumMessageBytes}),/size limit/);
});

for (const mode of ['after-consume','before-marker-clear','after-marker-clear']) {
 test(`resume ${mode} with recreated clients and no reusable prekey`, async () => {
  const f=setup();let fail=true;
  const consume=f.device.consumeOpenedSessionKeyForSession;
  f.device.consumeOpenedSessionKeyForSession=async(...args)=>{await consume(...args);if(mode==='after-consume'&&fail){fail=false;throw new Error('injected ambiguous consume');}};
  const write=f.store.write;
  f.store.write=async(id,value)=>{
   const clearing=id==='bob'&&f.store.rows.get(id)?.includes('pendingPrekeyUses')&&!value.includes('pendingPrekeyUses');
   if(clearing&&mode==='before-marker-clear'&&fail){fail=false;throw new Error('injected clear failure');}
   await write(id,value);
   if(clearing&&mode==='after-marker-clear'&&fail){fail=false;throw new Error('injected ambiguous clear');}
  };
  const encrypted=await f.client.encryptMessage({accountId:'alice',conversationId:'c',messageId:'m',senderDeviceId:'alice-device',senderBinding:f.senderBinding,plaintext:utf8('restart'),targets:[{userId:'bob',deviceId:'bob-device',encodedIdentity:await f.device.publicIdentityEncoded('bob'),encodedBundle:f.bobBundle,identityKeyId:encodeBase64(f.bob.keyId)}]});
  const input={accountId:'bob',conversationId:'c',messageId:'m',currentDeviceId:'bob-device',expectedSenderUserId:'alice',encrypted};
  await assert.rejects(f.client.decryptMessage(input),/injected/);
  f.device.openSessionEncodedPending=async()=>{throw new Error('consumed private key no longer exists');};
  const restarted=createEnigmMessageClient({device:f.device,sessions:createEnigmSessionClient({store:f.store,randomSource:random}),randomSource:random,logPublicKey:encodeBase64(ed25519.getPublicKey(new Uint8Array(32).fill(11)))});
  assert.deepEqual(await restarted.decryptMessage(input),utf8('restart'));
  assert.equal(f.consumed.length,1);
  assert.equal(JSON.parse(f.store.rows.get('bob')!).pendingPrekeyUses,undefined);
 });
}

for (const mode of ["reservation-after-write", "session-before-write"]) {
  test(`bootstrap resumes after ${mode} with recreated clients`, async () => {
    const f = setup();
    let fail = true;
    const reserve = f.device.reserveOpenedSessionKeyForSession;
    f.device.reserveOpenedSessionKeyForSession = async (...args) => {
      await reserve(...args);
      if (mode === "reservation-after-write" && fail) {
        fail = false;
        throw new Error("Injected ambiguous reservation failure");
      }
    };
    const write = f.store.write;
    f.store.write = async (id, value) => {
      if (id === "bob" && mode === "session-before-write" && fail) {
        fail = false;
        throw new Error("Injected session write failure");
      }
      await write(id, value);
    };
    const encrypted = await f.client.encryptMessage({
      accountId: "alice",
      conversationId: "c",
      messageId: "m",
      senderDeviceId: "alice-device",
      senderBinding: f.senderBinding,
      plaintext: utf8("restart"),
      targets: [{
        userId: "bob",
        deviceId: "bob-device",
        encodedIdentity: await f.device.publicIdentityEncoded("bob"),
        encodedBundle: f.bobBundle,
        identityKeyId: encodeBase64(f.bob.keyId),
      }],
    });
    const input = {
      accountId: "bob",
      conversationId: "c",
      messageId: "m",
      currentDeviceId: "bob-device",
      expectedSenderUserId: "alice",
      encrypted,
    };
    await assert.rejects(f.client.decryptMessage(input), /Injected/);
    assert.equal(f.store.rows.has("bob"), false);
    assert.equal(f.consumed.length, 0);
    assert.equal(f.sessionClaims.size, 1);
    const restarted = createEnigmMessageClient({
      device: f.device,
      sessions: createEnigmSessionClient({ store: f.store, randomSource: random }),
      randomSource: random,
      logPublicKey: encodeBase64(ed25519.getPublicKey(new Uint8Array(32).fill(11))),
    });
    assert.deepEqual(await restarted.decryptMessage(input), utf8("restart"));
    assert.equal(f.consumed.length, 1);
    assert.equal(JSON.parse(f.store.rows.get("bob")!).pendingPrekeyUses, undefined);
  });
}

test("legacy pending bootstrap reserves its claim before retrying with a strict key store", async () => {
  const f = setup({ failSessionConsumeOnce: true });
  const encrypted = await f.client.encryptMessage({
    accountId: "alice",
    conversationId: "c",
    messageId: "m",
    senderDeviceId: "alice-device",
    senderBinding: f.senderBinding,
    plaintext: utf8("legacy pending"),
    targets: [{
      userId: "bob",
      deviceId: "bob-device",
      encodedIdentity: await f.device.publicIdentityEncoded("bob"),
      encodedBundle: f.bobBundle,
      identityKeyId: encodeBase64(f.bob.keyId),
    }],
  });
  const input = {
    accountId: "bob",
    conversationId: "c",
    messageId: "m",
    currentDeviceId: "bob-device",
    expectedSenderUserId: "alice",
    encrypted,
  };
  await assert.rejects(f.client.decryptMessage(input), /key store failure/);
  // Older clients persisted the pending journal before any authoritative reservation.
  f.sessionClaims.clear();
  const consume = f.device.consumeOpenedSessionKeyForSession;
  f.device.consumeOpenedSessionKeyForSession = async (accountId, keyId, claimId) => {
    assert.equal(f.sessionClaims.get(keyId), claimId, "Missing authoritative reservation");
    await consume(accountId, keyId, claimId);
  };
  f.device.openSessionEncodedPending = async () => {
    throw new Error("Pending recovery must use the committed session");
  };
  const restarted = createEnigmMessageClient({
    device: f.device,
    sessions: createEnigmSessionClient({ store: f.store, randomSource: random }),
    randomSource: random,
    logPublicKey: encodeBase64(ed25519.getPublicKey(new Uint8Array(32).fill(11))),
  });
  assert.deepEqual(await restarted.decryptMessage(input), utf8("legacy pending"));
  assert.equal(f.consumed.length, 1);
  assert.equal(JSON.parse(f.store.rows.get("bob")!).pendingPrekeyUses, undefined);
});
