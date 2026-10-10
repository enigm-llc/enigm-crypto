import test from "node:test";
import assert from "node:assert/strict";
import {
  createEnigmSessionClient,
  encryptEnigmAttachment,
  decryptEnigmAttachment,
} from "../src/sdk/index.ts";
import { utf8 } from "../src/bytes.ts";
const entropy = (length: number) => new Uint8Array(length).fill(7);
test("attachments retain the existing base64-text payload and authenticate context", () => {
  const raw = Uint8Array.of(0, 255, 1, 128, 0);
  const encrypted = encryptEnigmAttachment(raw, entropy);
  assert.deepEqual(
    decryptEnigmAttachment(encrypted.encrypted, encrypted.fileKey),
    raw
  );
  assert.throws(() =>
    decryptEnigmAttachment(
      { ...encrypted.encrypted, ciphertext: "AAAA" },
      encrypted.fileKey
    )
  );
});
test("session authentication failure never commits durable state", async () => {
  const rows = new Map<string, string>();
  const store = {
    read: async (id: string) => rows.get(id) ?? null,
    write: async (id: string, value: string) => {
      rows.set(id, value);
    },
    delete: async (id: string) => {
      rows.delete(id);
    },
    exclusive: async <T>(_id: string, operation: () => Promise<T>) =>
      operation(),
  };
  const client = createEnigmSessionClient({ store, randomSource: entropy });
  const context = utf8("session");
  await client.initializeSession(
    "alice",
    "id",
    entropy(32),
    context,
    "initiator"
  );
  await client.initializeSession(
    "bob",
    "id",
    entropy(32),
    context,
    "responder"
  );
  const encrypted = await client.encrypt(
    "alice",
    "id",
    utf8("message"),
    context
  );
  const before = rows.get("bob");
  await assert.rejects(
    client.decryptAndCommit("bob", "id", encrypted, context, () => {
      throw new Error("authentication");
    })
  );
  assert.equal(rows.get("bob"), before);
  const opened = await client.decryptAndCommit(
    "bob",
    "id",
    encrypted,
    context,
    (plain: Uint8Array) => new Uint8Array(plain)
  );
  assert.deepEqual(opened, utf8("message"));
});

import { encryptContent } from "../src/protocols/payload.ts";
import { encodeBase64 } from "../src/core/base64.ts";
import { createHash } from "node:crypto";
test("all attachment media types preserve old wire format and verify integrity", () => {
  for (const data of [
    Uint8Array.of(0xff, 0xd8, 0xff, 0, 255),
    Uint8Array.of(0, 0, 0, 24, 102, 116, 121, 112),
    Uint8Array.of(82, 73, 70, 70, 0, 128),
    utf8("%PDF-1.7\0binary"),
  ]) {
    const key = entropy(32);
    const legacy = encryptContent(
      key,
      utf8(Buffer.from(data).toString("base64")),
      utf8("enigm-crypto-v2-attachment"),
      entropy
    );
    const wire = {
      version: 2 as const,
      nonce: encodeBase64(legacy.nonce),
      ciphertext: encodeBase64(legacy.ciphertext),
    };
    assert.deepEqual(
      decryptEnigmAttachment(
        wire,
        encodeBase64(key),
        createHash("sha256").update(data).digest("hex")
      ),
      data
    );
    assert.throws(
      () => decryptEnigmAttachment(wire, encodeBase64(key), "0".repeat(64)),
      /integrity/
    );
  }
});
test("failed session persistence leaves durable ratchet unchanged", async () => {
  const rows = new Map<string, string>();
  let fail = false;
  const store = {
    read: async (id: string) => rows.get(id) ?? null,
    write: async (id: string, value: string) => {
      if (fail) throw new Error("storage");
      rows.set(id, value);
    },
    delete: async () => {},
    exclusive: async <T>(_id: string, action: () => Promise<T>) => action(),
  };
  const client = createEnigmSessionClient({ store, randomSource: entropy });
  const context = utf8("session");
  await client.initializeSession(
    "alice",
    "id",
    entropy(32),
    context,
    "initiator"
  );
  const before = rows.get("alice");
  fail = true;
  await assert.rejects(
    client.encrypt("alice", "id", utf8("secret"), context),
    /storage/
  );
  assert.equal(rows.get("alice"), before);
});

test("a one-time key cannot be pending for two sessions", async () => {
  const rows = new Map<string, string>();
  const store = {
    read: async (id: string) => rows.get(id) ?? null,
    write: async (id: string, value: string) => { rows.set(id, value); },
    delete: async (id: string) => { rows.delete(id); },
    exclusive: async <T>(_id: string, action: () => Promise<T>) => action(),
  };
  const client = createEnigmSessionClient({ store, randomSource: entropy });
  const rootKey = new Uint8Array(32).fill(8);
  const context = utf8("pending prekey uniqueness");
  const sender = {
    accountId: "alice",
    deviceId: "alice-device",
    identityKeyId: encodeBase64(new Uint8Array(32).fill(9)),
  };
  const keyId = encodeBase64(new Uint8Array(32).fill(5));
  const first = { keyId, claimId: "a".repeat(64) };
  await client.initializeOrVerifySession(
    "bob", "session-a", rootKey, context, "responder", sender, first
  );
  await assert.rejects(
    client.initializeOrVerifySession(
      "bob", "session-b", rootKey, context, "responder", sender,
      { keyId, claimId: "b".repeat(64) }
    ),
    /already pending for another session/
  );
  assert.deepEqual(await client.pendingPrekeyUse("bob", "session-a"), first);
  assert.equal(await client.pendingPrekeyUse("bob", "session-b"), null);
  assert.equal(await client.hasSession("bob", "session-b"), false);
});

test('attachment size limits reject before entropy and bound authenticated decoding', () => {
 let calls=0;const random=(length:number)=>{calls++;return entropy(length);};
 assert.throws(()=>encryptEnigmAttachment(Uint8Array.of(1,2),random,{maximumPlaintextBytes:1}),/size limit/);
 assert.equal(calls,0);
 const sealed=encryptEnigmAttachment(Uint8Array.of(255),random,{maximumPlaintextBytes:1});
 assert.deepEqual(decryptEnigmAttachment(sealed.encrypted,sealed.fileKey,undefined,{maximumPlaintextBytes:1}),Uint8Array.of(255));
 assert.throws(()=>decryptEnigmAttachment({...sealed.encrypted,ciphertext:'A'.repeat(32)},sealed.fileKey,undefined,{maximumPlaintextBytes:1}),/too large/);
 assert.throws(()=>decryptEnigmAttachment({...sealed.encrypted,nonce:'A'.repeat(20)},sealed.fileKey),/too large/);
 assert.throws(()=>decryptEnigmAttachment(sealed.encrypted,'A'.repeat(48)),/too large/);
 for(const maximumPlaintextBytes of [0,-1,Infinity,1.5,128*1024*1024+1]) {
  assert.throws(()=>encryptEnigmAttachment(Uint8Array.of(1),random,{maximumPlaintextBytes}),/size limit/);
 }
 const oversized=encryptEnigmAttachment(Uint8Array.of(1,2,3),entropy);
 assert.throws(()=>decryptEnigmAttachment(oversized.encrypted,oversized.fileKey,undefined,{maximumPlaintextBytes:2}),/too large/);
});
