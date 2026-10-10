import test from "node:test";
import assert from "node:assert/strict";
import {
  createEnigmSessionClient,
  createEnigmDeviceClient,
} from "../src/sdk/index.ts";
import { assertWellFormedUtf16 } from "../src/core/utf8.ts";
const randomSource = (size: number) => new Uint8Array(size).fill(7);
test("every isolated surrogate is rejected at account boundaries before adapter access", async () => {
  let calls = 0;
  const sessions = createEnigmSessionClient({
    randomSource,
    store: {
      read: async () => {
        calls++;
        return null;
      },
      write: async () => {
        calls++;
      },
      delete: async () => {
        calls++;
      },
      exclusive: (_account, action) => {
        calls++;
        return action();
      },
    },
  });
  const device = createEnigmDeviceClient({
    randomSource,
    store: {
      load: async () => {
        calls++;
        throw new Error("adapter reached");
      },
      consume: async () => {
        calls++;
      },
      reserveForSession: async () => {
        calls++;
      },
      consumeForSession: async () => {
        calls++;
      },
    },
  });
  const invalid = Array.from(
    { length: 0x800 },
    (_, index) => `acct-${String.fromCodePoint(0xd800 + index)}`
  );
  await Promise.all(
    invalid.map(async (account) => {
      assert.throws(() => assertWellFormedUtf16(account), /surrogate/);
      await assert.rejects(
        async () => sessions.hasSession(account, "valid-session"),
        /surrogate/
      );
      await assert.rejects(async () => sessions.delete(account), /surrogate/);
      await assert.rejects(
        () => device.publicIdentityEncoded(account),
        /surrogate/
      );
      await assert.rejects(
        async () => device.consumeOpenedSessionKey(account, "key"),
        /surrogate/
      );
      await assert.rejects(
        () => device.reserveOpenedSessionKeyForSession(account, "key", "claim"),
        /surrogate/
      );
      await assert.rejects(
        () => device.consumeOpenedSessionKeyForSession(account, "key", "claim"),
        /surrogate/
      );
    })
  );
  assert.equal(calls, 0);
});
test("accepted Unicode accounts remain independent with UTF-8 hashed mobile storage", async () => {
  const rows = new Map<string, string>();
  const key = (id: string) => Buffer.from(id, "utf8").toString("hex");
  const sessions = createEnigmSessionClient({
    randomSource,
    store: {
      read: async (id) => rows.get(key(id)) ?? null,
      write: async (id, value) => {
        rows.set(key(id), value);
      },
      delete: async (id) => {
        rows.delete(key(id));
      },
      exclusive: (_id, action) => action(),
    },
  });
  await sessions.initializeSession(
    "acct-😀",
    "session",
    randomSource(32),
    new Uint8Array([1]),
    "initiator"
  );
  assert.equal(await sessions.hasSession("acct-😀", "session"), true);
  assert.equal(await sessions.hasSession("acct-😁", "session"), false);
  await assert.rejects(
    async () => sessions.exportTransferState("acct-😀", "device-\ud800"),
    /surrogate/
  );
});
