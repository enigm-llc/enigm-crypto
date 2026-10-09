import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createEnigmTransparencyVerifier } from "../src/sdk/index.ts";
import { encodeBase64, utf8 } from "../src/core/index.ts";
test("identity binding remains bound to the exact account and device JSON transcript", () => {
  const secret = new Uint8Array(32).fill(11);
  const logPublicKey = encodeBase64(ed25519.getPublicKey(secret));
  const row = {
    expectedAccountId: "cuenta ñ",
    expectedDeviceId: "device😀",
    identityKeyId: encodeBase64(new Uint8Array(32).fill(9)),
    accountCommitment: encodeBase64(new Uint8Array(32).fill(1)),
    deviceCommitment: encodeBase64(new Uint8Array(32).fill(2)),
  };
  const bindingSignature = encodeBase64(
    ed25519.sign(
      utf8(
        JSON.stringify([
          "enigm-key-transparency-binding-v2",
          row.expectedAccountId,
          row.expectedDeviceId,
          row.identityKeyId,
          row.accountCommitment,
          row.deviceCommitment,
        ])
      ),
      secret
    )
  );
  const store = {
    read: async () => null,
    write: async () => {},
    delete: async () => {},
    exclusive: async <T>(_key: string, action: () => Promise<T>) => action(),
  };
  const verifier = createEnigmTransparencyVerifier({
    store,
    logPublicKey,
    origin: "keys.test/v1",
    witnesses: [],
    quorum: 0,
    fetchConsistencyProof: async () => {
      throw new Error("unexpected fetch");
    },
  });
  verifier.verifyIdentityBinding({ ...row, bindingSignature });
  assert.throws(
    () =>
      verifier.verifyIdentityBinding({
        ...row,
        bindingSignature,
        expectedDeviceId: "other",
      }),
    /IDENTITY_BINDING_MISMATCH/
  );
});

import { buildProof } from "./fixtures/transparency.ts";
const verifierFixture = () => {
  const rows = new Map<string, string>();
  const store = {
    read: async (key: string) => rows.get(key) ?? null,
    write: async (key: string, value: string) => {
      rows.set(key, value);
    },
    delete: async (key: string) => {
      rows.delete(key);
    },
    exclusive: async <T>(_key: string, action: () => Promise<T>) => action(),
  };
  const advanced = buildProof(2);
  const verifier = createEnigmTransparencyVerifier({
    store,
    logPublicKey: "Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=",
    origin: "keys.localhost/v1",
    witnesses: [],
    quorum: 0,
    fetchConsistencyProof: async (from, to) => ({
      version: 1,
      oldSize: from,
      newSize: to,
      proof: advanced.consistencyFromOne,
    }),
  });
  return { verifier, rows };
};
test("full transparency verification preserves inclusion, active state and checkpoint continuity", async () => {
  const { verifier } = verifierFixture();
  const first = buildProof(1);
  const advanced = buildProof(2);
  assert.equal(
    (await verifier.verifyIdentity({ accountId: "local", ...first })).quorumMet,
    true
  );
  await verifier.verifyIdentity({ accountId: "local", ...advanced });
  await assert.rejects(
    verifier.verifyIdentity({ accountId: "local", ...first }),
    /CHECKPOINT_ROLLBACK/
  );
  const conflicting = buildProof(2, 8);
  await assert.rejects(
    verifier.verifyIdentity({ accountId: "local", ...conflicting }),
    /CHECKPOINT_EQUIVOCATION/
  );
});
test("transparency rejects altered identity state, anchor and signed fields without persisting", async () => {
  for (const mutate of [
    (proof: ReturnType<typeof buildProof>["proof"]) => {
      proof.stateMembership.action = "REVOKE";
    },
    (proof: ReturnType<typeof buildProof>["proof"]) => {
      proof.stateAnchor.rootHash = encodeBase64(new Uint8Array(32).fill(20));
    },
    (proof: ReturnType<typeof buildProof>["proof"]) => {
      proof.signedCheckpoint += "tampered";
    },
    (proof: ReturnType<typeof buildProof>["proof"]) => {
      proof.eventPayloadCommitment = encodeBase64(new Uint8Array(32).fill(20));
    },
  ]) {
    const { verifier, rows } = verifierFixture();
    const fixture = buildProof();
    mutate(fixture.proof);
    await assert.rejects(
      verifier.verifyIdentity({ accountId: "local", ...fixture })
    );
    assert.equal(rows.size, 0);
  }
});

test('identity binding rejects even signed noncanonical fixed-size commitment fields', () => {
 const secret=new Uint8Array(32).fill(11);
 const logPublicKey=encodeBase64(ed25519.getPublicKey(secret));
 const verifier=createEnigmTransparencyVerifier({store:{read:()=>Promise.resolve(null),write:()=>Promise.resolve(),delete:()=>Promise.resolve(),exclusive:(_id,action)=>action()},logPublicKey,origin:'keys.test/v1',witnesses:[],quorum:0,fetchConsistencyProof:()=>Promise.resolve(null)});
 const row={expectedAccountId:'alice',expectedDeviceId:'alice-device',identityKeyId:encodeBase64(new Uint8Array(32)),accountCommitment:encodeBase64(new Uint8Array(32)),deviceCommitment:encodeBase64(new Uint8Array(32))};
 for(const field of ['identityKeyId','accountCommitment','deviceCommitment'] as const) {
  const malformed={...row,[field]:encodeBase64(new Uint8Array(33))};
  const bindingSignature=encodeBase64(ed25519.sign(utf8(JSON.stringify(['enigm-key-transparency-binding-v2',malformed.expectedAccountId,malformed.expectedDeviceId,malformed.identityKeyId,malformed.accountCommitment,malformed.deviceCommitment])),secret));
  assert.throws(()=>verifier.verifyIdentityBinding({...malformed,bindingSignature}),/IDENTITY_BINDING_MISMATCH/);
 }
});
