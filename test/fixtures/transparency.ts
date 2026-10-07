import {
  emptyKeyTransparencyStateHash,
  keyTransparencyEventHash,
  keyTransparencyLogEntry,
  keyTransparencyLogEntryFromPayload,
  keyTransparencyStateNodeHash,
  rfc6962ConsistencyProof,
  rfc6962InclusionProof,
  rfc6962Root,
  signC2spCheckpoint,
} from "../../src/index.ts";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";

import type { EnigmTransparencyProof } from "../../src/sdk/index.ts";

const base64 = (value: Uint8Array): string =>
  Buffer.from(value).toString("base64");
const bindingSecretKey = new Uint8Array(32).fill(11);
const bindingDomain = "enigm-key-transparency-binding-v2";

export const buildProof = (
  treeSize: 1 | 2 = 1,
  anchorByte = 7
): {
  expectedAccountId: string;
  expectedDeviceId: string;
  identityKeyId: string;
  proof: EnigmTransparencyProof;
  consistencyFromOne: string[];
} => {
  const identityKey = new Uint8Array(32).fill(9);
  const identityCommitment = sha256(
    new Uint8Array([
      ...Buffer.from("enigm-key-transparency-identity-v2\0", "utf8"),
      ...identityKey,
    ])
  );
  const event = {
    version: 1 as const,
    sequence: 1,
    previousHash: new Uint8Array(32),
    accountCommitment: new Uint8Array(32).fill(1),
    deviceCommitment: new Uint8Array(32).fill(2),
    identityKeyId: identityCommitment,
    action: "ACTIVATE" as const,
    occurredAt: 1_100,
  };
  const empty = emptyKeyTransparencyStateHash();
  const stateRoot = keyTransparencyStateNodeHash(
    identityCommitment,
    "ACTIVATE",
    empty,
    empty
  );
  const entry = keyTransparencyLogEntry(event, stateRoot);
  const anchorPayload = new Uint8Array(32).fill(anchorByte);
  const anchorEntry = keyTransparencyLogEntryFromPayload(
    anchorPayload,
    stateRoot
  );
  const entries = treeSize === 1 ? [entry] : [entry, anchorEntry];
  const rootHash = rfc6962Root(entries);
  const signedCheckpoint = signC2spCheckpoint(
    { origin: "keys.localhost/v1", size: treeSize, rootHash },
    {
      name: "keys.localhost/v1",
      publicKey: Buffer.from(
        "Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=",
        "base64"
      ),
      secretKey: new Uint8Array(32).fill(11),
    }
  );
  const logFields = {
    sequence: 1,
    leafIndex: 0,
    eventCommitment: base64(entry),
    eventPayloadCommitment: base64(keyTransparencyEventHash(event)),
    stateRoot: base64(stateRoot),
    treeSize,
    rootHash: base64(rootHash),
    inclusionProof: rfc6962InclusionProof(entries, 0).map(base64),
    signedCheckpoint,
    witnessCosignatures: [],
  };
  const stateAnchor =
    treeSize === 1
      ? logFields
      : {
          sequence: 2,
          leafIndex: 1,
          eventCommitment: base64(anchorEntry),
          eventPayloadCommitment: base64(anchorPayload),
          stateRoot: base64(stateRoot),
          treeSize,
          rootHash: base64(rootHash),
          inclusionProof: rfc6962InclusionProof(entries, 1).map(base64),
          signedCheckpoint,
          witnessCosignatures: [],
        };
  const expectedAccountId = "user-a";
  const expectedDeviceId = "device-a-00000001";
  const identityKeyId = base64(identityKey);
  const accountCommitment = base64(event.accountCommitment);
  const deviceCommitment = base64(event.deviceCommitment);
  const bindingSignature = base64(
    ed25519.sign(
      new TextEncoder().encode(
        JSON.stringify([
          bindingDomain,
          expectedAccountId,
          expectedDeviceId,
          identityKeyId,
          accountCommitment,
          deviceCommitment,
        ])
      ),
      bindingSecretKey
    )
  );
  return {
    expectedAccountId,
    expectedDeviceId,
    identityKeyId,
    consistencyFromOne: rfc6962ConsistencyProof(entries, 1).map(base64),
    proof: {
      ...logFields,
      bindingSignature,
      event: {
        sequence: 1,
        previousEventHash: base64(event.previousHash),
        accountCommitment: base64(event.accountCommitment),
        deviceCommitment: base64(event.deviceCommitment),
        identityKeyCommitment: base64(identityCommitment),
        action: "ACTIVATE",
        occurredAt: new Date(event.occurredAt).toISOString(),
      },
      stateAnchor,
      stateMembership: {
        identityKeyCommitment: base64(identityCommitment),
        action: "ACTIVATE",
        leftHash: base64(empty),
        rightHash: base64(empty),
        path: [],
      },
    },
  };
};
