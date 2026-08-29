import { sha256 } from "@noble/hashes/sha2.js";

import { assertLength, equal, frame, utf8 } from "./bytes.js";
import {
  keyTransparencyEventHash,
  type KeyTransparencyAction,
  type KeyTransparencyEvent,
} from "./transparency.js";

const ENTRY_DOMAIN = utf8("enigm-key-transparency-entry-v2");
const STATE_EMPTY_DOMAIN = utf8("enigm-key-transparency-state-empty-v2");
const STATE_NODE_DOMAIN = utf8("enigm-key-transparency-state-node-v2");
const EMPTY_STATE_HASH = sha256(STATE_EMPTY_DOMAIN);

export type KeyTransparencyStateProofStep = {
  side: "LEFT" | "RIGHT";
  parentIdentityKeyId: Uint8Array;
  parentAction: KeyTransparencyAction;
  siblingHash: Uint8Array;
};

export type KeyTransparencyStateMembershipProof = {
  identityKeyId: Uint8Array;
  action: KeyTransparencyAction;
  leftHash: Uint8Array;
  rightHash: Uint8Array;
  path: readonly KeyTransparencyStateProofStep[];
};

const actionByte = (action: KeyTransparencyAction): Uint8Array => {
  if (action === "ACTIVATE") return new Uint8Array([1]);
  if (action === "REVOKE") return new Uint8Array([2]);
  throw new Error("Unsupported key transparency action.");
};

export const emptyKeyTransparencyStateHash = (): Uint8Array =>
  new Uint8Array(EMPTY_STATE_HASH);

export const keyTransparencyStateNodeHash = (
  identityKeyId: Uint8Array,
  action: KeyTransparencyAction,
  leftHash: Uint8Array,
  rightHash: Uint8Array,
): Uint8Array => {
  assertLength(identityKeyId, 32, "Identity key identifier");
  assertLength(leftHash, 32, "Left state hash");
  assertLength(rightHash, 32, "Right state hash");
  return sha256(
    frame(
      STATE_NODE_DOMAIN,
      identityKeyId,
      actionByte(action),
      leftHash,
      rightHash,
    ),
  );
};

export const keyTransparencyLogEntry = (
  event: KeyTransparencyEvent,
  stateRoot: Uint8Array,
): Uint8Array =>
  keyTransparencyLogEntryFromPayload(
    keyTransparencyEventHash(event),
    stateRoot,
  );

export const keyTransparencyLogEntryFromPayload = (
  eventPayloadHash: Uint8Array,
  stateRoot: Uint8Array,
): Uint8Array => {
  assertLength(eventPayloadHash, 32, "Key transparency event payload hash");
  assertLength(stateRoot, 32, "Key transparency state root");
  return sha256(frame(ENTRY_DOMAIN, eventPayloadHash, stateRoot));
};

export const verifyKeyTransparencyStateMembership = (
  rootHash: Uint8Array,
  proof: KeyTransparencyStateMembershipProof,
): boolean => {
  try {
    assertLength(rootHash, 32, "Key transparency state root");
    let current = keyTransparencyStateNodeHash(
      proof.identityKeyId,
      proof.action,
      proof.leftHash,
      proof.rightHash,
    );
    for (const step of proof.path) {
      assertLength(
        step.parentIdentityKeyId,
        32,
        "Parent identity key identifier",
      );
      assertLength(step.siblingHash, 32, "State proof sibling hash");
      current =
        step.side === "LEFT"
          ? keyTransparencyStateNodeHash(
              step.parentIdentityKeyId,
              step.parentAction,
              current,
              step.siblingHash,
            )
          : step.side === "RIGHT"
            ? keyTransparencyStateNodeHash(
                step.parentIdentityKeyId,
                step.parentAction,
                step.siblingHash,
                current,
              )
            : new Uint8Array();
    }
    return equal(current, rootHash);
  } catch {
    return false;
  }
};
