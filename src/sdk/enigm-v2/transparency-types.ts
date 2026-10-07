import type { SecureStateStore } from "../../adapters/storage.js";
export type EnigmLogProof = {
  sequence: number;
  leafIndex: number;
  eventCommitment: string;
  treeSize: number;
  rootHash: string;
  inclusionProof: readonly string[];
  signedCheckpoint: string;
  witnessCosignatures: readonly string[];
};
export type EnigmTransparencyProof = EnigmLogProof & {
  eventPayloadCommitment: string;
  stateRoot: string;
  bindingSignature: string;
  event: {
    sequence: number;
    previousEventHash: string;
    accountCommitment: string;
    deviceCommitment: string;
    identityKeyCommitment: string;
    action: string;
    occurredAt: string;
  };
  stateAnchor: EnigmLogProof & {
    eventPayloadCommitment: string;
    stateRoot: string;
  };
  stateMembership: {
    identityKeyCommitment: string;
    action: string;
    leftHash: string;
    rightHash: string;
    path: readonly {
      side: string;
      parentIdentityKeyCommitment: string;
      parentAction: string;
      siblingHash: string;
    }[];
  };
};
export type EnigmTransparencyOptions = {
  store: SecureStateStore;
  logPublicKey: string;
  origin: string;
  witnesses: readonly { name: string; publicKey: string }[];
  quorum: number;
  now?: () => number;
  fetchConsistencyProof: (from: number, to: number) => Promise<unknown>;
};
