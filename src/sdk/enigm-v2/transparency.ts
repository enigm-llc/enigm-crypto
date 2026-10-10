import {
  verifyEnigmIdentityBinding,
  type EnigmIdentityBindingInput,
} from "./identity-binding.js";
import { KeyTransparencyErrorEnigmV2 } from "./errors.js";
export { KeyTransparencyErrorEnigmV2 } from "./errors.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8, concat } from "../../core/bytes.js";
import { assertWellFormedUtf16 } from "../../core/utf8.js";
import { encodeBase64, decodeBase64 } from "../../core/base64.js";
import {
  keyTransparencyEventHash,
  keyTransparencyLogEntry,
  keyTransparencyLogEntryFromPayload,
  verifyC2spLogSignature,
  verifyC2spWitnessCosignature,
  verifyKeyTransparencyStateMembership,
  verifyRfc6962Consistency,
  verifyRfc6962Inclusion,
} from "../../protocols/index.js";
import type {
  KeyTransparencyAction,
  KeyTransparencyStateProofStep,
} from "../../protocols/index.js";
import type {
  EnigmTransparencyOptions,
  EnigmTransparencyProof,
} from "./transparency-types.js";
export type KeyTransparencyWitnessVerificationEnigmV2 = {
  verified: number;
  total: number;
  required: number;
  quorumMet: boolean;
};

export const createEnigmTransparencyVerifier = (
  options: EnigmTransparencyOptions
) => {
  const origin = options.origin;
  const quorum = options.quorum;
  const store = options.store;
  const fetchConsistencyProofAdapter = options.fetchConsistencyProof;
  const now = options.now ?? Date.now;
  const maximumWitnessAgeSeconds = options.maximumWitnessAgeSeconds ?? 86_400;
  if (!Number.isSafeInteger(maximumWitnessAgeSeconds) || maximumWitnessAgeSeconds < 1)
    throw new KeyTransparencyErrorEnigmV2("INVALID_WITNESS_CONFIGURATION");
  const hash = (value: string) => {
    assertWellFormedUtf16(value, "Key transparency identifier");
    return bytesToHex(sha256(utf8(value)));
  };
  const storeValue = (value: string, label: string) =>
    store.write(label, value);
  const canonicalBase64 = (value: string, label: string): Uint8Array => {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
      throw new KeyTransparencyErrorEnigmV2(`INVALID_${label}`);
    }
    const decoded = decodeBase64(value);
    if (decoded.length !== 32 || encodeBase64(decoded) !== value) {
      throw new KeyTransparencyErrorEnigmV2(`INVALID_${label}`);
    }
    return new Uint8Array(decoded);
  };
  type ConfiguredWitnessV2 = {
    name: string;
    publicKey: Uint8Array;
    fingerprint: string;
  };
  let logPublicKey: Uint8Array;
  let witnesses: ConfiguredWitnessV2[];
  try {
    assertWellFormedUtf16(origin, "Key transparency origin");
    logPublicKey = canonicalBase64(options.logPublicKey, "LOG_PUBLIC_KEY");
    witnesses = options.witnesses.map((witness) => {
      assertWellFormedUtf16(witness.name, "Key transparency witness name");
      const publicKey = canonicalBase64(witness.publicKey, "WITNESS_KEY");
      return { name: witness.name, publicKey, fingerprint: encodeBase64(publicKey) };
    });
  } catch {
    throw new KeyTransparencyErrorEnigmV2("INVALID_WITNESS_CONFIGURATION");
  }
  const witnessNames = new Set(witnesses.map((witness) => witness.name));
  const witnessKeys = new Set(witnesses.map((witness) => witness.fingerprint));
  if (
    !Number.isSafeInteger(quorum) ||
    quorum < 0 ||
    witnesses.length > 15 ||
    witnessNames.size !== witnesses.length ||
    witnessKeys.size !== witnesses.length ||
    witnessKeys.has(encodeBase64(logPublicKey)) ||
    quorum > witnessKeys.size
  )
    throw new KeyTransparencyErrorEnigmV2("INVALID_WITNESS_CONFIGURATION");
  const IDENTITY_DOMAIN = utf8("enigm-key-transparency-identity-v2\0");
  const MAX_MERKLE_PROOF_NODES = 63;
  const MAX_STATE_PROOF_NODES = 128;
  const MAX_SIGNED_CHECKPOINT_BYTES = 8 * 1024;
  const MAX_WITNESS_SIGNATURE_BYTES = 512;

  type StoredCheckpointV2 = {
    version: 1;
    size: number;
    rootHash: string;
  };

  const verifyIdentityBindingEnigmV2 = (
    input: EnigmIdentityBindingInput
  ): void => verifyEnigmIdentityBinding(input, encodeBase64(logPublicKey));

  const checkpointLabel = (accountId: string): string =>
    `checkpoint:${hash(accountId)}`;

  const identityTrustLabel = (accountId: string): string =>
    `trust:${hash(accountId)}`;

  const loadTrustedIdentities = async (
    accountId: string
  ): Promise<Set<string>> => {
    const stored = await store.read(identityTrustLabel(accountId));
    if (!stored) return new Set();
    try {
      const parsed = JSON.parse(stored) as unknown;
      if (
        !Array.isArray(parsed) ||
        parsed.length > 4_096 ||
        parsed.some(
          (value) =>
            typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)
        )
      ) {
        throw new Error("invalid");
      }
      return new Set(parsed as string[]);
    } catch {
      throw new KeyTransparencyErrorEnigmV2("INVALID_TRUSTED_IDENTITY_STORE");
    }
  };

  const equalBase64 = (value: Uint8Array, expected: string): boolean =>
    encodeBase64(value) === expected;

  const parseAction = (value: string): KeyTransparencyAction => {
    if (value === "ACTIVATE" || value === "REVOKE") return value;
    throw new KeyTransparencyErrorEnigmV2("INVALID_ACTION");
  };

  const verifyWitnesses = (
    signedCheckpoint: string,
    witnessCosignatures: readonly string[],
    treeSize: number,
    rootHash: Uint8Array
  ): KeyTransparencyWitnessVerificationEnigmV2 => {
    if (witnessCosignatures.length > 15) {
      return {
        verified: 0,
        total: witnesses.length,
        required: quorum,
        quorumMet: false,
      };
    }
    const normalizedLines = witnessCosignatures.map((line) =>
      line.endsWith("\n") ? line : `${line}\n`
    );
    const signedNote = `${signedCheckpoint}${normalizedLines.join("")}`;
    const nowSeconds = Math.floor(now() / 1000);
    let accepted = 0;
    const seen = new Set<string>();
    for (const witness of witnesses) {
      if (seen.has(witness.fingerprint)) continue;
      const timestamp = verifyC2spWitnessCosignature(
        signedNote,
        { origin, size: treeSize, rootHash },
        {
          name: witness.name,
          publicKey: witness.publicKey,
        },
        nowSeconds
      );
      if (timestamp !== null && nowSeconds - timestamp <= maximumWitnessAgeSeconds) {
        seen.add(witness.fingerprint);
        accepted += 1;
      }
    }
    return {
      verified: accepted,
      total: witnesses.length,
      required: quorum,
      quorumMet: accepted >= quorum,
    };
  };

  const verifyLogProof = (
    proof: Pick<
      EnigmTransparencyProof,
      | "sequence"
      | "leafIndex"
      | "eventCommitment"
      | "treeSize"
      | "rootHash"
      | "inclusionProof"
      | "signedCheckpoint"
      | "witnessCosignatures"
    >
  ): {
    rootHash: Uint8Array;
    witnesses: KeyTransparencyWitnessVerificationEnigmV2;
  } => {
    if (
      !Number.isSafeInteger(proof.sequence) ||
      proof.sequence < 1 ||
      proof.leafIndex !== proof.sequence - 1 ||
      !Number.isSafeInteger(proof.treeSize) ||
      proof.treeSize < proof.sequence ||
      proof.inclusionProof.length > MAX_MERKLE_PROOF_NODES ||
      proof.signedCheckpoint.length > MAX_SIGNED_CHECKPOINT_BYTES ||
      utf8(proof.signedCheckpoint).length > MAX_SIGNED_CHECKPOINT_BYTES ||
      proof.witnessCosignatures.length > 15 ||
      proof.witnessCosignatures.some(
        (line) => line.length > MAX_WITNESS_SIGNATURE_BYTES || utf8(line).length > MAX_WITNESS_SIGNATURE_BYTES
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_LOG_POSITION");
    }
    const eventCommitment = canonicalBase64(
      proof.eventCommitment,
      "EVENT_COMMITMENT"
    );
    const rootHash = canonicalBase64(proof.rootHash, "ROOT_HASH");
    const inclusionProof = proof.inclusionProof.map((item) =>
      canonicalBase64(item, "INCLUSION_PROOF")
    );
    const checkpoint = {
      origin,
      size: proof.treeSize,
      rootHash,
    };
    if (
      !verifyC2spLogSignature(proof.signedCheckpoint, checkpoint, {
        name: origin,
        publicKey: logPublicKey,
      })
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_LOG_SIGNATURE");
    }
    if (
      !verifyRfc6962Inclusion(
        eventCommitment,
        proof.leafIndex,
        proof.treeSize,
        rootHash,
        inclusionProof
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_INCLUSION_PROOF");
    }
    return {
      rootHash,
      witnesses: verifyWitnesses(
        proof.signedCheckpoint,
        proof.witnessCosignatures,
        proof.treeSize,
        rootHash
      ),
    };
  };

  const fetchConsistencyProof = async (
    from: number,
    to: number
  ): Promise<Uint8Array[]> => {
    let raw: unknown;
    try {
      raw = await fetchConsistencyProofAdapter(from, to);
    } catch {
      throw new KeyTransparencyErrorEnigmV2("CONSISTENCY_UNAVAILABLE");
    }
    if (!raw || typeof raw !== "object")
      throw new KeyTransparencyErrorEnigmV2("INVALID_CONSISTENCY_RESPONSE");
    const payload = raw as {
      version?: unknown;
      oldSize?: unknown;
      newSize?: unknown;
      proof?: unknown;
    };
    if (
      payload.version !== 1 ||
      payload.oldSize !== from ||
      payload.newSize !== to ||
      !Array.isArray(payload.proof) ||
      payload.proof.length > MAX_MERKLE_PROOF_NODES
    )
      throw new KeyTransparencyErrorEnigmV2("INVALID_CONSISTENCY_RESPONSE");
    return payload.proof.map((item) => {
      if (typeof item !== "string")
        throw new KeyTransparencyErrorEnigmV2("INVALID_CONSISTENCY_RESPONSE");
      return canonicalBase64(item, "CONSISTENCY_PROOF");
    });
  };

  const isKeyTransparencyWitnessContinuityAllowedEnigmV2 = (
    witnessed: boolean,
    identityWasPreviouslyWitnessed: boolean
  ): boolean => witnessed || identityWasPreviouslyWitnessed;

  const assertWitnessContinuity = (
    witnessed: boolean,
    trustedIdentities: ReadonlySet<string>,
    identityKeyCommitment: string
  ): void => {
    if (
      !isKeyTransparencyWitnessContinuityAllowedEnigmV2(
        witnessed,
        trustedIdentities.has(identityKeyCommitment)
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("WITNESS_QUORUM_UNAVAILABLE");
    }
    if (
      witnessed &&
      !trustedIdentities.has(identityKeyCommitment) &&
      trustedIdentities.size >= 4_096
    ) {
      throw new KeyTransparencyErrorEnigmV2(
        "TRUSTED_IDENTITY_CAPACITY_EXCEEDED"
      );
    }
  };

  const loadStoredCheckpoint = async (
    accountId: string
  ): Promise<StoredCheckpointV2 | null> => {
    const stored = await store.read(checkpointLabel(accountId));
    if (!stored) return null;

    let previous: StoredCheckpointV2;
    try {
      previous = JSON.parse(stored) as StoredCheckpointV2;
    } catch {
      throw new KeyTransparencyErrorEnigmV2("INVALID_STORED_CHECKPOINT");
    }
    canonicalBase64(previous.rootHash, "STORED_ROOT_HASH");
    if (
      previous.version !== 1 ||
      !Number.isSafeInteger(previous.size) ||
      previous.size < 1
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_STORED_CHECKPOINT");
    }
    return previous;
  };

  const verifyCheckpointAdvance = async (
    previous: StoredCheckpointV2,
    next: StoredCheckpointV2
  ): Promise<void> => {
    if (next.size < previous.size) {
      throw new KeyTransparencyErrorEnigmV2("CHECKPOINT_ROLLBACK");
    }
    if (next.size === previous.size && next.rootHash !== previous.rootHash) {
      throw new KeyTransparencyErrorEnigmV2("CHECKPOINT_EQUIVOCATION");
    }
    if (next.size === previous.size) return;

    const consistency = await fetchConsistencyProof(previous.size, next.size);
    if (
      !verifyRfc6962Consistency(
        previous.size,
        next.size,
        canonicalBase64(previous.rootHash, "STORED_ROOT_HASH"),
        canonicalBase64(next.rootHash, "ROOT_HASH"),
        consistency
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_CONSISTENCY_PROOF");
    }
  };

  const acceptCheckpoint = async (
    accountId: string,
    next: StoredCheckpointV2,
    identityKeyCommitment: string,
    witnessed: boolean
  ): Promise<void> => {
    await store.exclusive(accountId, async () => {
      const trustedIdentities = await loadTrustedIdentities(accountId);
      assertWitnessContinuity(
        witnessed,
        trustedIdentities,
        identityKeyCommitment
      );
      const previous = await loadStoredCheckpoint(accountId);
      if (previous) await verifyCheckpointAdvance(previous, next);
      await storeValue(JSON.stringify(next), checkpointLabel(accountId));
      if (witnessed) {
        trustedIdentities.add(identityKeyCommitment);
        await storeValue(
          JSON.stringify(
            [...trustedIdentities].sort((left, right) =>
              left.localeCompare(right)
            )
          ),
          identityTrustLabel(accountId)
        );
      }
    });
  };

  const verifyIdentityKeyTransparencyEnigmV2 = async (input: {
    accountId: string;
    expectedAccountId: string;
    expectedDeviceId: string;
    identityKeyId: string;
    proof: EnigmTransparencyProof | null | undefined;
    /** Disallow witness-outage continuity for operations requiring current witness evidence. */
    requireFreshWitnesses?: boolean;
  }): Promise<KeyTransparencyWitnessVerificationEnigmV2> => {
    if (!input.proof) throw new KeyTransparencyErrorEnigmV2("PROOF_REQUIRED");
    const proof = input.proof;
    verifyIdentityBindingEnigmV2({
      expectedAccountId: input.expectedAccountId,
      expectedDeviceId: input.expectedDeviceId,
      identityKeyId: input.identityKeyId,
      accountCommitment: proof.event.accountCommitment,
      deviceCommitment: proof.event.deviceCommitment,
      bindingSignature: proof.bindingSignature,
    });
    const identityKeyId = canonicalBase64(
      input.identityKeyId,
      "IDENTITY_KEY_ID"
    );
    const identityKeyCommitment = sha256(
      concat(IDENTITY_DOMAIN, identityKeyId)
    );
    if (
      !equalBase64(identityKeyCommitment, proof.event.identityKeyCommitment)
    ) {
      throw new KeyTransparencyErrorEnigmV2("IDENTITY_COMMITMENT_MISMATCH");
    }
    if (
      proof.event.sequence !== proof.sequence ||
      parseAction(proof.event.action) !== "ACTIVATE"
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_ACTIVATION_EVENT");
    }
    const occurredAt = Date.parse(proof.event.occurredAt);
    if (!Number.isSafeInteger(occurredAt) || occurredAt < 0) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_EVENT_TIME");
    }
    const event = {
      version: 1 as const,
      sequence: proof.event.sequence,
      previousHash: canonicalBase64(
        proof.event.previousEventHash,
        "PREVIOUS_EVENT_HASH"
      ),
      accountCommitment: canonicalBase64(
        proof.event.accountCommitment,
        "ACCOUNT_COMMITMENT"
      ),
      deviceCommitment: canonicalBase64(
        proof.event.deviceCommitment,
        "DEVICE_COMMITMENT"
      ),
      identityKeyId: identityKeyCommitment,
      action: "ACTIVATE" as const,
      occurredAt,
    };
    const payloadCommitment = keyTransparencyEventHash(event);
    if (!equalBase64(payloadCommitment, proof.eventPayloadCommitment)) {
      throw new KeyTransparencyErrorEnigmV2("EVENT_PAYLOAD_MISMATCH");
    }
    if (
      !equalBase64(
        keyTransparencyLogEntry(
          event,
          canonicalBase64(proof.stateRoot, "EVENT_STATE_ROOT")
        ),
        proof.eventCommitment
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("EVENT_COMMITMENT_MISMATCH");
    }
    const activationLog = verifyLogProof(proof);

    const anchor = proof.stateAnchor;
    if (
      anchor.sequence !== anchor.treeSize ||
      anchor.treeSize !== proof.treeSize ||
      anchor.rootHash !== proof.rootHash ||
      anchor.signedCheckpoint !== proof.signedCheckpoint
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_STATE_ANCHOR");
    }
    if (
      !equalBase64(
        keyTransparencyLogEntryFromPayload(
          canonicalBase64(anchor.eventPayloadCommitment, "ANCHOR_PAYLOAD"),
          canonicalBase64(anchor.stateRoot, "ANCHOR_STATE_ROOT")
        ),
        anchor.eventCommitment
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_STATE_ANCHOR");
    }
    const anchorLog = verifyLogProof(anchor);
    if (anchorLog.witnesses.quorumMet !== activationLog.witnesses.quorumMet) {
      throw new KeyTransparencyErrorEnigmV2("INCONSISTENT_WITNESS_SET");
    }

    const membership = proof.stateMembership;
    if (
      membership.identityKeyCommitment !== proof.event.identityKeyCommitment ||
      parseAction(membership.action) !== "ACTIVATE" ||
      membership.path.length > MAX_STATE_PROOF_NODES
    ) {
      throw new KeyTransparencyErrorEnigmV2("IDENTITY_NOT_ACTIVE");
    }
    const path: KeyTransparencyStateProofStep[] = membership.path.map(
      (step) => ({
        side:
          step.side === "LEFT" || step.side === "RIGHT"
            ? step.side
            : (() => {
                throw new KeyTransparencyErrorEnigmV2("INVALID_STATE_PROOF");
              })(),
        parentIdentityKeyId: canonicalBase64(
          step.parentIdentityKeyCommitment,
          "STATE_PARENT_KEY"
        ),
        parentAction: parseAction(step.parentAction),
        siblingHash: canonicalBase64(step.siblingHash, "STATE_SIBLING"),
      })
    );
    if (
      !verifyKeyTransparencyStateMembership(
        canonicalBase64(anchor.stateRoot, "ANCHOR_STATE_ROOT"),
        {
          identityKeyId: identityKeyCommitment,
          action: "ACTIVATE",
          leftHash: canonicalBase64(membership.leftHash, "STATE_LEFT_HASH"),
          rightHash: canonicalBase64(membership.rightHash, "STATE_RIGHT_HASH"),
          path,
        }
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("INVALID_STATE_PROOF");
    }

    if (input.requireFreshWitnesses && (quorum < 1 || !anchorLog.witnesses.quorumMet))
      throw new KeyTransparencyErrorEnigmV2("WITNESS_QUORUM_UNAVAILABLE");
    await acceptCheckpoint(
      input.accountId,
      { version: 1, size: proof.treeSize, rootHash: proof.rootHash },
      proof.event.identityKeyCommitment,
      anchorLog.witnesses.quorumMet
    );
    return {
      ...anchorLog.witnesses,
      verified: Math.min(
        anchorLog.witnesses.verified,
        activationLog.witnesses.verified
      ),
    };
  };

  const deleteKeyTransparencyStateEnigmV2 = async (
    accountId: string
  ): Promise<void> => {
    await store.exclusive(accountId, () => Promise.all([
      store.delete(checkpointLabel(accountId)),
      store.delete(identityTrustLabel(accountId)),
    ]).then(() => undefined));
  };

  return {
    verifyIdentityBinding: verifyIdentityBindingEnigmV2,
    verifyIdentity: verifyIdentityKeyTransparencyEnigmV2,
    deleteState: deleteKeyTransparencyStateEnigmV2,
    isWitnessContinuityAllowed:
      isKeyTransparencyWitnessContinuityAllowedEnigmV2,
  };
};
