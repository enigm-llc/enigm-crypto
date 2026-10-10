import type {
  GroupEpochState,
  SessionRole,
  SessionState,
} from "../../core/types.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { assertWellFormedUtf16, utf8, equal, wipe, type RandomSource } from "../../core/index.js";
import { deriveExportKey } from "../../protocols/envelope.js";
import { encodeBase64, decodeBase64 } from "../../core/base64.js";
import type { SecureStateStore } from "../../adapters/storage.js";
import {
  createGroupEpoch,
  decryptContent,
  decryptGroupEpoch,
  encryptContent,
  encryptGroupEpoch,
  initializeSession,
  rekeySession,
  rotateGroupEpoch,
  sessionDecrypt,
  sessionEncrypt,
  validateGroupEpochState,
  validateSessionState,
  wipeSession,
  type GroupEpochCiphertext,
  type RatchetCiphertext,
} from "../../protocols/index.js";
const assertTransferEntries = <T>(current: Record<string, T>, transferred: Record<string, T>, label: string): void => {
  for (const [key, value] of Object.entries(current)) {
    const transferredValue = transferred[key];
    if (transferredValue && JSON.stringify(transferredValue) !== JSON.stringify(value)) {
      throw new Error(`Conflicting EnigmV2 ${label} during device transfer.`);
    }
  }
};

const STORAGE_VERSION = 5;
const RECOVERY_KEY_BYTES = 32;
const MAX_SESSIONS = 10_000;
const MAX_GROUPS = 2_000;
const MAX_HISTORICAL_DEVICE_IDS = 100;
const MAX_TRANSFER_STATE_BYTES = 8 * 1024 * 1024;

type EncodedChain = { chainId: string; counter: number; chainKey: string };
type EncodedSession = {
  sessionId: string;
  epoch: number;
  rootKey: string;
  send: EncodedChain;
  receive: EncodedChain;
  skipped: Array<{ chainId: string; counter: number; messageKey: string }>;
};
type EncodedGroup = {
  groupId: string;
  epoch: number;
  epochSecret: string;
  membersHash: string;
};
export type PendingPrekeyUseEnigmV2 = { keyId: string; claimId: string };
export type EnigmSessionSender = { accountId: string; deviceId: string; identityKeyId: string };
const validateSender = (sender: EnigmSessionSender): void => {
  if (!sender || typeof sender.accountId !== 'string' || !sender.accountId || sender.accountId.length > 256 ||
      typeof sender.deviceId !== 'string' || !sender.deviceId || sender.deviceId.length > 256 ||
      typeof sender.identityKeyId !== 'string' || decodeBase64(sender.identityKeyId).length !== 32) {
    throw new Error('Invalid EnigmV2 session sender attribution.');
  }
  assertWellFormedUtf16(sender.accountId, "EnigmV2 sender account identifier");
  assertWellFormedUtf16(sender.deviceId, "EnigmV2 sender device identifier");
};
const assertSender = (stored: StoredMessagingCryptoEnigmV2, key: string, accountId: string, deviceId: string): void => {
  const sender = stored.sessionSenders?.[key];
  if (sender?.accountId !== accountId || sender.deviceId !== deviceId)
    throw new Error('EnigmV2 session sender attribution mismatch or unavailable.');
};
type StoredMessagingCryptoEnigmV2 = {
  version: typeof STORAGE_VERSION;
  recoveryKey: string;
  recoveryKeyInitialized: boolean;
  sessions: Record<string, EncodedSession>;
  sessionSenders?: Record<string, EnigmSessionSender>;
  pendingPrekeyUses?: Record<string, PendingPrekeyUseEnigmV2>;
  groups: Record<string, EncodedGroup>;
  historicalDeviceIds: string[];
};

export type EncodedRatchetMessageEnigmV2 = {
  version: 2;
  chainId: string;
  counter: number;
  nonce: string;
  ciphertext: string;
};

export type EncodedRecoveryContentKeyEnigmV2 = {
  version: 2;
  nonce: string;
  ciphertext: string;
};

export type EncodedGroupMessageEnigmV2 = {
  version: 2;
  groupId: string;
  epoch: number;
  purpose: "metadata" | "message";
  nonce: string;
  ciphertext: string;
};

export type MessagingEncryptTargetEnigmV2 = {
  id: string;
  plaintext: Uint8Array;
  context: Uint8Array;
  recoveryContext: Uint8Array;
  rootKey?: Uint8Array;
};

export type MessagingEncryptResultEnigmV2 = {
  id: string;
  initialized: boolean;
  message: EncodedRatchetMessageEnigmV2;
  recovery: EncodedRecoveryContentKeyEnigmV2;
};

const b64 = encodeBase64;
const bytes = decodeBase64;
const hash = (value: string): string => bytesToHex(sha256(utf8(value)));
const stateKey = (id: string): string => {
  assertWellFormedUtf16(id, "EnigmV2 state identifier");
  return hash(`messaging-state:${id}`);
};
const validatePendingPrekeyUse = (pending: PendingPrekeyUseEnigmV2): void => {
  if (
    !pending ||
    typeof pending.keyId !== "string" ||
    bytes(pending.keyId).length !== 32 ||
    b64(bytes(pending.keyId)) !== pending.keyId ||
    typeof pending.claimId !== "string" ||
    !/^[0-9a-f]{64}$/u.test(pending.claimId)
  ) {
    throw new Error("Invalid EnigmV2 pending one-time key use.");
  }
};
const assertSessionReady = (stored: StoredMessagingCryptoEnigmV2, key: string): void => {
  if (stored.pendingPrekeyUses?.[key]) {
    throw new Error("EnigmV2 session one-time key consumption is pending.");
  }
};
const assertPendingPrekeyAvailable = (
  stored: StoredMessagingCryptoEnigmV2,
  sessionKey: string,
  pending: PendingPrekeyUseEnigmV2
): void => {
  validatePendingPrekeyUse(pending);
  for (const [key, current] of Object.entries(stored.pendingPrekeyUses ?? {})) {
    if (key === sessionKey) {
      if (current.keyId !== pending.keyId || current.claimId !== pending.claimId) {
        throw new Error("EnigmV2 pending one-time key claim mismatch.");
      }
    } else if (current.keyId === pending.keyId) {
      throw new Error("EnigmV2 one-time key is already pending for another session.");
    }
  }
};

const createEmptyState = (
  randomSource: RandomSource
): StoredMessagingCryptoEnigmV2 => ({
  version: STORAGE_VERSION,
  recoveryKey: b64(randomSource(RECOVERY_KEY_BYTES)),
  recoveryKeyInitialized: false,
  sessions: {},
  groups: {},
  historicalDeviceIds: [],
});

const encodeChain = (chain: SessionState["send"]): EncodedChain => ({
  chainId: b64(chain.chainId),
  counter: chain.counter,
  chainKey: b64(chain.chainKey),
});
const decodeChain = (chain: EncodedChain): SessionState["send"] => ({
  version: 2,
  chainId: bytes(chain.chainId),
  counter: chain.counter,
  chainKey: bytes(chain.chainKey),
});
const encodeSession = (state: SessionState): EncodedSession => ({
  sessionId: b64(state.sessionId),
  epoch: state.epoch,
  rootKey: b64(state.rootKey),
  send: encodeChain(state.send),
  receive: encodeChain(state.receive),
  skipped: state.skipped.map((item) => ({
    chainId: b64(item.chainId),
    counter: item.counter,
    messageKey: b64(item.messageKey),
  })),
});
const decodeSession = (state: EncodedSession): SessionState => ({
  version: 2,
  sessionId: bytes(state.sessionId),
  epoch: state.epoch,
  rootKey: bytes(state.rootKey),
  send: decodeChain(state.send),
  receive: decodeChain(state.receive),
  skipped: state.skipped.map((item) => ({
    chainId: bytes(item.chainId),
    counter: item.counter,
    messageKey: bytes(item.messageKey),
  })),
});
const encodeGroup = (state: GroupEpochState): EncodedGroup => ({
  groupId: b64(state.groupId),
  epoch: state.epoch,
  epochSecret: b64(state.epochSecret),
  membersHash: b64(state.membersHash),
});
const decodeGroup = (state: EncodedGroup): GroupEpochState => ({
  version: 2,
  groupId: bytes(state.groupId),
  epoch: state.epoch,
  epochSecret: bytes(state.epochSecret),
  membersHash: bytes(state.membersHash),
});

const validateStoredState = (state: StoredMessagingCryptoEnigmV2): void => {
  if (
    state.version !== STORAGE_VERSION ||
    typeof state.recoveryKey !== "string" ||
    bytes(state.recoveryKey).length !== RECOVERY_KEY_BYTES ||
    b64(bytes(state.recoveryKey)) !== state.recoveryKey ||
    typeof state.recoveryKeyInitialized !== "boolean" ||
    !state.sessions ||
    !state.groups ||
    !Array.isArray(state.historicalDeviceIds) ||
    Object.keys(state.sessions).length > MAX_SESSIONS ||
    Object.keys(state.groups).length > MAX_GROUPS ||
    state.historicalDeviceIds.length > MAX_HISTORICAL_DEVICE_IDS ||
    new Set(state.historicalDeviceIds).size !==
      state.historicalDeviceIds.length ||
    state.historicalDeviceIds.some(
      (id) => typeof id !== "string" || id.length < 1 || id.length > 256
    )
  ) {
    throw new Error("Invalid EnigmV2 messaging cryptographic storage.");
  }
  if (state.sessionSenders !== undefined) {
    if (!state.sessionSenders || typeof state.sessionSenders !== 'object' || Array.isArray(state.sessionSenders) || Object.keys(state.sessionSenders).length > MAX_SESSIONS)
      throw new Error('Invalid EnigmV2 session sender attribution storage.');
    for (const [key, sender] of Object.entries(state.sessionSenders)) {
      if (!Object.hasOwn(state.sessions, key)) throw new Error('Orphaned EnigmV2 session sender attribution.');
      validateSender(sender);
    }
  }
  if (state.pendingPrekeyUses !== undefined) {
    if (!state.pendingPrekeyUses || typeof state.pendingPrekeyUses !== 'object' || Array.isArray(state.pendingPrekeyUses) || Object.keys(state.pendingPrekeyUses).length > MAX_SESSIONS)
      throw new Error('Invalid EnigmV2 pending one-time key storage.');
    const keyIds = new Set<string>();
    for (const [key, pending] of Object.entries(state.pendingPrekeyUses)) {
      if (!/^[0-9a-f]{64}$/u.test(key) || !Object.hasOwn(state.sessions, key))
        throw new Error('Orphaned EnigmV2 pending one-time key use.');
      validatePendingPrekeyUse(pending);
      if (keyIds.has(pending.keyId))
        throw new Error('Duplicate EnigmV2 pending one-time key use.');
      keyIds.add(pending.keyId);
    }
  }
  for (const encoded of Object.values(state.sessions)) {
    const session = decodeSession(encoded);
    try {
      validateSessionState(session);
    } finally {
      wipeSession(session);
    }
  }
  for (const encoded of Object.values(state.groups)) {
    const group = decodeGroup(encoded);
    try {
      validateGroupEpochState(group);
    } finally {
      wipe(group.epochSecret);
    }
  }
};

class MessagingCryptoManagerEnigmV2 {
  constructor(
    private readonly options: {
      store: SecureStateStore;
      randomSource: RandomSource;
    }
  ) {}
  private exclusive<T>(
    accountId: string,
    operation: () => Promise<T>
  ): Promise<T> {
    return this.options.store.exclusive(accountId, operation);
  }
  private async load(accountId: string): Promise<StoredMessagingCryptoEnigmV2> {
    const serialized = await this.options.store.read(accountId);
    if (serialized === null) return createEmptyState(this.options.randomSource);
    const state = JSON.parse(serialized) as StoredMessagingCryptoEnigmV2;
    validateStoredState(state);
    return state;
  }
  private persist(
    accountId: string,
    state: StoredMessagingCryptoEnigmV2
  ): Promise<void> {
    validateStoredState(state);
    return this.options.store.write(accountId, JSON.stringify(state));
  }
  public hasSession(accountId: string, id: string): Promise<boolean> {
    return this.exclusive(accountId, async () =>
      Boolean((await this.load(accountId)).sessions[stateKey(id)])
    );
  }

  public pendingPrekeyUse(
    accountId: string,
    id: string
  ): Promise<PendingPrekeyUseEnigmV2 | null> {
    return this.exclusive(accountId, async () => {
      const pending = (await this.load(accountId)).pendingPrekeyUses?.[stateKey(id)];
      return pending ? { ...pending } : null;
    });
  }

  public completePendingPrekeyUse(
    accountId: string,
    id: string,
    expected: PendingPrekeyUseEnigmV2
  ): Promise<void> {
    return this.exclusive(accountId, async () => {
      validatePendingPrekeyUse(expected);
      const stored = await this.load(accountId);
      const current = stored.pendingPrekeyUses?.[stateKey(id)];
      if (!current) return;
      if (current.keyId !== expected.keyId || current.claimId !== expected.claimId) {
        throw new Error("EnigmV2 pending one-time key claim mismatch.");
      }
      delete stored.pendingPrekeyUses![stateKey(id)];
      if (Object.keys(stored.pendingPrekeyUses!).length === 0) {
        delete stored.pendingPrekeyUses;
      }
      await this.persist(accountId, stored);
    });
  }

  public hasSessionSender(accountId: string, id: string): Promise<boolean> {
    return this.exclusive(accountId, async () => Boolean((await this.load(accountId)).sessionSenders?.[stateKey(id)]));
  }

  public assertSessionSender(accountId: string, id: string, senderAccountId: string, senderDeviceId: string): Promise<void> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      assertSender(stored, key, senderAccountId, senderDeviceId);
    });
  }

  public initializeSession(
    accountId: string,
    id: string,
    rootKey: Uint8Array,
    context: Uint8Array,
    role: SessionRole
  ): Promise<void> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      if (stored.sessions[key])
        throw new Error("EnigmV2 messaging session already exists.");
      if (Object.keys(stored.sessions).length >= MAX_SESSIONS)
        throw new Error("EnigmV2 session capacity reached.");
      const session = initializeSession(rootKey, context, role);
      stored.sessions[key] = encodeSession(session);
      await this.persist(accountId, stored);
      wipeSession(session);
    });
  }

  public initializeOrVerifySession(
    accountId: string,
    id: string,
    rootKey: Uint8Array,
    context: Uint8Array,
    role: SessionRole,
    sender?: EnigmSessionSender,
    pendingPrekeyUse?: PendingPrekeyUseEnigmV2
  ): Promise<"initialized" | "matching-session"> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      if (pendingPrekeyUse) {
        assertPendingPrekeyAvailable(stored, key, pendingPrekeyUse);
        if (!sender) throw new Error("EnigmV2 pending one-time key use requires sender attribution.");
      }
      if (sender) {
        validateSender(sender);
        const currentSender = stored.sessionSenders?.[key];
        if (currentSender && (currentSender.accountId !== sender.accountId || currentSender.deviceId !== sender.deviceId || currentSender.identityKeyId !== sender.identityKeyId))
          throw new Error('EnigmV2 session sender attribution mismatch.');
      }
      const expected = initializeSession(rootKey, context, role);
      try {
        const encoded = stored.sessions[key];
        if (!encoded) {
          if (Object.keys(stored.sessions).length >= MAX_SESSIONS) {
            throw new Error("EnigmV2 session capacity reached.");
          }
          stored.sessions[key] = encodeSession(expected);
          if (sender) {
            stored.sessionSenders ??= {};
            stored.sessionSenders[key] = { ...sender };
          }
          if (pendingPrekeyUse) {
            stored.pendingPrekeyUses ??= {};
            stored.pendingPrekeyUses[key] = { ...pendingPrekeyUse };
          }
          await this.persist(accountId, stored);
          return "initialized";
        }

        const current = decodeSession(encoded);
        try {
          const matchesSession =
            current.epoch === expected.epoch &&
            equal(current.sessionId, expected.sessionId) &&
            equal(current.rootKey, expected.rootKey) &&
            equal(current.send.chainId, expected.send.chainId) &&
            equal(current.receive.chainId, expected.receive.chainId);
          if (!matchesSession)
            throw new Error(
              "EnigmV2 bootstrap does not match the current session."
            );
          if (sender || pendingPrekeyUse) {
            if (sender) {
              stored.sessionSenders ??= {};
              stored.sessionSenders[key] = { ...sender };
            }
            if (pendingPrekeyUse) {
              stored.pendingPrekeyUses ??= {};
              stored.pendingPrekeyUses[key] = { ...pendingPrekeyUse };
            }
            await this.persist(accountId, stored);
          }
          return "matching-session";
        } finally {
          wipeSession(current);
        }
      } finally {
        wipeSession(expected);
      }
    });
  }

  public encrypt(
    accountId: string,
    id: string,
    plaintext: Uint8Array,
    context: Uint8Array
  ): Promise<EncodedRatchetMessageEnigmV2> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      try {
        const encrypted = sessionEncrypt(
          session,
          plaintext,
          context,
          this.options.randomSource
        );
        try {
          stored.sessions[key] = encodeSession(encrypted.next);
          await this.persist(accountId, stored);
          return {
            version: 2,
            chainId: b64(encrypted.message.chainId),
            counter: encrypted.message.counter,
            nonce: b64(encrypted.message.nonce),
            ciphertext: b64(encrypted.message.ciphertext),
          };
        } finally {
          wipeSession(encrypted.next);
        }
      } finally {
        wipeSession(session);
      }
    });
  }

  public encryptMany(
    accountId: string,
    targets: readonly MessagingEncryptTargetEnigmV2[]
  ): Promise<MessagingEncryptResultEnigmV2[]> {
    return this.exclusive(accountId, async () => {
      if (targets.length < 1 || targets.length > 100) {
        throw new Error("Invalid EnigmV2 messaging encryption batch size.");
      }
      const keys = targets.map(({ id }) => stateKey(id));
      if (new Set(keys).size !== keys.length) {
        throw new Error(
          "Duplicate EnigmV2 messaging session in encryption batch."
        );
      }

      const stored = await this.load(accountId);
      keys.forEach((key) => assertSessionReady(stored, key));
      const sessionsToWipe: SessionState[] = [];
      const nextSessionsToWipe: SessionState[] = [];
      try {
        const results = targets.map((target, index) => {
          const key = keys[index]!;
          const encoded = stored.sessions[key];
          const initialized = !encoded;
          if (initialized && !target.rootKey) {
            throw new Error("EnigmV2 session bootstrap key is unavailable.");
          }
          if (
            initialized &&
            Object.keys(stored.sessions).length >= MAX_SESSIONS
          ) {
            throw new Error("EnigmV2 session capacity reached.");
          }
          const session = encoded
            ? decodeSession(encoded)
            : initializeSession(target.rootKey!, target.context, "initiator");
          sessionsToWipe.push(session);
          const encrypted = sessionEncrypt(
            session,
            target.plaintext,
            target.context,
            this.options.randomSource
          );
          nextSessionsToWipe.push(encrypted.next);
          stored.sessions[key] = encodeSession(encrypted.next);
          const recoveryKey = deriveExportKey(
            session.rootKey,
            target.recoveryContext
          );
          let recovery;
          try {
            recovery = encryptContent(
              recoveryKey,
              target.plaintext,
              target.recoveryContext,
              this.options.randomSource
            );
          } finally {
            wipe(recoveryKey);
          }
          return {
            id: target.id,
            initialized,
            message: {
              version: 2 as const,
              chainId: b64(encrypted.message.chainId),
              counter: encrypted.message.counter,
              nonce: b64(encrypted.message.nonce),
              ciphertext: b64(encrypted.message.ciphertext),
            },
            recovery: {
              version: 2 as const,
              nonce: b64(recovery.nonce),
              ciphertext: b64(recovery.ciphertext),
            },
          };
        });
        await this.persist(accountId, stored);
        return results;
      } finally {
        sessionsToWipe.forEach((session) => wipeSession(session));
        nextSessionsToWipe.forEach((session) => wipeSession(session));
      }
    });
  }

  public shouldUseRecovery(
    accountId: string,
    id: string,
    message: EncodedRatchetMessageEnigmV2
  ): Promise<boolean> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      try {
        const chainId = bytes(message.chainId);
        return (
          equal(chainId, session.receive.chainId) &&
          message.counter < session.receive.counter &&
          !session.skipped.some(
            (item) =>
              item.counter === message.counter && equal(item.chainId, chainId)
          )
        );
      } finally {
        wipeSession(session);
      }
    });
  }

  public recover(
    accountId: string,
    id: string,
    recovery: EncodedRecoveryContentKeyEnigmV2,
    context: Uint8Array,
    expectedSender?: { accountId: string; deviceId: string }
  ): Promise<Uint8Array> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      if (expectedSender) assertSender(stored, key, expectedSender.accountId, expectedSender.deviceId);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      const recoveryKey = deriveExportKey(session.rootKey, context);
      try {
        return decryptContent(
          recoveryKey,
          {
            version: recovery.version,
            nonce: bytes(recovery.nonce),
            ciphertext: bytes(recovery.ciphertext),
          },
          context
        );
      } finally {
        wipe(recoveryKey);
        wipeSession(session);
      }
    });
  }

  public encryptLocalRecovery(
    accountId: string,
    plaintext: Uint8Array,
    context: Uint8Array
  ): Promise<EncodedRecoveryContentKeyEnigmV2> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      stored.recoveryKeyInitialized = true;
      const recoveryKeyMaterial = bytes(stored.recoveryKey);
      const recoveryKey = deriveExportKey(recoveryKeyMaterial, context);
      try {
        const encrypted = encryptContent(
          recoveryKey,
          plaintext,
          context,
          this.options.randomSource
        );
        await this.persist(accountId, stored);
        return {
          version: 2,
          nonce: b64(encrypted.nonce),
          ciphertext: b64(encrypted.ciphertext),
        };
      } finally {
        wipe(recoveryKeyMaterial, recoveryKey);
      }
    });
  }

  public decryptLocalRecovery(
    accountId: string,
    recovery: EncodedRecoveryContentKeyEnigmV2,
    context: Uint8Array
  ): Promise<Uint8Array> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const recoveryKeyMaterial = bytes(stored.recoveryKey);
      const recoveryKey = deriveExportKey(recoveryKeyMaterial, context);
      try {
        return decryptContent(
          recoveryKey,
          {
            version: recovery.version,
            nonce: bytes(recovery.nonce),
            ciphertext: bytes(recovery.ciphertext),
          },
          context
        );
      } finally {
        wipe(recoveryKeyMaterial, recoveryKey);
      }
    });
  }

  public exportTransferState(
    accountId: string,
    currentDeviceId: string
  ): Promise<string> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      if (Object.keys(stored.pendingPrekeyUses ?? {}).length > 0) {
        throw new Error("EnigmV2 transfer is unavailable while one-time key consumption is pending.");
      }
      const historicalDeviceIds = [
        ...new Set([...stored.historicalDeviceIds, currentDeviceId]),
      ];
      if (historicalDeviceIds.length > MAX_HISTORICAL_DEVICE_IDS) {
        throw new Error("EnigmV2 historical device capacity reached.");
      }
      const serialized = JSON.stringify({ ...stored, historicalDeviceIds });
      if (utf8(serialized).length > MAX_TRANSFER_STATE_BYTES) {
        throw new Error("EnigmV2 messaging transfer state is too large.");
      }
      await this.persist(accountId, { ...stored, historicalDeviceIds });
      return serialized;
    });
  }

  public importTransferState(
    accountId: string,
    serialized: string
  ): Promise<void> {
    return this.exclusive(accountId, async () => {
      if (utf8(serialized).length > MAX_TRANSFER_STATE_BYTES) {
        throw new Error("EnigmV2 messaging transfer state is too large.");
      }
      const transferred = JSON.parse(
        serialized
      ) as StoredMessagingCryptoEnigmV2;
      const current = await this.load(accountId);
      validateStoredState(transferred);
      if (
        Object.keys(current.pendingPrekeyUses ?? {}).length > 0 ||
        Object.keys(transferred.pendingPrekeyUses ?? {}).length > 0
      ) {
        throw new Error("EnigmV2 transfer cannot include pending one-time key consumption.");
      }
      const currentHasMessagingState =
        Object.keys(current.sessions).length > 0 ||
        Object.keys(current.groups).length > 0 ||
        current.historicalDeviceIds.length > 0 ||
        current.recoveryKeyInitialized;
      if (
        currentHasMessagingState &&
        current.recoveryKey !== transferred.recoveryKey
      ) {
        throw new Error(
          "Conflicting EnigmV2 recovery key during device transfer."
        );
      }
      assertTransferEntries(current.sessions, transferred.sessions, 'messaging session');
      assertTransferEntries(current.groups, transferred.groups, 'group state');
      for (const [key, sender] of Object.entries(current.sessionSenders ?? {})) {
        const other = transferred.sessionSenders?.[key];
        if (other && (sender.accountId !== other.accountId || sender.deviceId !== other.deviceId || sender.identityKeyId !== other.identityKeyId))
          throw new Error('Conflicting EnigmV2 session sender attribution during device transfer.');
      }
      const merged: StoredMessagingCryptoEnigmV2 = {
        version: STORAGE_VERSION,
        recoveryKey: currentHasMessagingState
          ? current.recoveryKey
          : transferred.recoveryKey,
        recoveryKeyInitialized:
          current.recoveryKeyInitialized || transferred.recoveryKeyInitialized,
        sessions: { ...transferred.sessions, ...current.sessions },
        sessionSenders: { ...transferred.sessionSenders, ...current.sessionSenders },
        groups: { ...transferred.groups, ...current.groups },
        historicalDeviceIds: [
          ...new Set([
            ...transferred.historicalDeviceIds,
            ...current.historicalDeviceIds,
          ]),
        ],
      };
      validateStoredState(merged);
      await this.persist(accountId, merged);
    });
  }

  public historicalDeviceIds(accountId: string): Promise<string[]> {
    return this.exclusive(accountId, async () => [
      ...(await this.load(accountId)).historicalDeviceIds,
    ]);
  }

  public decrypt(
    accountId: string,
    id: string,
    message: EncodedRatchetMessageEnigmV2,
    context: Uint8Array
  ): Promise<Uint8Array> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      let next: SessionState | undefined;
      let plaintext: Uint8Array | undefined;
      let committed = false;
      const wire: RatchetCiphertext = {
        version: message.version,
        chainId: bytes(message.chainId),
        counter: message.counter,
        nonce: bytes(message.nonce),
        ciphertext: bytes(message.ciphertext),
      };
      try {
        const decrypted = sessionDecrypt(session, wire, context);
        next = decrypted.next;
        plaintext = decrypted.plaintext;
        stored.sessions[key] = encodeSession(decrypted.next);
        await this.persist(accountId, stored);
        committed = true;
        return decrypted.plaintext;
      } finally {
        if (!committed && plaintext) wipe(plaintext);
        if (next) wipeSession(next);
        wipeSession(session);
      }
    });
  }

  public decryptAndCommit<T>(
    accountId: string,
    id: string,
    message: EncodedRatchetMessageEnigmV2,
    context: Uint8Array,
    authenticate: (plaintext: Uint8Array) => T | Promise<T>,
    expectedSender?: { accountId: string; deviceId: string }
  ): Promise<T> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      if (expectedSender) assertSender(stored, key, expectedSender.accountId, expectedSender.deviceId);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      const wire: RatchetCiphertext = {
        version: message.version,
        chainId: bytes(message.chainId),
        counter: message.counter,
        nonce: bytes(message.nonce),
        ciphertext: bytes(message.ciphertext),
      };
      let next: SessionState | undefined;
      let plaintext: Uint8Array | undefined;
      try {
        const decrypted = sessionDecrypt(session, wire, context);
        next = decrypted.next;
        plaintext = decrypted.plaintext;
        const authenticated = await authenticate(plaintext);
        stored.sessions[key] = encodeSession(next);
        await this.persist(accountId, stored);
        return authenticated;
      } finally {
        if (plaintext) wipe(plaintext);
        if (next) wipeSession(next);
        wipeSession(session);
      }
    });
  }

  public bootstrapDecryptAndCommit<T>(
    accountId: string,
    id: string,
    rootKey: Uint8Array,
    message: EncodedRatchetMessageEnigmV2,
    context: Uint8Array,
    authenticate: (plaintext: Uint8Array) => T | Promise<T>,
    sender?: EnigmSessionSender,
    pendingPrekeyUse?: PendingPrekeyUseEnigmV2
  ): Promise<T> {
    return this.exclusive(accountId, async () => {
      if (sender) validateSender(sender);
      if (pendingPrekeyUse) {
        validatePendingPrekeyUse(pendingPrekeyUse);
        if (!sender) throw new Error("EnigmV2 pending one-time key use requires sender attribution.");
      }
      const stored = await this.load(accountId);
      const key = stateKey(id);
      if (pendingPrekeyUse) {
        assertPendingPrekeyAvailable(stored, key, pendingPrekeyUse);
      }
      if (stored.sessions[key])
        throw new Error("EnigmV2 messaging session already exists.");
      if (Object.keys(stored.sessions).length >= MAX_SESSIONS) {
        throw new Error("EnigmV2 session capacity reached.");
      }
      const session = initializeSession(rootKey, context, "responder");
      const wire: RatchetCiphertext = {
        version: message.version,
        chainId: bytes(message.chainId),
        counter: message.counter,
        nonce: bytes(message.nonce),
        ciphertext: bytes(message.ciphertext),
      };
      let next: SessionState | undefined;
      let plaintext: Uint8Array | undefined;
      try {
        const decrypted = sessionDecrypt(session, wire, context);
        next = decrypted.next;
        plaintext = decrypted.plaintext;
        const authenticated = await authenticate(plaintext);
        stored.sessions[key] = encodeSession(next);
        if (sender) {
          stored.sessionSenders ??= {};
          stored.sessionSenders[key] = { ...sender };
        }
        if (pendingPrekeyUse) {
          stored.pendingPrekeyUses ??= {};
          stored.pendingPrekeyUses[key] = { ...pendingPrekeyUse };
        }
        await this.persist(accountId, stored);
        return authenticated;
      } finally {
        if (plaintext) wipe(plaintext);
        if (next) wipeSession(next);
        wipeSession(session);
      }
    });
  }

  public rekey(
    accountId: string,
    id: string,
    freshHybridSecret: Uint8Array,
    context: Uint8Array,
    role: SessionRole
  ): Promise<void> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      assertSessionReady(stored, key);
      const encoded = stored.sessions[key];
      if (!encoded)
        throw new Error("EnigmV2 messaging session is unavailable.");
      const session = decodeSession(encoded);
      let next: SessionState | undefined;
      try {
        next = rekeySession(session, freshHybridSecret, context, role);
        stored.sessions[key] = encodeSession(next);
        await this.persist(accountId, stored);
      } finally {
        if (next) wipeSession(next);
        wipeSession(session);
      }
    });
  }

  public createGroup(
    accountId: string,
    id: string,
    groupId: Uint8Array,
    memberDeviceIds: readonly string[]
  ): Promise<void> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      if (stored.groups[key])
        throw new Error("EnigmV2 group epoch already exists.");
      if (Object.keys(stored.groups).length >= MAX_GROUPS)
        throw new Error("EnigmV2 group capacity reached.");
      const group = createGroupEpoch(
        groupId,
        memberDeviceIds,
        this.options.randomSource
      );
      try {
        stored.groups[key] = encodeGroup(group);
        await this.persist(accountId, stored);
      } finally {
        wipe(group.epochSecret);
      }
    });
  }

  public rotateGroup(
    accountId: string,
    id: string,
    memberDeviceIds: readonly string[]
  ): Promise<number> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const key = stateKey(id);
      const encoded = stored.groups[key];
      if (!encoded) throw new Error("EnigmV2 group epoch is unavailable.");
      const group = decodeGroup(encoded);
      let next: GroupEpochState | undefined;
      try {
        next = rotateGroupEpoch(
          group,
          memberDeviceIds,
          this.options.randomSource
        );
        stored.groups[key] = encodeGroup(next);
        await this.persist(accountId, stored);
        return next.epoch;
      } finally {
        if (next) wipe(next.epochSecret);
        wipe(group.epochSecret);
      }
    });
  }

  public encryptGroup(
    accountId: string,
    id: string,
    purpose: EncodedGroupMessageEnigmV2["purpose"],
    plaintext: Uint8Array
  ): Promise<EncodedGroupMessageEnigmV2> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const encoded = stored.groups[stateKey(id)];
      if (!encoded) throw new Error("EnigmV2 group epoch is unavailable.");
      const group = decodeGroup(encoded);
      try {
        const encrypted = encryptGroupEpoch(
          group,
          purpose,
          plaintext,
          this.options.randomSource
        );
        return {
          version: 2,
          groupId: b64(encrypted.groupId),
          epoch: encrypted.epoch,
          purpose: encrypted.purpose,
          nonce: b64(encrypted.nonce),
          ciphertext: b64(encrypted.ciphertext),
        };
      } finally {
        wipe(group.epochSecret);
      }
    });
  }

  public decryptGroup(
    accountId: string,
    id: string,
    message: EncodedGroupMessageEnigmV2
  ): Promise<Uint8Array> {
    return this.exclusive(accountId, async () => {
      const stored = await this.load(accountId);
      const encoded = stored.groups[stateKey(id)];
      if (!encoded) throw new Error("EnigmV2 group epoch is unavailable.");
      const group = decodeGroup(encoded);
      const wire: GroupEpochCiphertext = {
        version: message.version,
        groupId: bytes(message.groupId),
        epoch: message.epoch,
        purpose: message.purpose,
        nonce: bytes(message.nonce),
        ciphertext: bytes(message.ciphertext),
      };
      try {
        return decryptGroupEpoch(group, wire);
      } finally {
        wipe(group.epochSecret);
      }
    });
  }

  public delete(accountId: string): Promise<void> {
    return this.exclusive(accountId, () =>
      this.options.store.delete(accountId)
    );
  }
}
export const createEnigmSessionClient = (options: {
  store: SecureStateStore;
  randomSource: RandomSource;
}) => new MessagingCryptoManagerEnigmV2(options);
