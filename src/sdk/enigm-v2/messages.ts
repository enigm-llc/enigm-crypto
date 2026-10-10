import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  utf8 as utf8Bytes,
  wipe,
  type RandomSource,
} from "../../core/index.js";
import { encodeBase64, decodeBase64 } from "../../core/base64.js";
import {
  encryptContent,
  decryptContent,
  generateContentKey,
  type ContentCiphertext,
} from "../../protocols/payload.js";
import type {
  EncodedRatchetMessageEnigmV2,
  EncodedRecoveryContentKeyEnigmV2,
  createEnigmSessionClient,
} from "./session-state.js";
import type { createEnigmDeviceClient } from "./device-keys.js";
import { verifyEnigmIdentityBinding } from "./identity-binding.js";
export type MessageDeviceTargetEnigmV2 = {
  userId: string;
  deviceId: string;
  encodedIdentity?: string;
  encodedBundle?: string;
  identityKeyId?: string;
};

export type MessageKeyPacketEnigmV2 = {
  version: 2;
  recipientUserId: string;
  recipientDeviceId: string;
  senderDeviceId: string;
  senderUserId?: string;
  senderIdentityKeyId?: string;
  senderIdentityBindingSignature?: string;
  senderAccountCommitment?: string;
  senderDeviceCommitment?: string;
  sessionId: string;
  senderIdentity?: string;
  bootstrapEnvelope?: string;
  directContentKeyEnvelope?: string;
  wrappedContentKey?: EncodedRatchetMessageEnigmV2;
  recoveryContentKey: EncodedRecoveryContentKeyEnigmV2;
};

export type EncryptedMessageEnigmV2 = {
  version: 2 | 3;
  nonce: string;
  ciphertext: string;
  keyPackets: MessageKeyPacketEnigmV2[];
};

type DecryptMessageInputEnigmV2 = {
  accountId: string;
  conversationId: string;
  messageId: string;
  currentDeviceId: string;
  expectedSenderUserId?: string;
  encrypted: EncryptedMessageEnigmV2;
};

export const createEnigmMessageClient = (options: {
  randomSource: RandomSource;
  device: ReturnType<typeof createEnigmDeviceClient>;
  sessions: ReturnType<typeof createEnigmSessionClient>;
  logPublicKey: string;
  /** Maximum message plaintext bytes, default 1 MiB; attachments have a separate API. */
  maximumMessageBytes?: number;
}) => {
  const maximumMessageBytes = options.maximumMessageBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maximumMessageBytes) || maximumMessageBytes < 1 || maximumMessageBytes > 32 * 1024 * 1024)
    throw new Error("Invalid EnigmV2 message size limit.");
  const b64 = encodeBase64;
  const bytes = (value: string, limit = maximumMessageBytes + 16) => decodeBase64(value, limit);
  const validateIdentifier = (value: string): void => {
    if (typeof value !== "string" || !value || value.length > 256 || /[:|]/u.test(value))
      throw new Error("Invalid EnigmV2 protocol identifier.");
  };
  const randomSource = options.randomSource;
  const digest = (value: string): string =>
    bytesToHex(sha256(utf8Bytes(value)));

  const sessionLocator = (
    conversationId: string,
    senderDeviceId: string,
    recipientDeviceId: string
  ): string => {
    [conversationId, senderDeviceId, recipientDeviceId].forEach(validateIdentifier);
    return digest(`v2:${conversationId}:${senderDeviceId}:${recipientDeviceId}`);
  };

  const sessionContext = (
    conversationId: string,
    senderDeviceId: string,
    recipientDeviceId: string
  ): Uint8Array => {
    [conversationId, senderDeviceId, recipientDeviceId].forEach(validateIdentifier);
    return utf8Bytes(
      `enigm-crypto-v2-session|conversation:${conversationId}|sender:${senderDeviceId}|recipient:${recipientDeviceId}`
    );
  };

  const contentContext = (
    conversationId: string,
    messageId: string,
    senderDeviceId: string
  ): Uint8Array => {
    [conversationId, messageId, senderDeviceId].forEach(validateIdentifier);
    return utf8Bytes(
      `enigm-crypto-v2-content|conversation:${conversationId}|message:${messageId}|sender:${senderDeviceId}`
    );
  };

  const recoveryContext = (
    conversationId: string,
    messageId: string,
    senderDeviceId: string,
    recipientDeviceId: string
  ): Uint8Array =>
    utf8Bytes(
      `enigm-crypto-v2-recovery|conversation:${conversationId}|message:${messageId}|sender:${senderDeviceId}|recipient:${recipientDeviceId}`
    );

  const decryptLocalMessageEnigmV2 = async (
    input: DecryptMessageInputEnigmV2,
    packet: MessageKeyPacketEnigmV2,
    context: Uint8Array
  ): Promise<Uint8Array> => {
    if (
      !packet.directContentKeyEnvelope ||
      !packet.senderIdentity ||
      packet.wrappedContentKey
    ) {
      throw new Error("Invalid EnigmV2 local content-key envelope.");
    }

    let contentKey: Uint8Array;
    if (packet.recipientDeviceId === input.currentDeviceId) {
      contentKey = await options.device.openSessionEncoded(
        input.accountId,
        packet.senderIdentity,
        packet.directContentKeyEnvelope,
        context,
        undefined,
        packet.senderIdentityKeyId
      );
    } else {
      contentKey = await options.sessions.decryptLocalRecovery(
        input.accountId,
        packet.recoveryContentKey,
        recoveryContext(
          input.conversationId,
          input.messageId,
          packet.senderDeviceId,
          packet.recipientDeviceId
        )
      );
    }

    try {
      return decryptContent(
        contentKey,
        {
          version: 2,
          nonce: bytes(input.encrypted.nonce),
          ciphertext: bytes(input.encrypted.ciphertext),
        },
        contentContext(
          input.conversationId,
          input.messageId,
          packet.senderDeviceId
        )
      );
    } finally {
      wipe(contentKey);
    }
  };

  const needsMessageSessionEnigmV2 = (
    accountId: string,
    conversationId: string,
    senderDeviceId: string,
    recipientDeviceId: string
  ): Promise<boolean> =>
    recipientDeviceId === senderDeviceId
      ? Promise.resolve(false)
      : options.sessions
          .hasSession(
            accountId,
            sessionLocator(conversationId, senderDeviceId, recipientDeviceId)
          )
          .then((exists) => !exists);

  const encryptMessageEnigmV2 = async (input: {
    accountId: string;
    conversationId: string;
    messageId: string;
    senderDeviceId: string;
    senderBinding: {
      identityKeyId: string;
      bindingSignature: string;
      accountCommitment: string;
      deviceCommitment: string;
    };
    plaintext: Uint8Array;
    targets: readonly MessageDeviceTargetEnigmV2[];
  }): Promise<EncryptedMessageEnigmV2> => {
    if (input.plaintext.length > maximumMessageBytes) throw new Error("EnigmV2 message is too large.");
    if (input.targets.length < 1 || input.targets.length > 100) {
      throw new Error("Invalid EnigmV2 message device target count.");
    }
    const uniqueTargets = new Set(
      input.targets.map((target) => target.deviceId)
    );
    if (uniqueTargets.size !== input.targets.length)
      throw new Error("Duplicate EnigmV2 message device target.");

    const key = generateContentKey(randomSource);
    const bootstrapRoots: Uint8Array[] = [];
    try {
      const content = encryptContent(
        key,
        input.plaintext,
        contentContext(
          input.conversationId,
          input.messageId,
          input.senderDeviceId
        ),
        randomSource
      );
      const senderIdentity = await options.device.publicIdentityEncoded(
        input.accountId
      );
      const directPackets = new Map<string, MessageKeyPacketEnigmV2>();
      const ratchetTargets: Array<{
        target: MessageDeviceTargetEnigmV2;
        locator: string;
        context: Uint8Array;
        recoveryContext: Uint8Array;
        rootKey?: Uint8Array;
        bootstrapEnvelope?: string;
      }> = [];
      const prepareTarget = async (target: MessageDeviceTargetEnigmV2): Promise<void> => {
        const locator = sessionLocator(
          input.conversationId,
          input.senderDeviceId,
          target.deviceId
        );
        const context = sessionContext(
          input.conversationId,
          input.senderDeviceId,
          target.deviceId
        );
        let bootstrapEnvelope: string | undefined;
        if (target.deviceId === input.senderDeviceId) {
          const ownBundle = await options.device.publicLastResortBundleEncoded(
            input.accountId
          );
          const ownRecoveryContext = recoveryContext(
            input.conversationId,
            input.messageId,
            input.senderDeviceId,
            target.deviceId
          );
          const ownRecovery = await options.sessions.encryptLocalRecovery(
            input.accountId,
            key,
            ownRecoveryContext
          );
          directPackets.set(target.deviceId, {
            version: 2,
            recipientUserId: target.userId,
            recipientDeviceId: target.deviceId,
            senderDeviceId: input.senderDeviceId,
            senderUserId: input.accountId,
            senderIdentityKeyId: input.senderBinding.identityKeyId,
            senderIdentityBindingSignature:
              input.senderBinding.bindingSignature,
            senderAccountCommitment: input.senderBinding.accountCommitment,
            senderDeviceCommitment: input.senderBinding.deviceCommitment,
            sessionId: locator,
            senderIdentity,
            directContentKeyEnvelope: await options.device.sealSession(
              input.accountId,
              senderIdentity,
              ownBundle,
              key,
              context
            ),
            recoveryContentKey: ownRecovery,
          });
          return;
        }
        let rootKey: Uint8Array | undefined;
        if (!(await options.sessions.hasSession(input.accountId, locator))) {
          if (!target.encodedIdentity || !target.encodedBundle) {
            throw new Error(
              "A EnigmV2 prekey is required to initialize the device session."
            );
          }
          rootKey = randomSource(32);
          bootstrapRoots.push(rootKey);
          bootstrapEnvelope = await options.device.sealSession(
            input.accountId,
            target.encodedIdentity,
            target.encodedBundle,
            rootKey,
            context,
            undefined,
            target.identityKeyId
          );
        }
        ratchetTargets.push({
          target,
          locator,
          context,
          recoveryContext: recoveryContext(
            input.conversationId,
            input.messageId,
            input.senderDeviceId,
            target.deviceId
          ),
          ...(rootKey === undefined ? {} : { rootKey }),
          ...(bootstrapEnvelope === undefined ? {} : { bootstrapEnvelope }),
        });
      };
      // Preserve target order and sequential storage operations.
      await input.targets.reduce(
        (previous, target) => previous.then(() => prepareTarget(target)),
        Promise.resolve()
      );
      const ratchetResults = ratchetTargets.length
        ? await options.sessions.encryptMany(
            input.accountId,
            ratchetTargets.map(
              ({
                locator,
                context,
                recoveryContext: targetRecoveryContext,
                rootKey,
              }) => ({
                id: locator,
                plaintext: key,
                context,
                recoveryContext: targetRecoveryContext,
                ...(rootKey === undefined ? {} : { rootKey }),
              })
            )
          )
        : [];
      const ratchetPackets = new Map(
        ratchetResults.map((result, index) => {
          const prepared = ratchetTargets[index]!;
          if (result.initialized && !prepared.bootstrapEnvelope) {
            throw new Error(
              "EnigmV2 session bootstrap envelope is unavailable."
            );
          }
          return [
            prepared.target.deviceId,
            {
              version: 2 as const,
              recipientUserId: prepared.target.userId,
              recipientDeviceId: prepared.target.deviceId,
              senderDeviceId: input.senderDeviceId,
              senderUserId: input.accountId,
              sessionId: prepared.locator,
              ...(result.initialized
                ? {
                    senderIdentity,
                    bootstrapEnvelope: prepared.bootstrapEnvelope,
                    senderIdentityKeyId: input.senderBinding.identityKeyId,
                    senderIdentityBindingSignature:
                      input.senderBinding.bindingSignature,
                    senderAccountCommitment:
                      input.senderBinding.accountCommitment,
                    senderDeviceCommitment:
                      input.senderBinding.deviceCommitment,
                  }
                : {}),
              wrappedContentKey: result.message,
              recoveryContentKey: result.recovery,
            },
          ];
        })
      );
      const keyPackets = input.targets.map((target) => {
        const packet =
          directPackets.get(target.deviceId) ??
          ratchetPackets.get(target.deviceId);
        if (!packet)
          throw new Error("EnigmV2 content-key packet is unavailable.");
        return packet;
      });
      return {
        version: 3,
        nonce: b64(content.nonce),
        ciphertext: b64(content.ciphertext),
        keyPackets,
      };
    } finally {
      bootstrapRoots.forEach((root) => wipe(root));
      wipe(key);
    }
  };

  const authenticatePacketSender = (
    input: DecryptMessageInputEnigmV2,
    packet: MessageKeyPacketEnigmV2
  ): string | undefined => {
    if (
      input.expectedSenderUserId &&
      packet.senderUserId &&
      packet.senderUserId !== input.expectedSenderUserId
    ) {
      throw new Error("EnigmV2 message sender attribution mismatch.");
    }
    if (input.encrypted.version === 3 && !packet.senderUserId) {
      throw new Error("EnigmV2 authenticated sender binding is unavailable.");
    }
    const authenticatedSenderUserId =
      input.expectedSenderUserId ?? packet.senderUserId;
    if (packet.senderIdentity) {
      if (
        !authenticatedSenderUserId ||
        !packet.senderIdentityKeyId ||
        !packet.senderIdentityBindingSignature ||
        !packet.senderAccountCommitment ||
        !packet.senderDeviceCommitment
      ) {
        throw new Error("EnigmV2 sender identity binding is unavailable.");
      }
      verifyEnigmIdentityBinding(
        {
          expectedAccountId: authenticatedSenderUserId,
          expectedDeviceId: packet.senderDeviceId,
          identityKeyId: packet.senderIdentityKeyId,
          accountCommitment: packet.senderAccountCommitment,
          deviceCommitment: packet.senderDeviceCommitment,
          bindingSignature: packet.senderIdentityBindingSignature,
        },
        options.logPublicKey
      );
    }
    return authenticatedSenderUserId;
  };

  const bootstrapMessage = async (
    input: DecryptMessageInputEnigmV2,
    packet: MessageKeyPacketEnigmV2,
    context: Uint8Array,
    encryptedContent: ContentCiphertext,
    authenticatedSenderUserId: string | undefined
  ): Promise<Uint8Array> => {
    if (!packet.bootstrapEnvelope || !packet.senderIdentity) {
      throw new Error("Invalid EnigmV2 message session bootstrap.");
    }
    const opened = await options.device.openSessionEncodedPending(
      input.accountId,
      packet.senderIdentity,
      packet.bootstrapEnvelope,
      context,
      packet.senderIdentityKeyId
    );
    try {
      const plaintext = await options.sessions.bootstrapDecryptAndCommit(
        input.accountId,
        packet.sessionId,
        opened.plaintext,
        packet.wrappedContentKey!,
        context,
        (contentKey) =>
          decryptContent(
            contentKey,
            encryptedContent,
            contentContext(
              input.conversationId,
              input.messageId,
              packet.senderDeviceId
            )
          ),
        { accountId: authenticatedSenderUserId!, deviceId: packet.senderDeviceId, identityKeyId: packet.senderIdentityKeyId! }
      );
      if (opened.consumable) {
        await options.device.consumeOpenedSessionKey(
          input.accountId,
          opened.keyId
        );
      }
      return plaintext;
    } finally {
      wipe(opened.plaintext);
    }
  };

  const migrateSessionSender = async (
    input: DecryptMessageInputEnigmV2,
    packet: MessageKeyPacketEnigmV2,
    context: Uint8Array,
    hasBootstrap: boolean,
    sessionExists: boolean,
    authenticatedSenderUserId: string | undefined
  ): Promise<void> => {
    // Upgrade legacy persisted sessions only from a signed envelope matching their root.
    if (hasBootstrap && sessionExists && !(await options.sessions.hasSessionSender(input.accountId, packet.sessionId))) {
      if (!packet.bootstrapEnvelope || !packet.senderIdentity || !authenticatedSenderUserId || !packet.senderIdentityKeyId)
        throw new Error('EnigmV2 sender attribution migration requires an authenticated bootstrap.');
      const opened = await options.device.openSessionEncodedPending(input.accountId, packet.senderIdentity, packet.bootstrapEnvelope, context, packet.senderIdentityKeyId);
      try {
        await options.sessions.initializeOrVerifySession(input.accountId, packet.sessionId, opened.plaintext, context, 'responder',
          { accountId: authenticatedSenderUserId, deviceId: packet.senderDeviceId, identityKeyId: packet.senderIdentityKeyId });
      } finally { wipe(opened.plaintext); }
    }
  };

  const selectMessagePacket = async (input: DecryptMessageInputEnigmV2): Promise<{
    packet: MessageKeyPacketEnigmV2; context: Uint8Array;
  }> => {
    if (!Array.isArray(input.encrypted.keyPackets) || input.encrypted.keyPackets.length < 1 || input.encrypted.keyPackets.length > 100)
      throw new Error("Invalid EnigmV2 message device target count.");
    bytes(input.encrypted.ciphertext);
    bytes(input.encrypted.nonce, 12);
    if (input.encrypted.version !== 2 && input.encrypted.version !== 3) {
      throw new Error("Unsupported encrypted message version.");
    }
    const historicalDeviceIds = await options.sessions.historicalDeviceIds(
      input.accountId
    );
    const acceptedDeviceIds = new Set([
      input.currentDeviceId,
      ...historicalDeviceIds,
    ]);
    const packet = input.encrypted.keyPackets.find((item) =>
      acceptedDeviceIds.has(item.recipientDeviceId)
    );
    if (!packet)
      throw new Error("This device is not an encrypted message recipient.");
    if (packet.recoveryContentKey?.version !== 2) {
      throw new Error(
        "The EnigmV2 recovery content-key envelope is unavailable."
      );
    }
    bytes(packet.recoveryContentKey.nonce, 12);
    bytes(packet.recoveryContentKey.ciphertext, 48);
    if (packet.wrappedContentKey) {
      bytes(packet.wrappedContentKey.chainId, 32);
      bytes(packet.wrappedContentKey.nonce, 12);
      bytes(packet.wrappedContentKey.ciphertext, 48);
    }
    const context = sessionContext(
      input.conversationId,
      packet.senderDeviceId,
      packet.recipientDeviceId
    );
    const expectedSessionId = sessionLocator(
      input.conversationId,
      packet.senderDeviceId,
      packet.recipientDeviceId
    );
    if (packet.sessionId !== expectedSessionId)
      throw new Error("Invalid EnigmV2 message session identifier.");
    return { packet, context };
  };

  const decryptMessageEnigmV2 = async (
    input: DecryptMessageInputEnigmV2
  ): Promise<Uint8Array> => {
    const { packet, context } = await selectMessagePacket(input);
    const authenticatedSenderUserId = authenticatePacketSender(input, packet);
    if (packet.recipientDeviceId === packet.senderDeviceId) {
      if (
        authenticatedSenderUserId &&
        authenticatedSenderUserId !== input.accountId
      ) {
        throw new Error(
          "A remote sender cannot use the EnigmV2 local envelope path."
        );
      }
      return decryptLocalMessageEnigmV2(input, packet, context);
    }
    if (!packet.wrappedContentKey || packet.directContentKeyEnvelope) {
      throw new Error("Invalid EnigmV2 ratchet content-key packet.");
    }
    const hasBootstrap = Boolean(
      packet.bootstrapEnvelope || packet.senderIdentity
    );
    const sessionExists = await options.sessions.hasSession(
      input.accountId,
      packet.sessionId
    );
    if (
      input.encrypted.version === 2 &&
      input.expectedSenderUserId &&
      input.expectedSenderUserId !== input.accountId &&
      !sessionExists
    ) {
      throw new Error(
        "A legacy EnigmV2 bootstrap cannot establish a newly attributed sender session."
      );
    }
    const encryptedContent: ContentCiphertext = {
      version: 2,
      nonce: bytes(input.encrypted.nonce),
      ciphertext: bytes(input.encrypted.ciphertext),
    };
    if (hasBootstrap && !sessionExists) {
      return bootstrapMessage(input, packet, context, encryptedContent, authenticatedSenderUserId);
    } else if (!sessionExists) {
      throw new Error("EnigmV2 message session bootstrap is unavailable.");
    }
    await migrateSessionSender(input, packet, context, hasBootstrap, sessionExists, authenticatedSenderUserId);
    if (!authenticatedSenderUserId) throw new Error('EnigmV2 session sender attribution is unavailable.');
    await options.sessions.assertSessionSender(input.accountId, packet.sessionId, authenticatedSenderUserId, packet.senderDeviceId);
    if (
      await options.sessions.shouldUseRecovery(
        input.accountId,
        packet.sessionId,
        packet.wrappedContentKey
      )
    ) {
      const contentKey = await options.sessions.recover(
        input.accountId,
        packet.sessionId,
        packet.recoveryContentKey,
        recoveryContext(
          input.conversationId,
          input.messageId,
          packet.senderDeviceId,
          packet.recipientDeviceId
        ),
        { accountId: authenticatedSenderUserId, deviceId: packet.senderDeviceId }
      );
      try {
        const plaintext = decryptContent(
          contentKey,
          encryptedContent,
          contentContext(
            input.conversationId,
            input.messageId,
            packet.senderDeviceId
          )
        );
        return plaintext;
      } finally {
        wipe(contentKey);
      }
    }
    return options.sessions.decryptAndCommit(
      input.accountId,
      packet.sessionId,
      packet.wrappedContentKey,
      context,
      (contentKey) =>
        decryptContent(
          contentKey,
          encryptedContent,
          contentContext(
            input.conversationId,
            input.messageId,
            packet.senderDeviceId
          )
        ),
      { accountId: authenticatedSenderUserId, deviceId: packet.senderDeviceId }
    );
  };

  return {
    encryptMessage: encryptMessageEnigmV2,
    decryptMessage: decryptMessageEnigmV2,
    needsMessageSession: needsMessageSessionEnigmV2,
  };
};
