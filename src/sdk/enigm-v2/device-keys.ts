import type { DeviceKeyStore } from "../../adapters/device-keys.js";
import { decodeBase64, encodeBase64 } from "../../core/base64.js";
import { equal, wipe, type RandomSource } from "../../core/index.js";
import {
  decodeEnvelope,
  decodePublicIdentity,
  decodePublicKemBundle,
  encodeEnvelope,
  encodePublicIdentity,
  encodePublicKemBundle,
} from "../../codecs/index.js";
import {
  publicIdentity,
  publicKemBundle,
  validatePrivateIdentity,
  validatePrivateKemBundle,
} from "../../primitives/index.js";
import { seal, open } from "../../protocols/envelope.js";
export const createEnigmDeviceClient = (options: {
  store: DeviceKeyStore;
  randomSource: RandomSource;
  now?: () => number;
}) => {
  const withKeys = async <T>(
    accountId: string,
    action: (
      state: Awaited<ReturnType<DeviceKeyStore["load"]>>
    ) => T | Promise<T>
  ): Promise<T> => {
    const state = await options.store.load(accountId);
    try {
      validatePrivateIdentity(state.identity);
      for (const item of state.bundles) validatePrivateKemBundle(item.bundle);
      return await action(state);
    } finally {
      wipe(state.identity.mlDsaSecretKey, state.identity.ed25519SecretKey);
      for (const item of state.bundles)
        wipe(item.bundle.mlKemSecretKey, item.bundle.x25519SecretKey);
    }
  };
  const checkIdentity = (encoded: string, expected?: string) => {
    const identity = decodePublicIdentity(decodeBase64(encoded));
    if (
      expected !== undefined &&
      !equal(identity.keyId, decodeBase64(expected))
    )
      throw new Error("EnigmV2 identity key identifier mismatch.");
    return identity;
  };
  const openPending = (
    accountId: string,
    sender: string,
    encoded: string,
    context: Uint8Array,
    expected?: string,
    supplementalSecret?: Uint8Array
  ) =>
    withKeys(accountId, (state) => {
      const envelope = decodeEnvelope(decodeBase64(encoded));
      const item = state.bundles.find((item) =>
        equal(item.bundle.keyId, envelope.recipientKemKeyId)
      );
      if (!item) throw new Error("EnigmV2 recipient KEM key is unavailable.");
      return {
        plaintext: open({
          sender: checkIdentity(sender, expected),
          recipientIdentity: publicIdentity(state.identity),
          recipient: item.bundle,
          envelope,
          context,
          now: (options.now ?? Date.now)(),
          ...(supplementalSecret === undefined ? {} : { supplementalSecret }),
        }),
        keyId: encodeBase64(item.bundle.keyId),
        consumable: !item.lastResort,
      };
    });
  return {
    publicIdentityEncoded: (accountId: string) =>
      withKeys(accountId, (state) =>
        encodeBase64(encodePublicIdentity(publicIdentity(state.identity)))
      ),
    publicLastResortBundleEncoded: (accountId: string) =>
      withKeys(accountId, (state) => {
        const item = state.bundles.find((item) => item.lastResort);
        if (!item)
          throw new Error("EnigmV2 last-resort bundle is unavailable.");
        return encodeBase64(
          encodePublicKemBundle(publicKemBundle(item.bundle))
        );
      }),
    sealSession: (
      accountId: string,
      identity: string,
      bundle: string,
      plaintext: Uint8Array,
      context: Uint8Array,
      supplementalSecret?: Uint8Array,
      expectedIdentityKeyId?: string
    ) =>
      withKeys(accountId, (state) =>
        encodeBase64(
          encodeEnvelope(
            seal({
              sender: state.identity,
              recipientIdentity: checkIdentity(identity, expectedIdentityKeyId),
              recipient: decodePublicKemBundle(decodeBase64(bundle)),
              plaintext,
              context,
              randomSource: options.randomSource,
              now: (options.now ?? Date.now)(),
              ...(supplementalSecret === undefined
                ? {}
                : { supplementalSecret }),
            })
          )
        )
      ),
    openSessionEncodedPending: openPending,
    openSessionEncoded: async (
      accountId: string,
      sender: string,
      envelope: string,
      context: Uint8Array,
      supplementalSecret?: Uint8Array,
      expected?: string
    ) => {
      const opened = await openPending(
        accountId,
        sender,
        envelope,
        context,
        expected,
        supplementalSecret
      );
      try {
        if (opened.consumable)
          await options.store.consume(accountId, opened.keyId);
        return opened.plaintext;
      } catch (error) {
        wipe(opened.plaintext);
        throw error;
      }
    },
    consumeOpenedSessionKey: (accountId: string, keyId: string) =>
      options.store.consume(accountId, keyId),
  };
};
