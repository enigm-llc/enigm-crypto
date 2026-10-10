import type { PrivateIdentity, PrivateKemBundle } from "../core/types.js";
/** load returns fresh, independently owned buffers: the SDK wipes them after use. */
export interface DeviceKeyStore {
  load(
    accountId: string
  ): Promise<{
    identity: PrivateIdentity;
    bundles: readonly { bundle: PrivateKemBundle; lastResort: boolean }[];
  }>;
  consume(accountId: string, keyId: string): Promise<void>;
}
