import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8 } from "../../core/bytes.js";
import { decodeBase64 } from "../../core/base64.js";
import { KeyTransparencyErrorEnigmV2 } from "./errors.js";
export type EnigmIdentityBindingInput = {
  expectedAccountId: string;
  expectedDeviceId: string;
  identityKeyId: string;
  accountCommitment: string;
  deviceCommitment: string;
  bindingSignature: string;
};
export const verifyEnigmIdentityBinding = (
  input: EnigmIdentityBindingInput,
  logPublicKey: string
): void => {
  try {
    const signature = decodeBase64(input.bindingSignature);
    const publicKey = decodeBase64(logPublicKey);
    if (
      !input.expectedAccountId ||
      !input.expectedDeviceId ||
      input.expectedAccountId.length > 256 ||
      input.expectedDeviceId.length > 256 ||
      signature.length !== 64 ||
      publicKey.length !== 32 ||
      !ed25519.verify(
        signature,
        utf8(
          JSON.stringify([
            "enigm-key-transparency-binding-v2",
            input.expectedAccountId,
            input.expectedDeviceId,
            input.identityKeyId,
            input.accountCommitment,
            input.deviceCommitment,
          ])
        ),
        publicKey,
        { zip215: false }
      )
    ) {
      throw new KeyTransparencyErrorEnigmV2("IDENTITY_BINDING_MISMATCH");
    }
  } catch {
    throw new KeyTransparencyErrorEnigmV2("IDENTITY_BINDING_MISMATCH");
  }
};
