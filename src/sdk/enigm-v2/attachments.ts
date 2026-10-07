import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8, wipe, type RandomSource } from "../../core/index.js";
import { decodeUtf8 } from "../../core/utf8.js";
import { encodeBase64, decodeBase64 } from "../../core/base64.js";
import {
  generateContentKey,
  encryptContent,
  decryptContent,
} from "../../protocols/payload.js";
export type EnigmAttachment = { version: 2; nonce: string; ciphertext: string };
const context = utf8("enigm-crypto-v2-attachment");
/** Existing Enigm attachments encrypt UTF-8 base64 text, not raw file bytes. */
export const encryptEnigmAttachment = (
  plaintext: Uint8Array,
  randomSource: RandomSource
): {
  encrypted: EnigmAttachment;
  fileKey: string;
} => {
  const key = generateContentKey(randomSource);
  try {
    const encrypted = encryptContent(
      key,
      utf8(encodeBase64(plaintext)),
      context,
      randomSource
    );
    return {
      encrypted: {
        version: 2,
        nonce: encodeBase64(encrypted.nonce),
        ciphertext: encodeBase64(encrypted.ciphertext),
      },
      fileKey: encodeBase64(key),
    };
  } finally {
    wipe(key);
  }
};
export const decryptEnigmAttachment = (
  encrypted: EnigmAttachment,
  fileKey: string,
  expectedPlaintextSha256?: string
): Uint8Array => {
  if (encrypted.version !== 2)
    throw new Error("Invalid EnigmV2 encrypted attachment.");
  const key = decodeBase64(fileKey);
  let encoded: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    encoded = decryptContent(
      key,
      {
        version: 2,
        nonce: decodeBase64(encrypted.nonce),
        ciphertext: decodeBase64(encrypted.ciphertext),
      },
      context
    );
    // Mobile historically ignored whitespace in recovered base64 text.
    plaintext = decodeBase64(decodeUtf8(encoded).replace(/\s/g, ""));
    if (
      expectedPlaintextSha256 !== undefined &&
      bytesToHex(sha256(plaintext)) !== expectedPlaintextSha256
    ) {
      throw new Error("Captured media integrity verification failed.");
    }
    const result = plaintext;
    plaintext = undefined;
    return result;
  } finally {
    wipe(key);
    if (encoded) wipe(encoded);
    if (plaintext) wipe(plaintext);
  }
};
