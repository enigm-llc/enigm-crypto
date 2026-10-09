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
export type EnigmAttachmentLimits = { maximumPlaintextBytes?: number };
const attachmentLimit = (limits: EnigmAttachmentLimits): number => {
  const maximum = limits.maximumPlaintextBytes ?? 50 * 1024 * 1024;
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 128 * 1024 * 1024)
    throw new Error("Invalid attachment size limit.");
  return maximum;
};
const base64Length = (length: number): number => 4 * Math.ceil(length / 3);
const context = utf8("enigm-crypto-v2-attachment");
/** Existing Enigm attachments encrypt UTF-8 base64 text, not raw file bytes. */
export const encryptEnigmAttachment = (
  plaintext: Uint8Array,
  randomSource: RandomSource,
  limits: EnigmAttachmentLimits = {}
): {
  encrypted: EnigmAttachment;
  fileKey: string;
} => {
  const maximum = attachmentLimit(limits);
  if (plaintext.length > maximum) throw new Error("Attachment exceeds size limit.");
  const key = generateContentKey(randomSource);
  let encoded: Uint8Array | undefined;
  try {
    encoded = utf8(encodeBase64(plaintext));
    const encrypted = encryptContent(
      key,
      encoded,
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
    if (encoded) wipe(encoded);
  }
};
export const decryptEnigmAttachment = (
  encrypted: EnigmAttachment,
  fileKey: string,
  expectedPlaintextSha256?: string,
  limits: EnigmAttachmentLimits = {}
): Uint8Array => {
  if (encrypted.version !== 2)
    throw new Error("Invalid EnigmV2 encrypted attachment.");
  const maximum = attachmentLimit(limits);
  const key = decodeBase64(fileKey, 32);
  let encoded: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    encoded = decryptContent(
      key,
      {
        version: 2,
        nonce: decodeBase64(encrypted.nonce, 12),
        ciphertext: decodeBase64(encrypted.ciphertext, base64Length(maximum) + 16),
      },
      context
    );
    // Mobile historically ignored whitespace in recovered base64 text.
    plaintext = decodeBase64(decodeUtf8(encoded).replace(/\s/g, ""), maximum);
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
