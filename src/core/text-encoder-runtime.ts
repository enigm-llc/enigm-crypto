import { encodeUtf8 } from './utf8.js';

// @noble/curves 2.3.0 eagerly encodes FROST domains when importing ed25519.
// Run before those imports. Never replace a host encoder or install a decoder.
if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = class TextEncoder {
    get encoding(): string { return 'utf-8'; }

    encode(input = ''): Uint8Array<ArrayBuffer> {
      return encodeUtf8(String(input)) as Uint8Array<ArrayBuffer>;
    }

    encodeInto(source: string, destination: Uint8Array): TextEncoderEncodeIntoResult {
      source = String(source);
      let read = 0;
      let written = 0;
      for (const character of source) {
        const bytes = encodeUtf8(character);
        if (written + bytes.length > destination.length) break;
        destination.set(bytes, written);
        read += character.length;
        written += bytes.length;
      }
      return { read, written };
    }
  };
}
