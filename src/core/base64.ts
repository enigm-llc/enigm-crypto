const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export const encodeBase64 = (value: Uint8Array): string => {
  let output = "";
  for (let offset = 0; offset < value.length; offset += 3) {
    const first = value[offset] ?? 0;
    const second = value[offset + 1] ?? 0;
    const third = value[offset + 2] ?? 0;
    const packed = (first << 16) | (second << 8) | third;
    output += BASE64_ALPHABET[(packed >>> 18) & 63];
    output += BASE64_ALPHABET[(packed >>> 12) & 63];
    output +=
      offset + 1 < value.length ? BASE64_ALPHABET[(packed >>> 6) & 63] : "=";
    output += offset + 2 < value.length ? BASE64_ALPHABET[packed & 63] : "=";
  }
  return output;
};

const checkBase64Size = (encodedLength: number, maximumBytes?: number): void => {
  if (maximumBytes === undefined) return;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new Error("Invalid base64 size limit.");
  if (encodedLength > 4 * Math.ceil(maximumBytes / 3)) throw new Error("Base64 value is too large.");
};

export const decodeBase64 = (value: string, maximumBytes?: number): Uint8Array => {
  checkBase64Size(value.length, maximumBytes);
  if (value === "") return new Uint8Array();
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error("Invalid base64 value.");
  }
  let padding = 0;
  if (value.endsWith("==")) padding = 2;
  else if (value.endsWith("=")) padding = 1;
  const length = (value.length / 4) * 3 - padding;
  if (maximumBytes !== undefined && length > maximumBytes) throw new Error("Base64 value is too large.");
  const output = new Uint8Array(length);
  let outputOffset = 0;
  for (let offset = 0; offset < value.length; offset += 4) {
    const indexes = [0, 1, 2, 3].map((position) => {
      const character = value[offset + position];
      return character === "=" ? 0 : BASE64_ALPHABET.indexOf(character ?? "");
    });
    if (indexes.some((index) => index < 0))
      throw new Error("Invalid base64 value.");
    const packed =
      ((indexes[0] ?? 0) << 18) |
      ((indexes[1] ?? 0) << 12) |
      ((indexes[2] ?? 0) << 6) |
      (indexes[3] ?? 0);
    if (outputOffset < output.length)
      output[outputOffset++] = (packed >>> 16) & 0xff;
    if (outputOffset < output.length)
      output[outputOffset++] = (packed >>> 8) & 0xff;
    if (outputOffset < output.length) output[outputOffset++] = packed & 0xff;
  }
  if (encodeBase64(output) !== value)
    throw new Error("Non-canonical base64 value.");
  return output;
};
