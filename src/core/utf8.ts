// WHATWG UTF-8 semantics, without platform TextEncoder/TextDecoder or Buffer.
// Unpaired UTF-16 surrogates encode as U+FFFD, as with TextEncoder.
export const encodeUtf8 = (value: string): Uint8Array => {
  const output = new Uint8Array(value.length * 3);
  let offset = 0;
  for (let index = 0; index < value.length; index += 1) {
    let point = value.charCodeAt(index);
    if (point >= 0xd800 && point <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        point = 0x10000 + ((point - 0xd800) << 10) + next - 0xdc00;
        index += 1;
      } else point = 0xfffd;
    } else if (point >= 0xdc00 && point <= 0xdfff) point = 0xfffd;

    if (point < 0x80) output[offset++] = point;
    else if (point < 0x800) {
      output[offset++] = 0xc0 | (point >> 6);
      output[offset++] = 0x80 | (point & 0x3f);
    } else if (point < 0x10000) {
      output[offset++] = 0xe0 | (point >> 12);
      output[offset++] = 0x80 | ((point >> 6) & 0x3f);
      output[offset++] = 0x80 | (point & 0x3f);
    } else {
      output[offset++] = 0xf0 | (point >> 18);
      output[offset++] = 0x80 | ((point >> 12) & 0x3f);
      output[offset++] = 0x80 | ((point >> 6) & 0x3f);
      output[offset++] = 0x80 | (point & 0x3f);
    }
  }
  return output.slice(0, offset);
};

// Equivalent to a fresh TextDecoder('utf-8', { fatal: true }).decode(value).
// Reject overlong encodings, surrogate code points, truncation and > U+10FFFF.
export const decodeUtf8 = (value: Uint8Array): string => {
  let output = '';
  for (let index = 0; index < value.length;) {
    const start = index;
    const lead = value[index++]!;
    let point: number;
    let remaining: number;
    let minimum: number;
    if (lead < 0x80) {
      point = lead;
      remaining = 0;
      minimum = 0;
    } else if (lead >= 0xc2 && lead <= 0xdf) {
      point = lead & 0x1f;
      remaining = 1;
      minimum = 0x80;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      point = lead & 0x0f;
      remaining = 2;
      minimum = 0x800;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      point = lead & 0x07;
      remaining = 3;
      minimum = 0x10000;
    } else throw new TypeError('Invalid UTF-8.');

    if (index + remaining > value.length) throw new TypeError('Invalid UTF-8.');
    for (let count = 0; count < remaining; count += 1) {
      const byte = value[index++]!;
      if ((byte & 0xc0) !== 0x80) throw new TypeError('Invalid UTF-8.');
      point = (point << 6) | (byte & 0x3f);
    }
    if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
      throw new TypeError('Invalid UTF-8.');
    }
    // TextDecoder's default ignoreBOM=false strips only the first U+FEFF.
    if (start !== 0 || point !== 0xfeff) output += String.fromCodePoint(point);
  }
  return output;
};
