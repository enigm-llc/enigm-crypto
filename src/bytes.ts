const textEncoder = new TextEncoder();

export const utf8 = (value: string): Uint8Array => textEncoder.encode(value);

export const concat = (...values: readonly Uint8Array[]): Uint8Array => {
  const length = values.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
};

export const u32 = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('Value is outside the uint32 range.');
  }
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
};

export const u64 = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid uint64 value.');
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), false);
  return output;
};

export const frame = (...values: readonly Uint8Array[]): Uint8Array =>
  concat(...values.flatMap((value) => [u32(value.length), value]));

export const equal = (left: Uint8Array, right: Uint8Array): boolean => {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
};

export const assertLength = (value: Uint8Array, length: number, label: string): void => {
  if (value.length !== length) throw new Error(`${label} must contain exactly ${length} bytes.`);
};

export const clone = (value: Uint8Array): Uint8Array => new Uint8Array(value);

export const wipe = (...values: readonly Uint8Array[]): void => {
  for (const value of values) value.fill(0);
};
