import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeUtf8, decodeUtf8 } from '../src/utf8.js';

test('UTF-8 matches native encoding across UTF-16 boundaries and lone surrogates', () => {
  const encoder = new TextEncoder();
  for (let unit = 0; unit <= 0xffff; unit++) {
    const value = String.fromCharCode(unit);
    assert.deepEqual(encodeUtf8(value), encoder.encode(value));
  }
  for (let point = 0x10000; point <= 0x10ffff; point += 997) {
    const value = String.fromCodePoint(point);
    assert.deepEqual(encodeUtf8(value), encoder.encode(value));
    assert.equal(decodeUtf8(encodeUtf8(value)), value);
  }
  for (const value of ['\ud800A\udc00', '\ud800\ud800\udc00', '\udfff\udbff', 'español 😀 中文\0']) {
    assert.deepEqual(encodeUtf8(value), encoder.encode(value));
  }
});

test('strict decoding rejects malformed UTF-8 and preserves native BOM semantics', () => {
  const invalid = [
    [0x80], [0xbf], [0xc0, 0x80], [0xc1, 0xbf], [0xc2], [0xc2, 0x41],
    [0xe0, 0x80, 0x80], [0xe0, 0x9f, 0xbf], [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf],
    [0xe1, 0x80], [0xe1, 0x41, 0x80], [0xf0, 0x80, 0x80, 0x80],
    [0xf0, 0x8f, 0xbf, 0xbf], [0xf4, 0x90, 0x80, 0x80], [0xf5, 0x80, 0x80, 0x80],
    [0xf1, 0x80, 0x80], [0xf1, 0x80, 0x80, 0x41], [0xfe], [0xff],
    [0xef, 0xbb, 0xbf, 0xff],
  ];
  for (const bytes of invalid) assert.throws(() => decodeUtf8(Uint8Array.from(bytes)), TypeError);
  for (const value of ['', '\0', '\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff', '😀\u{10ffff}',
    '\ufeffhello', 'a\ufeff', '\ufeff\ufeff']) {
    const bytes = new TextEncoder().encode(value);
    assert.equal(decodeUtf8(bytes), new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const padded = new Uint8Array(bytes.length + 4);
    padded.set(bytes, 2);
    assert.equal(decodeUtf8(padded.subarray(2, 2 + bytes.length)), decodeUtf8(bytes));
  }
});

test('all one- and two-byte inputs agree with the native fatal decoder', () => {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  for (let value = 0; value < 0x10100; value++) {
    const bytes = value < 256 ? Uint8Array.of(value) : Uint8Array.of((value - 256) >> 8, (value - 256) & 255);
    let expected: string;
    try { expected = decoder.decode(bytes); }
    catch { assert.throws(() => decodeUtf8(bytes), TypeError); continue; }
    assert.equal(decodeUtf8(bytes), expected);
  }
});
