/**
 * Shared JS→native vectors. Every expected value is produced by the JavaScript engine
 * (@noble); `native/tests/vectors.rs` requires the Rust engine to return exactly the same.
 * Deterministic: inputs derive from SHA-256 counters, so the output is reproducible.
 *
 *   node --import tsx native/vectors/generate.ts > native/target/vectors.json
 */
import { gcm } from '@noble/ciphers/aes.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { jsEngine } from '../../src/core/engine.ts';

const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
let counter = 0;
const bytes = (length: number): Uint8Array => {
  const output = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 32) {
    const block = sha256(new TextEncoder().encode(`enigm-native-vectors-v1/${counter++}`));
    output.set(block.subarray(0, Math.min(32, length - offset)), offset);
  }
  return output;
};

type Vector = Record<string, string | boolean | number | null>;
const mlDsa: Vector[] = [];
const mlKem: Vector[] = [];
const ed: Vector[] = [];

// ---- ML-DSA-65 ----------------------------------------------------------------------------
const contexts = [new Uint8Array(0), new TextEncoder().encode('Enigm-PQ-V2-Identity'), bytes(255)];
for (let index = 0; index < 12; index++) {
  const seed = bytes(32);
  const publicKey = jsEngine.mlDsa65PublicKey(seed);
  const message = bytes([0, 1, 33, 1000, 70_000][index % 5] ?? 0);
  const context = contexts[index % contexts.length] ?? new Uint8Array(0);
  const entropy = bytes(32);
  const signature = jsEngine.mlDsa65Sign(seed, publicKey, message, context, entropy);
  const tampered = signature.slice();
  tampered[(index * 271) % tampered.length] ^= 1 << (index % 8);
  const otherContext = new Uint8Array([...context, 1]).subarray(0, Math.min(255, context.length + 1));
  mlDsa.push({
    seed: hex(seed),
    publicKey: hex(publicKey),
    message: hex(message),
    context: hex(context),
    entropy: hex(entropy),
    signature: hex(signature),
    tampered: hex(tampered),
    tamperedValid: jsEngine.mlDsa65Verify(publicKey, message, context, tampered),
    otherContext: hex(otherContext),
    otherContextValid: jsEngine.mlDsa65Verify(publicKey, message, otherContext, signature),
  });
}
{
  // Random bytes as a signature and as a public key: both engines must reject.
  const seed = bytes(32);
  const publicKey = jsEngine.mlDsa65PublicKey(seed);
  const message = bytes(10);
  const junkSignature = bytes(3309);
  mlDsa.push({
    seed: hex(seed),
    publicKey: hex(publicKey),
    message: hex(message),
    context: '',
    entropy: null,
    signature: hex(junkSignature),
    signatureValid: jsEngine.mlDsa65Verify(publicKey, message, new Uint8Array(0), junkSignature),
  });
}

// ---- ML-KEM-768 ---------------------------------------------------------------------------
for (let index = 0; index < 12; index++) {
  const seed = bytes(64);
  const publicKey = jsEngine.mlKem768PublicKey(seed);
  const entropy = bytes(32);
  const { cipherText, sharedSecret } = jsEngine.mlKem768Encapsulate(publicKey, entropy);
  const tampered = cipherText.slice();
  tampered[(index * 97) % tampered.length] ^= 0x80;
  // FIPS 203 implicit rejection: a modified ciphertext yields a pseudorandom secret.
  const rejected = jsEngine.mlKem768Decapsulate(seed, publicKey, tampered);
  mlKem.push({
    seed: hex(seed),
    publicKey: hex(publicKey),
    entropy: hex(entropy),
    cipherText: hex(cipherText),
    sharedSecret: hex(sharedSecret),
    tampered: hex(tampered),
    rejectedSecret: hex(rejected),
  });
}
{
  // A public key whose first coefficient is ≥ q fails the FIPS 203 modulus check.
  const publicKey = jsEngine.mlKem768PublicKey(bytes(64));
  publicKey[0] = 0xff;
  publicKey[1] = publicKey[1]! | 0x0f;
  let accepted = true;
  try {
    ml_kem768.encapsulate(publicKey, bytes(32));
  } catch {
    accepted = false;
  }
  mlKem.push({ invalidPublicKey: hex(publicKey), entropy: hex(bytes(32)), accepted });
}

// ---- Ed25519 (strict, @noble zip215: false) ------------------------------------------------
const Point = ed25519.Point;
const L = Point.Fn.ORDER;
const P = Point.Fp.ORDER;
const le = (value: bigint): Uint8Array => {
  const output = new Uint8Array(32);
  let rest = value;
  for (let index = 0; index < 32; index++) {
    output[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return output;
};
const fromLe = (value: Uint8Array): bigint => value.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const mod = (value: bigint, modulus: bigint) => ((value % modulus) + modulus) % modulus;
const challenge = (r: Uint8Array, a: Uint8Array, message: Uint8Array) =>
  mod(fromLe(sha512(new Uint8Array([...r, ...a, ...message]))), L);

// An order-8 torsion point and the full small-order set.
const T8 = Point.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
const smallOrder: InstanceType<typeof Point>[] = [];
for (let multiple = 0n; multiple < 8n; multiple++) smallOrder.push(multiple === 0n ? Point.ZERO : T8.multiply(multiple));

const push = (label: string, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) =>
  ed.push({
    label,
    publicKey: hex(publicKey),
    message: hex(message),
    signature: hex(signature),
    valid: jsEngine.ed25519Verify(publicKey, message, signature),
  });

for (let index = 0; index < 6; index++) {
  const seed = bytes(32);
  const message = bytes(index * 17);
  const publicKey = ed25519.getPublicKey(seed);
  const signature = ed25519.sign(message, seed);
  push('rfc8032 valid', publicKey, message, signature);
  const tampered = signature.slice();
  tampered[index * 5] ^= 4;
  push('tampered', publicKey, message, tampered);
  // S + ℓ: same equation, non-canonical scalar → strict rejection.
  const s = fromLe(signature.subarray(32));
  if (s + L < 1n << 256n) push('S + l (non-canonical)', publicKey, message, new Uint8Array([...signature.subarray(0, 32), ...le(s + L)]));
}

const secretScalar = mod(fromLe(bytes(32)), L);
const A = Point.BASE.multiply(secretScalar);
for (const [label, torsion] of smallOrder.map((point, index) => [`R + T*${index}`, point] as const)) {
  // R' = rB + T: the cofactored equation still holds, cofactorless would not.
  const message = bytes(12);
  const nonce = mod(fromLe(bytes(32)), L);
  const R = Point.BASE.multiply(nonce).add(torsion);
  const rBytes = R.toBytes();
  const aBytes = A.toBytes();
  const s = mod(nonce + challenge(rBytes, aBytes, message) * secretScalar, L);
  push(`torsioned ${label}`, aBytes, message, new Uint8Array([...rBytes, ...le(s)]));
}
for (const [index, torsion] of smallOrder.entries()) {
  // Small-order R (nonce 0 + torsion): allowed by @noble strict mode.
  const message = bytes(9);
  const rBytes = torsion.toBytes();
  const aBytes = A.toBytes();
  const s = mod(challenge(rBytes, aBytes, message) * secretScalar, L);
  push(`small-order R #${index}`, aBytes, message, new Uint8Array([...rBytes, ...le(s)]));
}
for (const [index, torsion] of smallOrder.entries()) {
  // Mixed-order public key A' = aB + T and small-order public keys.
  const message = bytes(7);
  const mixed = A.add(torsion);
  const aBytes = mixed.toBytes();
  const nonce = mod(fromLe(bytes(32)), L);
  const rBytes = Point.BASE.multiply(nonce).toBytes();
  const s = mod(nonce + challenge(rBytes, aBytes, message) * secretScalar, L);
  push(`mixed-order A #${index}`, aBytes, message, new Uint8Array([...rBytes, ...le(s)]));
  const smallBytes = torsion.toBytes();
  push(`small-order A #${index}`, smallBytes, message, new Uint8Array([...rBytes, ...le(s)]));
}
{
  // Non-canonical encodings: y + p for small y, and x = 0 with the sign bit set.
  const message = bytes(5);
  const valid = ed25519.sign(message, bytes(32));
  for (const y of [0n, 1n, 2n, 3n, 4n, 18n]) {
    const encoded = le(y + P);
    push(`non-canonical A y=${y}+p`, encoded, message, valid);
    push(`non-canonical R y=${y}+p`, ed25519.getPublicKey(bytes(32)), message, new Uint8Array([...encoded, ...valid.subarray(32)]));
  }
  const negativeZero = le(1n);
  negativeZero[31] = negativeZero[31]! | 0x80;
  push('A = (-0, 1)', negativeZero, message, valid);
  push('R = (-0, 1)', ed25519.getPublicKey(bytes(32)), message, new Uint8Array([...negativeZero, ...valid.subarray(32)]));
  push('not on curve A', le(2n), message, valid);
}

// ---- SHA-2 / HMAC / HKDF / AES-GCM --------------------------------------------------------
const symmetric: Vector[] = [];
for (const length of [0, 1, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 70_000]) {
  const data = bytes(length);
  const key = bytes([0, 16, 32, 64, 128, 200][length % 6] ?? 32);
  const salt = bytes(length % 3 === 0 ? 0 : 64);
  const info = bytes(length % 50);
  const outLength = [16, 32, 64, 100, 255][length % 5] ?? 32;
  const aesKey = bytes(32);
  const nonce = bytes(12);
  const aad = bytes(length % 40);
  const sealed = gcm(aesKey, nonce, aad).encrypt(data);
  const tampered = sealed.slice();
  if (tampered.length) tampered[length % tampered.length] ^= 1;
  symmetric.push({
    data: hex(data),
    sha256: hex(sha256(data)),
    sha512: hex(sha512(data)),
    hmacKey: hex(key),
    hmacSha512: hex(hmac(sha512, key, data)),
    hkdfSalt: hex(salt),
    hkdfInfo: hex(info),
    hkdfLength: outLength,
    hkdfSha512: hex(hkdf(sha512, data, salt, info, outLength)),
    aesKey: hex(aesKey),
    nonce: hex(nonce),
    aad: hex(aad),
    sealed: hex(sealed),
    tampered: hex(tampered),
  });
}

// ---- X25519 --------------------------------------------------------------------------------
const montgomery: Vector[] = [];
const x25519Case = (label: string, secret: Uint8Array, publicKey: Uint8Array) => {
  let shared: string | null = null;
  try {
    shared = hex(x25519.getSharedSecret(secret, publicKey));
  } catch {
    shared = null;
  }
  montgomery.push({ label, secret: hex(secret), publicKey: hex(publicKey), shared });
};
for (let index = 0; index < 8; index++) {
  const secret = bytes(32);
  const other = bytes(32);
  const otherPublic = x25519.getPublicKey(other);
  montgomery.push({ label: 'public', secret: hex(secret), derivedPublic: hex(x25519.getPublicKey(secret)) });
  x25519Case('shared', secret, otherPublic);
  const highBit = otherPublic.slice();
  highBit[31] |= 0x80;
  x25519Case('high bit set', secret, highBit);
}
{
  const secret = bytes(32);
  const P25519 = 2n ** 255n - 19n;
  const lowOrder = [0n, 1n, P25519 - 1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n];
  for (const u of lowOrder) {
    x25519Case(`low-order u=${u}`, secret, le(u));
    if (u + P25519 < 2n ** 255n) x25519Case(`low-order u+p`, secret, le(u + P25519));
    const high = le(u);
    high[31] |= 0x80;
    x25519Case('low-order with high bit', secret, high);
  }
  for (const u of [P25519, P25519 + 1n, P25519 + 2n, P25519 + 9n, 2n ** 255n - 1n]) x25519Case(`non-canonical u=${u - P25519}+p`, secret, le(u));
}

// ---- Ed25519 signing -----------------------------------------------------------------------
const edSign: Vector[] = [];
for (let index = 0; index < 10; index++) {
  const seed = bytes(32);
  const message = bytes(index * 37);
  edSign.push({ seed: hex(seed), publicKey: hex(ed25519.getPublicKey(seed)), message: hex(message), signature: hex(ed25519.sign(message, seed)) });
}

process.stdout.write(`${JSON.stringify({ version: 2, mlDsa, mlKem, ed25519: ed, symmetric, x25519: montgomery, ed25519Sign: edSign })}\n`);
