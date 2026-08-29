import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { assertLength, clone, concat, equal, utf8 } from './bytes.js';

const EMPTY_TREE_HASH = sha256(new Uint8Array());
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOG_SIGNATURE_TYPE = 0x01;
const WITNESS_SIGNATURE_TYPE = 0x04;
const MAX_SIGNATURE_LINES = 16;

export type C2spLogSigner = {
  name: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type C2spWitness = {
  name: string;
  publicKey: Uint8Array;
};

export type C2spCheckpoint = {
  origin: string;
  size: number;
  rootHash: Uint8Array;
};

export type Rfc6962Node = {
  level: number;
  index: number;
  hash: Uint8Array;
};

export type Rfc6962AppendResult = {
  treeSize: number;
  rootHash: Uint8Array;
  frontier: Array<Uint8Array | null>;
  createdNodes: Rfc6962Node[];
};

const validateSafeSize = (value: number, label: string): void => {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
};

const validateTextLine = (value: string, label: string): void => {
  const hasControlCharacter = Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
  if (!value || hasControlCharacter) throw new Error(`${label} is invalid.`);
};

const validateKeyName = (value: string): void => {
  validateTextLine(value, 'C2SP key name');
  if (/\s|\+/u.test(value)) throw new Error('C2SP key name contains a reserved character.');
};

const encodeBase64 = (value: Uint8Array): string => {
  let output = '';
  for (let offset = 0; offset < value.length; offset += 3) {
    const first = value[offset] ?? 0;
    const second = value[offset + 1] ?? 0;
    const third = value[offset + 2] ?? 0;
    const packed = (first << 16) | (second << 8) | third;
    output += BASE64_ALPHABET[(packed >>> 18) & 63];
    output += BASE64_ALPHABET[(packed >>> 12) & 63];
    output += offset + 1 < value.length ? BASE64_ALPHABET[(packed >>> 6) & 63] : '=';
    output += offset + 2 < value.length ? BASE64_ALPHABET[packed & 63] : '=';
  }
  return output;
};

const decodeBase64 = (value: string): Uint8Array => {
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error('Invalid base64 value.');
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const output = new Uint8Array((value.length / 4) * 3 - padding);
  let outputOffset = 0;
  for (let offset = 0; offset < value.length; offset += 4) {
    const indexes = [0, 1, 2, 3].map((position) => {
      const character = value[offset + position];
      return character === '=' ? 0 : BASE64_ALPHABET.indexOf(character ?? '');
    });
    if (indexes.some((index) => index < 0)) throw new Error('Invalid base64 value.');
    const packed =
      ((indexes[0] ?? 0) << 18) |
      ((indexes[1] ?? 0) << 12) |
      ((indexes[2] ?? 0) << 6) |
      (indexes[3] ?? 0);
    if (outputOffset < output.length) output[outputOffset++] = (packed >>> 16) & 0xff;
    if (outputOffset < output.length) output[outputOffset++] = (packed >>> 8) & 0xff;
    if (outputOffset < output.length) output[outputOffset++] = packed & 0xff;
  }
  if (encodeBase64(output) !== value) throw new Error('Non-canonical base64 value.');
  return output;
};

const encodeUint64 = (value: number): Uint8Array => {
  validateSafeSize(value, 'Timestamp');
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), false);
  return output;
};

const decodeUint64 = (value: Uint8Array): number => {
  assertLength(value, 8, 'Timestamp');
  const decoded = new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0, false);
  if (decoded > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Timestamp is outside the safe range.');
  return Number(decoded);
};

const keyId = (name: string, signatureType: number, publicKey: Uint8Array): Uint8Array => {
  validateKeyName(name);
  assertLength(publicKey, 32, 'C2SP public key');
  return sha256(concat(utf8(name), new Uint8Array([0x0a, signatureType]), publicKey)).slice(0, 4);
};

const largestPowerOfTwoLessThan = (value: number): number => {
  if (!Number.isSafeInteger(value) || value <= 1) {
    throw new Error('Merkle subtree must contain at least two leaves.');
  }
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
};

export const rfc6962LeafHash = (entry: Uint8Array): Uint8Array =>
  sha256(concat(new Uint8Array([0]), entry));

export const rfc6962NodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array => {
  assertLength(left, 32, 'Left Merkle hash');
  assertLength(right, 32, 'Right Merkle hash');
  return sha256(concat(new Uint8Array([1]), left, right));
};

const validateFrontier = (
  frontier: readonly (Uint8Array | null)[],
  treeSize: number,
): void => {
  validateSafeSize(treeSize, 'Merkle tree size');
  let representedSize = 0;
  for (let level = 0; level < frontier.length; level += 1) {
    const node = frontier[level];
    const expected = Math.floor(treeSize / 2 ** level) % 2 === 1;
    if (Boolean(node) !== expected) throw new Error('Merkle frontier does not match its tree size.');
    if (node) {
      assertLength(node, 32, 'Merkle frontier hash');
      representedSize += 2 ** level;
    }
  }
  if (representedSize !== treeSize) throw new Error('Merkle frontier is incomplete.');
};

export const rfc6962RootFromFrontier = (
  frontier: readonly (Uint8Array | null)[],
  treeSize: number,
): Uint8Array => {
  validateFrontier(frontier, treeSize);
  if (treeSize === 0) return clone(EMPTY_TREE_HASH);

  let root: Uint8Array | null = null;
  for (let level = 0; level < frontier.length; level += 1) {
    const node = frontier[level];
    if (node) root = root ? rfc6962NodeHash(node, root) : clone(node);
  }
  if (!root) throw new Error('Merkle frontier has no root.');
  return root;
};

export const appendRfc6962Entry = (
  frontier: readonly (Uint8Array | null)[],
  treeSize: number,
  entry: Uint8Array,
): Rfc6962AppendResult => {
  validateFrontier(frontier, treeSize);
  if (treeSize === Number.MAX_SAFE_INTEGER) throw new Error('Merkle tree is full.');

  const nextFrontier = frontier.map((node) => (node ? clone(node) : null));
  let level = 0;
  let node = rfc6962LeafHash(entry);
  const createdNodes: Rfc6962Node[] = [{ level, index: treeSize, hash: clone(node) }];

  while (Math.floor(treeSize / 2 ** level) % 2 === 1) {
    const left = nextFrontier[level];
    if (!left) throw new Error('Merkle frontier is missing a merge node.');
    node = rfc6962NodeHash(left, node);
    nextFrontier[level] = null;
    level += 1;
    createdNodes.push({ level, index: Math.floor(treeSize / 2 ** level), hash: clone(node) });
  }
  while (nextFrontier.length <= level) nextFrontier.push(null);
  nextFrontier[level] = clone(node);

  const nextSize = treeSize + 1;
  return {
    treeSize: nextSize,
    rootHash: rfc6962RootFromFrontier(nextFrontier, nextSize),
    frontier: nextFrontier,
    createdNodes,
  };
};

export const rfc6962Root = (entries: readonly Uint8Array[]): Uint8Array => {
  if (entries.length === 0) return clone(EMPTY_TREE_HASH);
  if (entries.length === 1) return rfc6962LeafHash(entries[0] ?? new Uint8Array());
  const split = largestPowerOfTwoLessThan(entries.length);
  return rfc6962NodeHash(rfc6962Root(entries.slice(0, split)), rfc6962Root(entries.slice(split)));
};

export const rfc6962InclusionProof = (
  entries: readonly Uint8Array[],
  leafIndex: number,
): Uint8Array[] => {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= entries.length) {
    throw new Error('Merkle leaf index is outside the tree.');
  }
  if (entries.length === 1) return [];
  const split = largestPowerOfTwoLessThan(entries.length);
  if (leafIndex < split) {
    return [...rfc6962InclusionProof(entries.slice(0, split), leafIndex), rfc6962Root(entries.slice(split))];
  }
  return [
    ...rfc6962InclusionProof(entries.slice(split), leafIndex - split),
    rfc6962Root(entries.slice(0, split)),
  ];
};

export const verifyRfc6962Inclusion = (
  entry: Uint8Array,
  leafIndex: number,
  treeSize: number,
  rootHash: Uint8Array,
  proof: readonly Uint8Array[],
): boolean => {
  try {
    validateSafeSize(treeSize, 'Merkle tree size');
    assertLength(rootHash, 32, 'Merkle root hash');
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
    let node = rfc6962LeafHash(entry);
    let leaf = leafIndex;
    let last = treeSize - 1;
    for (const sibling of proof) {
      assertLength(sibling, 32, 'Merkle proof hash');
      if ((leaf & 1) === 1 || leaf === last) {
        node = rfc6962NodeHash(sibling, node);
        while ((leaf & 1) === 0 && leaf !== 0) {
          leaf = Math.floor(leaf / 2);
          last = Math.floor(last / 2);
        }
      } else {
        node = rfc6962NodeHash(node, sibling);
      }
      leaf = Math.floor(leaf / 2);
      last = Math.floor(last / 2);
    }
    return last === 0 && equal(node, rootHash);
  } catch {
    return false;
  }
};

const consistencySubproof = (
  oldSize: number,
  entries: readonly Uint8Array[],
  includeOldRoot: boolean,
): Uint8Array[] => {
  if (oldSize === entries.length) return includeOldRoot ? [] : [rfc6962Root(entries)];
  const split = largestPowerOfTwoLessThan(entries.length);
  if (oldSize <= split) {
    return [
      ...consistencySubproof(oldSize, entries.slice(0, split), includeOldRoot),
      rfc6962Root(entries.slice(split)),
    ];
  }
  return [
    ...consistencySubproof(oldSize - split, entries.slice(split), false),
    rfc6962Root(entries.slice(0, split)),
  ];
};

export const rfc6962ConsistencyProof = (
  entries: readonly Uint8Array[],
  oldSize: number,
): Uint8Array[] => {
  if (!Number.isSafeInteger(oldSize) || oldSize < 0 || oldSize > entries.length) {
    throw new Error('Previous Merkle tree size is invalid.');
  }
  if (oldSize === 0 || oldSize === entries.length) return [];
  return consistencySubproof(oldSize, entries, true);
};

export const verifyRfc6962Consistency = (
  oldSize: number,
  newSize: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean => {
  try {
    validateSafeSize(oldSize, 'Previous Merkle tree size');
    validateSafeSize(newSize, 'Current Merkle tree size');
    assertLength(oldRoot, 32, 'Previous Merkle root');
    assertLength(newRoot, 32, 'Current Merkle root');
    if (oldSize > newSize) return false;
    if (oldSize === 0) return proof.length === 0;
    if (oldSize === newSize) return proof.length === 0 && equal(oldRoot, newRoot);

    let previousIndex = oldSize - 1;
    let currentIndex = newSize - 1;
    while ((previousIndex & 1) === 1) {
      previousIndex = Math.floor(previousIndex / 2);
      currentIndex = Math.floor(currentIndex / 2);
    }

    let proofIndex = 0;
    let previousHash: Uint8Array;
    let currentHash: Uint8Array;
    if (previousIndex === 0) {
      previousHash = clone(oldRoot);
      currentHash = clone(oldRoot);
    } else {
      const first = proof[proofIndex++];
      if (!first) return false;
      assertLength(first, 32, 'Merkle proof hash');
      previousHash = clone(first);
      currentHash = clone(first);
    }

    for (; proofIndex < proof.length; proofIndex += 1) {
      const sibling = proof[proofIndex];
      if (!sibling || currentIndex === 0) return false;
      assertLength(sibling, 32, 'Merkle proof hash');
      if ((previousIndex & 1) === 1 || previousIndex === currentIndex) {
        previousHash = rfc6962NodeHash(sibling, previousHash);
        currentHash = rfc6962NodeHash(sibling, currentHash);
        while ((previousIndex & 1) === 0 && previousIndex !== 0) {
          previousIndex = Math.floor(previousIndex / 2);
          currentIndex = Math.floor(currentIndex / 2);
        }
      } else {
        currentHash = rfc6962NodeHash(currentHash, sibling);
      }
      previousIndex = Math.floor(previousIndex / 2);
      currentIndex = Math.floor(currentIndex / 2);
    }

    return currentIndex === 0 && equal(previousHash, oldRoot) && equal(currentHash, newRoot);
  } catch {
    return false;
  }
};

export const c2spCheckpointText = (checkpoint: C2spCheckpoint): string => {
  validateTextLine(checkpoint.origin, 'C2SP checkpoint origin');
  validateSafeSize(checkpoint.size, 'C2SP checkpoint size');
  assertLength(checkpoint.rootHash, 32, 'C2SP checkpoint root');
  return `${checkpoint.origin}\n${checkpoint.size}\n${encodeBase64(checkpoint.rootHash)}\n`;
};

export const c2spVerifierKey = (name: string, publicKey: Uint8Array): string => {
  const identifier = keyId(name, LOG_SIGNATURE_TYPE, publicKey);
  const identifierHex = Array.from(identifier, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${name}+${identifierHex}+${encodeBase64(concat(new Uint8Array([LOG_SIGNATURE_TYPE]), publicKey))}`;
};

export const signC2spCheckpoint = (
  checkpoint: C2spCheckpoint,
  signer: C2spLogSigner,
): string => {
  validateKeyName(signer.name);
  assertLength(signer.publicKey, 32, 'C2SP signer public key');
  assertLength(signer.secretKey, 32, 'C2SP signer secret key');
  const noteText = c2spCheckpointText(checkpoint);
  const signature = ed25519.sign(utf8(noteText), signer.secretKey);
  const encoded = encodeBase64(concat(keyId(signer.name, LOG_SIGNATURE_TYPE, signer.publicKey), signature));
  return `${noteText}\n\u2014 ${signer.name} ${encoded}\n`;
};

const signatureLines = (signedNote: string, expectedText: string): string[] => {
  if (!signedNote.startsWith(`${expectedText}\n`)) throw new Error('Signed note body mismatch.');
  const suffix = signedNote.slice(expectedText.length + 1);
  if (!suffix.endsWith('\n')) throw new Error('Signed note is not newline terminated.');
  const lines = suffix.slice(0, -1).split('\n');
  if (lines.length < 1 || lines.length > MAX_SIGNATURE_LINES) {
    throw new Error('Signed note has an invalid signature count.');
  }
  return lines;
};

export const verifyC2spLogSignature = (
  signedNote: string,
  checkpoint: C2spCheckpoint,
  signer: Pick<C2spLogSigner, 'name' | 'publicKey'>,
): boolean => {
  try {
    validateKeyName(signer.name);
    const noteText = c2spCheckpointText(checkpoint);
    const expectedId = keyId(signer.name, LOG_SIGNATURE_TYPE, signer.publicKey);
    for (const line of signatureLines(signedNote, noteText)) {
      const match = /^\u2014 ([^ ]+) ([A-Za-z0-9+/]+={0,2})$/u.exec(line);
      if (!match || match[1] !== signer.name) continue;
      const encoded = decodeBase64(match[2] ?? '');
      if (encoded.length !== 68 || !equal(encoded.slice(0, 4), expectedId)) continue;
      return ed25519.verify(encoded.slice(4), utf8(noteText), signer.publicKey, { zip215: false });
    }
    return false;
  } catch {
    return false;
  }
};

export const verifyC2spWitnessCosignature = (
  signedNote: string,
  checkpoint: C2spCheckpoint,
  witness: C2spWitness,
  nowSeconds: number,
  maximumFutureSkewSeconds = 300,
): number | null => {
  try {
    validateSafeSize(nowSeconds, 'Current time');
    validateSafeSize(maximumFutureSkewSeconds, 'Maximum future skew');
    validateKeyName(witness.name);
    const noteText = c2spCheckpointText(checkpoint);
    const expectedId = keyId(witness.name, WITNESS_SIGNATURE_TYPE, witness.publicKey);
    for (const line of signatureLines(signedNote, noteText)) {
      const match = /^\u2014 ([^ ]+) ([A-Za-z0-9+/]+={0,2})$/u.exec(line);
      if (!match || match[1] !== witness.name) continue;
      const encoded = decodeBase64(match[2] ?? '');
      if (encoded.length !== 76 || !equal(encoded.slice(0, 4), expectedId)) continue;
      const timestamp = decodeUint64(encoded.slice(4, 12));
      if (timestamp === 0 || timestamp > nowSeconds + maximumFutureSkewSeconds) return null;
      const transcript = utf8(`cosignature/v1\ntime ${timestamp}\n${noteText}`);
      if (ed25519.verify(encoded.slice(12), transcript, witness.publicKey, { zip215: false })) {
        return timestamp;
      }
    }
    return null;
  } catch {
    return null;
  }
};

export const encodeC2spWitnessTimestamp = encodeUint64;
