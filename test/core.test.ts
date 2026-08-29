import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeEnvelope,
  decodePublicIdentity,
  decodePublicKemBundle,
  decodeSealedSenderEnvelope,
  createGroupEpoch,
  decryptGroupEpoch,
  encodeEnvelope,
  encodePublicIdentity,
  encodePublicKemBundle,
  encodeSealedSenderEnvelope,
  generateIdentity,
  generateKemBundle,
  encryptGroupEpoch,
  decryptContent,
  emptyKeyTransparencyCheckpoint,
  encryptContent,
  extendKeyTransparencyCheckpoint,
  generateContentKey,
  initializeChain,
  initializeSession,
  keyTransparencyEventHash,
  observeKeyTransparencyCheckpoint,
  open,
  openSealedSender,
  publicIdentity,
  publicKemBundle,
  ratchetDecrypt,
  ratchetEncrypt,
  rekeySession,
  rotateGroupEpoch,
  seal,
  sealSender,
  sessionDecrypt,
  sessionEncrypt,
  signKeyTransparencyCheckpoint,
  utf8,
  verifyKemBundle,
  verifyKeyTransparencyCheckpoint,
  wipe,
} from '../src/index.ts';

const future = () => Date.now() + 60_000;

test('sealed sender hides its identity outside the encrypted envelope', () => {
  const alice = generateIdentity();
  const mallory = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, future());
  const context = utf8('sealed-sender:conversation:abc:message:1');
  const envelope = sealSender({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('private sender'),
    context,
  });

  assert.equal('senderIdentityKeyId' in envelope, false);
  const encodedEnvelope = encodeSealedSenderEnvelope(envelope);
  const decodedEnvelope = decodeSealedSenderEnvelope(encodedEnvelope);
  const opened = openSealedSender({
    recipientIdentity: publicIdentity(bob),
    recipient: bobKem,
    envelope: decodedEnvelope,
    context,
    expectedSenderIdentity: publicIdentity(alice),
  });
  assert.deepEqual(opened.sender.keyId, alice.keyId);
  assert.equal(new TextDecoder().decode(opened.plaintext), 'private sender');
  assert.throws(() =>
    openSealedSender({
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope,
      context,
      expectedSenderIdentity: publicIdentity(mallory),
    }),
  );
  const trailing = new Uint8Array(encodedEnvelope.length + 1);
  trailing.set(encodedEnvelope);
  assert.throws(() => decodeSealedSenderEnvelope(trailing));
  assert.throws(() =>
    openSealedSender({
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope,
      context: utf8('sealed-sender:conversation:other'),
    }),
  );
});

test('hybrid envelope round-trips and binds context', () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, future());
  const context = utf8('conversation:abc|sender-device:a|recipient-device:b|message:1');
  const envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('classified'),
    context,
  });

  const plaintext = open({
    sender: publicIdentity(alice),
    recipientIdentity: publicIdentity(bob),
    recipient: bobKem,
    envelope,
    context,
  });
  assert.equal(new TextDecoder().decode(plaintext), 'classified');
  assert.throws(() =>
    open({
      sender: publicIdentity(alice),
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope,
      context: utf8('conversation:other'),
    }),
  );
});

test('an envelope created before bundle expiry remains decryptable after delayed delivery', () => {
  const createdAt = Date.now();
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, createdAt + 1_000);
  const context = utf8('conversation:delayed-delivery');
  const envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('delayed'),
    context,
    now: createdAt,
  });

  assert.equal(
    new TextDecoder().decode(
      open({
        sender: publicIdentity(alice),
        recipientIdentity: publicIdentity(bob),
        recipient: bobKem,
        envelope,
        context,
        now: createdAt + 30 * 24 * 60 * 60 * 1_000,
      }),
    ),
    'delayed',
  );
  assert.throws(() =>
    open({
      sender: publicIdentity(alice),
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope: { ...envelope, createdAt: bobKem.expiresAt },
      context,
      now: createdAt + 30 * 24 * 60 * 60 * 1_000,
    }),
  );
});

test('tampering either signature or ciphertext fails closed', () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, future());
  const context = utf8('message:2');
  const envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('payload'),
    context,
  });
  const tampered = { ...envelope, ciphertext: new Uint8Array(envelope.ciphertext) };
  tampered.ciphertext[0] ^= 1;
  assert.throws(() =>
    open({
      sender: publicIdentity(alice),
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope: tampered,
      context,
    }),
  );
});

test('supplemental protection is explicit and mandatory when selected', () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, future());
  const supplementalSecret = new Uint8Array(32).fill(7);
  const context = utf8('message:3');
  const envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('payload'),
    context,
    supplementalSecret,
  });
  assert.throws(() =>
    open({
      sender: publicIdentity(alice),
      recipientIdentity: publicIdentity(bob),
      recipient: bobKem,
      envelope,
      context,
    }),
  );
  const plaintext = open({
    sender: publicIdentity(alice),
    recipientIdentity: publicIdentity(bob),
    recipient: bobKem,
    envelope,
    context,
    supplementalSecret,
  });
  assert.equal(new TextDecoder().decode(plaintext), 'payload');
});

test('KEM bundle authentication rejects expiry and wrong identity', () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bundle = generateKemBundle(bob, future());
  assert.equal(verifyKemBundle(publicIdentity(bob), bundle), true);
  assert.equal(verifyKemBundle(publicIdentity(alice), bundle), false);
  assert.equal(verifyKemBundle(publicIdentity(bob), bundle, bundle.expiresAt), false);
});

test('canonical public and envelope codecs round-trip and reject trailing data', () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKem = generateKemBundle(bob, future());
  const encodedIdentity = encodePublicIdentity(publicIdentity(alice));
  const encodedBundle = encodePublicKemBundle(publicKemBundle(bobKem));
  assert.deepEqual(decodePublicIdentity(encodedIdentity), publicIdentity(alice));
  assert.deepEqual(decodePublicKemBundle(encodedBundle), publicKemBundle(bobKem));

  const context = utf8('codec');
  const envelope = seal({
    sender: alice,
    recipientIdentity: publicIdentity(bob),
    recipient: publicKemBundle(bobKem),
    plaintext: utf8('wire'),
    context,
  });
  const encodedEnvelope = encodeEnvelope(envelope);
  const decodedEnvelope = decodeEnvelope(encodedEnvelope);
  assert.equal(
    new TextDecoder().decode(
      open({
        sender: publicIdentity(alice),
        recipientIdentity: publicIdentity(bob),
        recipient: bobKem,
        envelope: decodedEnvelope,
        context,
      }),
    ),
    'wire',
  );
  const withTrailingByte = new Uint8Array(encodedEnvelope.length + 1);
  withTrailingByte.set(encodedEnvelope);
  assert.throws(() => decodeEnvelope(withTrailingByte));
});

test('symmetric chain advances and rejects replay', () => {
  const root = new Uint8Array(32).fill(9);
  const context = utf8('conversation:abc|direction:a-to-b');
  const sender = initializeChain(root, context);
  const receiver = initializeChain(root, context);
  const encrypted = ratchetEncrypt(sender, utf8('hello'), context);
  const decrypted = ratchetDecrypt(receiver, encrypted.message, context);
  assert.equal(new TextDecoder().decode(decrypted.plaintext), 'hello');
  assert.equal(encrypted.next.counter, 1);
  assert.equal(decrypted.next.counter, 1);
  assert.throws(() => ratchetDecrypt(decrypted.next, encrypted.message, context));
  wipe(root, sender.chainKey, receiver.chainKey);
});

test('ratchet encryption rejects an invalid nonce without advancing caller state', () => {
  const root = new Uint8Array(32).fill(9);
  const context = utf8('conversation:invalid-nonce');
  const sender = initializeChain(root, context);
  assert.throws(
    () => ratchetEncrypt(sender, utf8('hello'), context, () => new Uint8Array(11)),
    /Ratchet nonce/,
  );
  assert.equal(sender.counter, 0);
});

test('device session supports bounded out-of-order delivery and rejects replay', () => {
  const root = new Uint8Array(32).fill(4);
  const context = utf8('conversation:session');
  let alice = initializeSession(root, context, 'initiator');
  let bob = initializeSession(root, context, 'responder');
  const first = sessionEncrypt(alice, utf8('zero'), context);
  alice = first.next;
  const second = sessionEncrypt(alice, utf8('one'), context);
  alice = second.next;
  const third = sessionEncrypt(alice, utf8('two'), context);

  const openedThird = sessionDecrypt(bob, third.message, context);
  bob = openedThird.next;
  assert.equal(new TextDecoder().decode(openedThird.plaintext), 'two');
  const openedFirst = sessionDecrypt(bob, first.message, context);
  bob = openedFirst.next;
  assert.equal(new TextDecoder().decode(openedFirst.plaintext), 'zero');
  const openedSecond = sessionDecrypt(bob, second.message, context);
  bob = openedSecond.next;
  assert.equal(new TextDecoder().decode(openedSecond.plaintext), 'one');
  assert.throws(() => sessionDecrypt(bob, first.message, context), /Replayed/);
});

test('session rekey changes the epoch and invalidates old ciphertext', () => {
  const root = new Uint8Array(32).fill(5);
  const contribution = new Uint8Array(64).fill(8);
  const context = utf8('conversation:rekey');
  let alice = initializeSession(root, context, 'initiator');
  let bob = initializeSession(root, context, 'responder');
  const old = sessionEncrypt(alice, utf8('old'), context);
  alice = rekeySession(old.next, contribution, context, 'initiator');
  bob = rekeySession(bob, contribution, context, 'responder');
  const fresh = sessionEncrypt(alice, utf8('fresh'), context);
  const opened = sessionDecrypt(bob, fresh.message, context);
  assert.equal(new TextDecoder().decode(opened.plaintext), 'fresh');
  assert.throws(() => sessionDecrypt(opened.next, old.message, context));
});

test('group membership rotation encrypts metadata and excludes new members from old epochs', () => {
  const groupId = utf8('group-identifier-0001');
  const oldMemberState = createGroupEpoch(groupId, ['alice:a', 'bob:b'], (length) => new Uint8Array(length).fill(1));
  const retainedOldState = {
    ...oldMemberState,
    groupId: new Uint8Array(oldMemberState.groupId),
    epochSecret: new Uint8Array(oldMemberState.epochSecret),
    membersHash: new Uint8Array(oldMemberState.membersHash),
  };
  const oldMetadata = encryptGroupEpoch(oldMemberState, 'metadata', utf8('{"name":"A"}'));
  const next = rotateGroupEpoch(oldMemberState, ['alice:a', 'bob:b', 'carol:c'], (length) =>
    new Uint8Array(length).fill(2),
  );
  const nextMetadata = encryptGroupEpoch(next, 'metadata', utf8('{"name":"A","photo":"cipher"}'));
  assert.equal(new TextDecoder().decode(decryptGroupEpoch(next, nextMetadata)).includes('photo'), true);
  assert.throws(() => decryptGroupEpoch(next, oldMetadata));
  assert.equal(new TextDecoder().decode(decryptGroupEpoch(retainedOldState, oldMetadata)), '{"name":"A"}');
});

test('failed group rotation preserves the current epoch secret', () => {
  const state = createGroupEpoch(utf8('group-identifier-0002'), ['alice:a']);
  const secret = new Uint8Array(state.epochSecret);
  assert.throws(() => rotateGroupEpoch(state, ['alice:a', 'alice:a']), /duplicate/);
  assert.deepEqual(state.epochSecret, secret);
});

test('public key projections do not expose mutable private identity storage', () => {
  const identity = generateIdentity();
  const identityView = publicIdentity(identity);
  const originalIdentityByte = identity.keyId[0];
  identityView.keyId[0] ^= 0xff;
  assert.equal(identity.keyId[0], originalIdentityByte);

  const bundle = generateKemBundle(identity, Date.now() + 60_000);
  const bundleView = publicKemBundle(bundle);
  const originalBundleByte = bundle.signature.mlDsa[0];
  bundleView.signature.mlDsa[0] ^= 0xff;
  assert.equal(bundle.signature.mlDsa[0], originalBundleByte);

  const originalKeyIdByte = identity.keyId[0];
  bundle.identityKeyId[0] ^= 0xff;
  assert.equal(identity.keyId[0], originalKeyIdByte);
});

test('ratchet ciphertext does not expose mutable chain state', () => {
  const root = new Uint8Array(32).fill(3);
  const context = utf8('conversation:immutable-wire');
  const sender = initializeChain(root, context);
  const encrypted = ratchetEncrypt(sender, utf8('hello'), context);
  const nextChainId = new Uint8Array(encrypted.next.chainId);
  encrypted.message.chainId[0] ^= 0xff;
  assert.deepEqual(encrypted.next.chainId, nextChainId);
});

test('one content ciphertext can be wrapped independently for multiple device sessions', () => {
  const context = utf8('conversation:content|message:1');
  const key = generateContentKey((length) => new Uint8Array(length).fill(6));
  const encrypted = encryptContent(key, utf8('one payload'), context, (length) =>
    new Uint8Array(length).fill(7),
  );
  assert.equal(new TextDecoder().decode(decryptContent(key, encrypted, context)), 'one payload');
  assert.throws(() => decryptContent(key, encrypted, utf8('conversation:other')));
  wipe(key);
});

test('key transparency proofs are contiguous, signed and gossip detects equivocation', () => {
  const signer = generateIdentity();
  const initial = emptyKeyTransparencyCheckpoint(1_000);
  const first = {
    version: 1 as const,
    sequence: 1,
    previousHash: initial.headHash,
    accountCommitment: new Uint8Array(32).fill(1),
    deviceCommitment: new Uint8Array(32).fill(2),
    identityKeyId: new Uint8Array(32).fill(3),
    action: 'ACTIVATE' as const,
    occurredAt: 1_100,
  };
  const second = {
    ...first,
    sequence: 2,
    previousHash: keyTransparencyEventHash(first),
    identityKeyId: new Uint8Array(32).fill(4),
    action: 'REVOKE' as const,
    occurredAt: 1_200,
  };
  const checkpoint = extendKeyTransparencyCheckpoint(initial, [first, second], 1_300);
  const signed = signKeyTransparencyCheckpoint(signer, checkpoint);

  assert.equal(verifyKeyTransparencyCheckpoint(publicIdentity(signer), signed), true);
  assert.equal(observeKeyTransparencyCheckpoint(initial, checkpoint), 'ADVANCED');
  assert.equal(observeKeyTransparencyCheckpoint(checkpoint, checkpoint), 'UNCHANGED');
  assert.throws(() =>
    observeKeyTransparencyCheckpoint(checkpoint, {
      ...checkpoint,
      headHash: new Uint8Array(32).fill(9),
    }),
  );
  assert.throws(() => extendKeyTransparencyCheckpoint(initial, [{ ...first, sequence: 2 }], 1_300));
});
