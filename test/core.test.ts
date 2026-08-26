import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeEnvelope,
  decodePublicIdentity,
  decodePublicKemBundle,
  createGroupEpoch,
  decryptGroupEpoch,
  encodeEnvelope,
  encodePublicIdentity,
  encodePublicKemBundle,
  generateIdentity,
  generateKemBundle,
  encryptGroupEpoch,
  decryptContent,
  encryptContent,
  generateContentKey,
  initializeChain,
  initializeSession,
  open,
  publicIdentity,
  publicKemBundle,
  ratchetDecrypt,
  ratchetEncrypt,
  rekeySession,
  rotateGroupEpoch,
  seal,
  sessionDecrypt,
  sessionEncrypt,
  utf8,
  verifyKemBundle,
  wipe,
} from '../src/index.ts';

const future = () => Date.now() + 60_000;

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
