import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
  clearVerificationCache,
  cryptoBackend,
  EnigmKeyError,
  generateIdentity,
  generateKemBundle,
  open,
  publicIdentity,
  publicKemBundle,
  seal,
  sealSender,
  openSealedSender,
  signHybrid,
  validatePrivateIdentity,
  validatePrivateKemBundle,
  verifyKemBundle,
  encodeEnvelope,
  encodePublicIdentity,
  encodePublicKemBundle,
} from '../src/index.ts';
import {
  jsEngine,
  resetEngineSelectionForTesting,
  setEngineForTesting,
  type PrimitiveEngine,
} from '../src/core/engine.ts';

const context = new Uint8Array([1, 2, 3]);

const fixture = () => {
  const sender = generateIdentity();
  const recipient = generateIdentity();
  const bundle = generateKemBundle(recipient, Date.now() + 60_000);
  const envelope = seal({
    sender,
    recipientIdentity: publicIdentity(recipient),
    recipient: publicKemBundle(bundle),
    plaintext: new Uint8Array([9, 8, 7]),
    context,
  });
  return { sender, recipient, bundle, envelope };
};

const openFixture = (value: ReturnType<typeof fixture>) =>
  open({
    sender: publicIdentity(value.sender),
    recipientIdentity: publicIdentity(value.recipient),
    recipient: value.bundle,
    envelope: value.envelope,
    context,
  });

const counting = (base: PrimitiveEngine) => {
  const calls = { mlDsa65Verify: 0 };
  const wrapped: PrimitiveEngine = {
    ...base,
    mlDsa65Verify: (...args) => {
      calls.mlDsa65Verify++;
      return base.mlDsa65Verify(...args);
    },
  };
  return { calls, engine: wrapped };
};

test('Node selects the JavaScript engine', () => {
  assert.equal(cryptoBackend(), 'js');
});

test('private keys are stored as FIPS 203/204 seeds', () => {
  const identity = generateIdentity();
  const bundle = generateKemBundle(identity, Date.now() + 60_000);
  assert.equal(identity.mlDsaSeed.length, 32);
  assert.equal(bundle.mlKemSeed.length, 64);
  assert.equal('mlDsaSecretKey' in identity, false);
  assert.equal('mlKemSecretKey' in bundle, false);
  // The seed derives exactly the public key that was published and signed.
  assert.deepEqual(ml_kem768.keygen(bundle.mlKemSeed).publicKey, bundle.mlKemPublicKey);
  assert.deepEqual(jsEngine.mlDsa65PublicKey(identity.mlDsaSeed), identity.mlDsaPublicKey);
});

test('keys from the expanded format fail with KEY_FORMAT_CHANGED and are never used', () => {
  const value = fixture();
  const expandedSecret = ml_kem768.keygen(value.bundle.mlKemSeed).secretKey;
  const { mlKemSeed: _seed, ...rest } = value.bundle;
  const legacyBundle = { ...rest, mlKemSecretKey: expandedSecret } as unknown as typeof value.bundle;
  const isFormatChanged = (error: unknown) =>
    error instanceof EnigmKeyError && error.code === 'KEY_FORMAT_CHANGED';
  assert.throws(() => validatePrivateKemBundle(legacyBundle), isFormatChanged);
  assert.throws(() => openFixture({ ...value, bundle: legacyBundle }), isFormatChanged);
  // An expanded key placed in the seed field is also rejected as a format change.
  assert.throws(
    () => validatePrivateKemBundle({ ...value.bundle, mlKemSeed: expandedSecret }),
    isFormatChanged,
  );
  const { mlDsaSeed: _dsa, ...identityRest } = value.sender;
  const legacyIdentity = { ...identityRest, mlDsaSecretKey: new Uint8Array(4032) } as unknown as typeof value.sender;
  assert.throws(() => validatePrivateIdentity(legacyIdentity), isFormatChanged);
  assert.throws(() => signHybrid(legacyIdentity, context), isFormatChanged);
});

test('a seed that does not derive the stored public key fails with KEY_MISMATCH', () => {
  const value = fixture();
  const other = generateKemBundle(value.recipient, Date.now() + 60_000);
  const isMismatch = (error: unknown) => error instanceof EnigmKeyError && error.code === 'KEY_MISMATCH';
  assert.throws(() => openFixture({ ...value, bundle: { ...value.bundle, mlKemSeed: other.mlKemSeed } }), isMismatch);
  const stranger = generateIdentity();
  assert.throws(() => signHybrid({ ...value.sender, mlDsaSeed: stranger.mlDsaSeed }, context), isMismatch);
});

test('own bundle verification is cached by exact bytes; expiry and tampering are still enforced', () => {
  const { calls, engine } = counting(jsEngine);
  setEngineForTesting(engine);
  try {
    const value = fixture();
    clearVerificationCache();
    calls.mlDsa65Verify = 0;
    assert.deepEqual(openFixture(value), new Uint8Array([9, 8, 7]));
    assert.equal(calls.mlDsa65Verify, 2, 'first open verifies bundle and envelope');
    calls.mlDsa65Verify = 0;
    assert.deepEqual(openFixture(value), new Uint8Array([9, 8, 7]));
    assert.equal(calls.mlDsa65Verify, 1, 'second open only verifies the envelope signature');

    const recipient = publicIdentity(value.recipient);
    assert.equal(verifyKemBundle(recipient, value.bundle, value.bundle.expiresAt), false, 'expiry is not cached');
    const tampered = { ...value.bundle, expiresAt: value.bundle.expiresAt + 1 };
    assert.equal(verifyKemBundle(recipient, tampered), false, 'changed bytes miss the cache and fail');
    const forgedIdentity = { ...recipient, mlDsaPublicKey: generateIdentity().mlDsaPublicKey };
    assert.equal(verifyKemBundle(forgedIdentity, value.bundle), false, 'another signer key misses the cache');

    clearVerificationCache();
    calls.mlDsa65Verify = 0;
    openFixture(value);
    assert.equal(calls.mlDsa65Verify, 2, 'clearing forces a full verification');
  } finally {
    setEngineForTesting(undefined);
    clearVerificationCache();
  }
});

test('the native engine is not paired with the cache: it verifies every time', () => {
  const { calls, engine } = counting({ ...jsEngine, backend: 'native' });
  setEngineForTesting(engine);
  try {
    const value = fixture();
    calls.mlDsa65Verify = 0;
    openFixture(value);
    openFixture(value);
    assert.equal(calls.mlDsa65Verify, 4);
  } finally {
    setEngineForTesting(undefined);
  }
});

/** A binding that behaves like the JSI module: typed arrays in, ArrayBuffers out, fixed error codes. */
const bindingFrom = (base: PrimitiveEngine, mutate?: (name: string, output: Uint8Array) => void) => {
  const binding: Record<string, unknown> = { abiVersion: 2 };
  for (const [name, value] of Object.entries(base)) {
    if (typeof value !== 'function') continue;
    binding[name] = (...args: unknown[]) => {
      let result: unknown;
      try {
        result = (value as (...inner: unknown[]) => unknown)(...args);
      } catch (error) {
        if (error instanceof EnigmKeyError) throw new Error('ENIGM_NATIVE_KEY_MISMATCH');
        throw new Error('ENIGM_NATIVE_REJECTED');
      }
      if (typeof result === 'boolean') return result;
      const bytes =
        name === 'mlKem768Encapsulate'
          ? (() => {
              const { cipherText, sharedSecret } = result as { cipherText: Uint8Array; sharedSecret: Uint8Array };
              const joined = new Uint8Array(cipherText.length + sharedSecret.length);
              joined.set(cipherText);
              joined.set(sharedSecret, cipherText.length);
              return joined;
            })()
          : (result as Uint8Array).slice();
      mutate?.(name, bytes);
      return bytes.buffer;
    };
  }
  return binding;
};

const withReactNativeHost = (
  binding: unknown,
  development: boolean,
  run: (warnings: string[]) => void,
) => {
  const host = globalThis as Record<string, unknown>;
  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (message: unknown) => {
    warnings.push(String(message));
  };
  host.HermesInternal = {};
  host.__DEV__ = development;
  host.__turboModuleProxy = (name: string) => {
    if (name === 'EnigmCrypto' && binding !== undefined) host.__enigmCryptoNative = binding;
    return null;
  };
  resetEngineSelectionForTesting();
  try {
    run(warnings);
  } finally {
    console.warn = originalWarn;
    for (const key of ['HermesInternal', '__DEV__', '__turboModuleProxy', '__enigmCryptoNative']) delete host[key];
    resetEngineSelectionForTesting();
  }
};

test('React Native with a linked, self-tested binding selects the native engine transparently', () => {
  withReactNativeHost(bindingFrom(jsEngine), true, (warnings) => {
    assert.equal(cryptoBackend(), 'native');
    assert.deepEqual(warnings, []);
    const value = fixture();
    assert.deepEqual(openFixture(value), new Uint8Array([9, 8, 7]));
    const sealed = sealSender({
      sender: value.sender,
      recipientIdentity: publicIdentity(value.recipient),
      recipient: publicKemBundle(value.bundle),
      plaintext: new Uint8Array([5]),
      context,
    });
    const opened = openSealedSender({
      recipientIdentity: publicIdentity(value.recipient),
      recipient: value.bundle,
      envelope: sealed,
      context,
    });
    assert.deepEqual(opened.plaintext, new Uint8Array([5]));
    // Rejections keep the JavaScript engine's errors.
    const tampered = { ...value.envelope, ciphertext: value.envelope.ciphertext.slice() };
    tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 1;
    assert.throws(() => openFixture({ ...value, envelope: tampered }), /signature is invalid/);
    const other = generateKemBundle(value.recipient, Date.now() + 60_000);
    assert.throws(
      () => openFixture({ ...value, bundle: { ...value.bundle, mlKemSeed: other.mlKemSeed } }),
      (error: unknown) => error instanceof EnigmKeyError && error.code === 'KEY_MISMATCH',
    );
  });
});

test('React Native without the module falls back to JS silently in production', () => {
  withReactNativeHost(undefined, false, (warnings) => {
    assert.equal(cryptoBackend(), 'js');
    assert.deepEqual(warnings, []);
    assert.deepEqual(openFixture(fixture()), new Uint8Array([9, 8, 7]));
  });
});

test('React Native without the module warns once in development and explains the fix', () => {
  withReactNativeHost(undefined, true, (warnings) => {
    assert.equal(cryptoBackend(), 'js');
    cryptoBackend();
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? '', /not linked/);
    assert.match(warnings[0] ?? '', /pod install/);
  });
});

test('a binding that fails the known-answer self-test is never used', () => {
  const wrongSignature = bindingFrom(jsEngine, (name, output) => {
    if (name === 'mlDsa65Sign') output[10] = (output[10] ?? 0) ^ 1;
  });
  withReactNativeHost(wrongSignature, true, (warnings) => {
    assert.equal(cryptoBackend(), 'js');
    assert.match(warnings[0] ?? '', /self-test/);
  });
  const acceptsAnything = { ...bindingFrom(jsEngine), mlDsa65Verify: () => true };
  withReactNativeHost(acceptsAnything, false, () => {
    assert.equal(cryptoBackend(), 'js');
  });
  const acceptsForgedTags = bindingFrom(jsEngine);
  const realDecrypt = acceptsForgedTags.aes256GcmDecrypt as (...args: Uint8Array[]) => ArrayBuffer;
  acceptsForgedTags.aes256GcmDecrypt = (...args: Uint8Array[]) => {
    try {
      return realDecrypt(...args);
    } catch {
      return new ArrayBuffer(3);
    }
  };
  withReactNativeHost(acceptsForgedTags, false, () => {
    assert.equal(cryptoBackend(), 'js');
  });
  const acceptsLowOrder = bindingFrom(jsEngine);
  const realShared = acceptsLowOrder.x25519SharedSecret as (...args: Uint8Array[]) => ArrayBuffer;
  acceptsLowOrder.x25519SharedSecret = (...args: Uint8Array[]) => {
    try {
      return realShared(...args);
    } catch {
      return new ArrayBuffer(32);
    }
  };
  withReactNativeHost(acceptsLowOrder, false, () => {
    assert.equal(cryptoBackend(), 'js');
  });
  withReactNativeHost({ ...bindingFrom(jsEngine), abiVersion: 1 }, false, () => {
    assert.equal(cryptoBackend(), 'js');
  });
});

test('with fixed entropy both engines produce identical keys, envelopes and sealed-sender bytes', () => {
  const produce = () => {
    let counter = 0;
    const randomSource = (length: number) => {
      const output = new Uint8Array(length);
      for (let index = 0; index < length; index++) output[index] = (counter * 31 + index * 7 + 3) & 0xff;
      counter++;
      return output;
    };
    const sender = generateIdentity(randomSource);
    const recipient = generateIdentity(randomSource);
    const bundle = generateKemBundle(recipient, 4_000_000_000_000, randomSource);
    const envelope = seal({
      sender,
      recipientIdentity: publicIdentity(recipient),
      recipient: publicKemBundle(bundle),
      plaintext: new Uint8Array([1, 2, 3]),
      context,
      now: 1_700_000_000_000,
      randomSource,
    });
    const sealed = sealSender({
      sender,
      recipientIdentity: publicIdentity(recipient),
      recipient: publicKemBundle(bundle),
      plaintext: new Uint8Array([4]),
      context,
      now: 1_700_000_000_000,
      randomSource,
    });
    return [
      encodePublicIdentity(publicIdentity(sender)),
      encodePublicKemBundle(publicKemBundle(bundle)),
      encodeEnvelope(envelope),
      sealed.ciphertext,
      sealed.mlKemCiphertext,
    ].map((bytes) => Buffer.from(bytes).toString('hex'));
  };
  const javascript = produce();
  let native: string[] = [];
  withReactNativeHost(bindingFrom(jsEngine), false, () => {
    assert.equal(cryptoBackend(), 'native');
    native = produce();
  });
  assert.deepEqual(native, javascript);
});
