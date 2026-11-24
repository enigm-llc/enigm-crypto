// React Native module that installs the @enigm/crypto native primitive engine as a
// synchronous JSI binding (`globalThis.__enigmCryptoNative`, ABI 2). The library requests this
// TurboModule itself and falls back to its JavaScript engine if it is absent or fails the
// known-answer self-test; apps never call it directly.
//
// Inputs are Uint8Array views read in place (no copies, no strings, so secrets stay in
// wipeable buffers). Outputs are fresh ArrayBuffers whose memory is zeroed when collected.

#import <React/RCTBridgeModule.h>
#import <ReactCommon/RCTTurboModule.h>
#import <ReactCommon/RCTTurboModuleWithJSIBindings.h>
#include <jsi/jsi.h>

#include <cstring>
#include <functional>
#include <memory>
#include <string>

#include "enigm_crypto_native.h"

using namespace facebook;

namespace {

class ZeroizingBuffer final : public jsi::MutableBuffer {
 public:
  explicit ZeroizingBuffer(size_t size) : data_(new uint8_t[size]()), size_(size) {}
  ~ZeroizingBuffer() override {
    volatile uint8_t *bytes = data_;
    for (size_t index = 0; index < size_; index++) bytes[index] = 0;
    delete[] data_;
  }
  size_t size() const override { return size_; }
  uint8_t *data() override { return data_; }

 private:
  uint8_t *data_;
  size_t size_;
};

struct Bytes {
  const uint8_t *data;
  size_t size;
};

[[noreturn]] void fail(jsi::Runtime &rt, int32_t code) {
  throw jsi::JSError(rt, code == -2 ? "ENIGM_NATIVE_KEY_MISMATCH" : code == -4 ? "ENIGM_NATIVE_REJECTED" : "ENIGM_NATIVE_INPUT");
}

constexpr size_t kMaxVariableOutput = 64 * 1024 * 1024;

Bytes bytes(jsi::Runtime &rt, const jsi::Value &value) {
  if (!value.isObject()) fail(rt, -1);
  jsi::Object view = value.getObject(rt);
  jsi::Value bufferValue = view.getProperty(rt, "buffer");
  if (!bufferValue.isObject()) fail(rt, -1);
  jsi::Object bufferObject = bufferValue.getObject(rt);
  if (!bufferObject.isArrayBuffer(rt)) fail(rt, -1);
  jsi::ArrayBuffer buffer = bufferObject.getArrayBuffer(rt);
  jsi::Value offsetValue = view.getProperty(rt, "byteOffset");
  jsi::Value lengthValue = view.getProperty(rt, "byteLength");
  if (!offsetValue.isNumber() || !lengthValue.isNumber()) fail(rt, -1);
  const double offset = offsetValue.getNumber();
  const double length = lengthValue.getNumber();
  const size_t capacity = buffer.size(rt);
  if (offset < 0 || length < 0 || offset + length > static_cast<double>(capacity)) fail(rt, -1);
  return {buffer.data(rt) + static_cast<size_t>(offset), static_cast<size_t>(length)};
}

void expectArguments(jsi::Runtime &rt, size_t count, size_t expected) {
  if (count != expected) fail(rt, -1);
}

jsi::Value output(jsi::Runtime &rt, size_t size, const std::function<int32_t(uint8_t *)> &operation) {
  auto buffer = std::make_shared<ZeroizingBuffer>(size);
  const int32_t code = operation(buffer->data());
  if (code != 0) fail(rt, code);
  return jsi::ArrayBuffer(rt, buffer);
}

void define(jsi::Runtime &rt, jsi::Object &target, const char *name, unsigned int arity, jsi::HostFunctionType body) {
  target.setProperty(rt, name, jsi::Function::createFromHostFunction(rt, jsi::PropNameID::forAscii(rt, name), arity, std::move(body)));
}

void install(jsi::Runtime &rt) {
  if (enigm_crypto_abi_version() != 2) return;
  jsi::Object binding(rt);
  binding.setProperty(rt, "abiVersion", 2);

  define(rt, binding, "mlDsa65PublicKey", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes seed = bytes(rt, args[0]);
    return output(rt, ENIGM_MLDSA65_PUBLIC_KEY, [&](uint8_t *out) { return enigm_mldsa65_public_key(seed.data, seed.size, out); });
  });
  define(rt, binding, "mlDsa65Sign", 5, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 5);
    Bytes seed = bytes(rt, args[0]), publicKey = bytes(rt, args[1]), message = bytes(rt, args[2]),
          context = bytes(rt, args[3]), entropy = bytes(rt, args[4]);
    return output(rt, ENIGM_MLDSA65_SIGNATURE, [&](uint8_t *out) {
      return enigm_mldsa65_sign(seed.data, seed.size, publicKey.data, publicKey.size, message.data, message.size,
                                context.data, context.size, entropy.data, entropy.size, out);
    });
  });
  define(rt, binding, "mlDsa65Verify", 4, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 4);
    Bytes publicKey = bytes(rt, args[0]), message = bytes(rt, args[1]), context = bytes(rt, args[2]),
          signature = bytes(rt, args[3]);
    const int32_t code = enigm_mldsa65_verify(publicKey.data, publicKey.size, message.data, message.size, context.data,
                                              context.size, signature.data, signature.size);
    if (code < 0) fail(rt, code);
    return jsi::Value(code == 1);
  });
  define(rt, binding, "mlKem768PublicKey", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes seed = bytes(rt, args[0]);
    return output(rt, ENIGM_MLKEM768_PUBLIC_KEY, [&](uint8_t *out) { return enigm_mlkem768_public_key(seed.data, seed.size, out); });
  });
  define(rt, binding, "mlKem768Encapsulate", 2, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 2);
    Bytes publicKey = bytes(rt, args[0]), entropy = bytes(rt, args[1]);
    return output(rt, ENIGM_MLKEM768_CIPHERTEXT + ENIGM_SHARED_SECRET, [&](uint8_t *out) {
      return enigm_mlkem768_encapsulate(publicKey.data, publicKey.size, entropy.data, entropy.size, out);
    });
  });
  define(rt, binding, "mlKem768Decapsulate", 3, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 3);
    Bytes seed = bytes(rt, args[0]), publicKey = bytes(rt, args[1]), cipherText = bytes(rt, args[2]);
    return output(rt, ENIGM_SHARED_SECRET, [&](uint8_t *out) {
      return enigm_mlkem768_decapsulate(seed.data, seed.size, publicKey.data, publicKey.size, cipherText.data,
                                        cipherText.size, out);
    });
  });
  define(rt, binding, "ed25519Verify", 3, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 3);
    Bytes publicKey = bytes(rt, args[0]), message = bytes(rt, args[1]), signature = bytes(rt, args[2]);
    const int32_t code = enigm_ed25519_verify(publicKey.data, publicKey.size, message.data, message.size, signature.data,
                                              signature.size);
    if (code < 0) fail(rt, code);
    return jsi::Value(code == 1);
  });

  define(rt, binding, "ed25519PublicKey", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes seed = bytes(rt, args[0]);
    return output(rt, 32, [&](uint8_t *out) { return enigm_ed25519_public_key(seed.data, seed.size, out); });
  });
  define(rt, binding, "ed25519Sign", 2, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 2);
    Bytes seed = bytes(rt, args[0]), message = bytes(rt, args[1]);
    return output(rt, 64, [&](uint8_t *out) { return enigm_ed25519_sign(seed.data, seed.size, message.data, message.size, out); });
  });
  define(rt, binding, "x25519PublicKey", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes secret = bytes(rt, args[0]);
    return output(rt, 32, [&](uint8_t *out) { return enigm_x25519_public_key(secret.data, secret.size, out); });
  });
  define(rt, binding, "x25519SharedSecret", 2, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 2);
    Bytes secret = bytes(rt, args[0]), publicKey = bytes(rt, args[1]);
    return output(rt, 32, [&](uint8_t *out) {
      return enigm_x25519(secret.data, secret.size, publicKey.data, publicKey.size, out);
    });
  });
  define(rt, binding, "sha256", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes data = bytes(rt, args[0]);
    return output(rt, 32, [&](uint8_t *out) { return enigm_sha256(data.data, data.size, out); });
  });
  define(rt, binding, "sha512", 1, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 1);
    Bytes data = bytes(rt, args[0]);
    return output(rt, 64, [&](uint8_t *out) { return enigm_sha512(data.data, data.size, out); });
  });
  define(rt, binding, "hmacSha512", 2, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 2);
    Bytes key = bytes(rt, args[0]), message = bytes(rt, args[1]);
    return output(rt, 64, [&](uint8_t *out) { return enigm_hmac_sha512(key.data, key.size, message.data, message.size, out); });
  });
  define(rt, binding, "hkdfSha512", 4, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 4);
    Bytes ikm = bytes(rt, args[0]), salt = bytes(rt, args[1]), info = bytes(rt, args[2]);
    if (!args[3].isNumber()) fail(rt, -1);
    const double length = args[3].getNumber();
    if (!(length >= 1 && length <= 255 * 64) || length != static_cast<double>(static_cast<size_t>(length))) fail(rt, -1);
    const size_t size = static_cast<size_t>(length);
    return output(rt, size, [&](uint8_t *out) {
      return enigm_hkdf_sha512(ikm.data, ikm.size, salt.data, salt.size, info.data, info.size, out, size);
    });
  });
  define(rt, binding, "aes256GcmEncrypt", 4, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 4);
    Bytes key = bytes(rt, args[0]), nonce = bytes(rt, args[1]), aad = bytes(rt, args[2]), plaintext = bytes(rt, args[3]);
    if (plaintext.size > kMaxVariableOutput) fail(rt, -1);
    return output(rt, plaintext.size + 16, [&](uint8_t *out) {
      return enigm_aes256gcm_encrypt(key.data, key.size, nonce.data, nonce.size, aad.data, aad.size, plaintext.data,
                                     plaintext.size, out);
    });
  });
  define(rt, binding, "aes256GcmDecrypt", 4, [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) {
    expectArguments(rt, count, 4);
    Bytes key = bytes(rt, args[0]), nonce = bytes(rt, args[1]), aad = bytes(rt, args[2]), ciphertext = bytes(rt, args[3]);
    if (ciphertext.size < 16) fail(rt, -4);
    if (ciphertext.size > kMaxVariableOutput + 16) fail(rt, -1);
    return output(rt, ciphertext.size - 16, [&](uint8_t *out) {
      return enigm_aes256gcm_decrypt(key.data, key.size, nonce.data, nonce.size, aad.data, aad.size, ciphertext.data,
                                     ciphertext.size, out);
    });
  });

  // Frozen and non-writable so later code cannot swap functions behind the self-test.
  jsi::Object objectConstructor = rt.global().getPropertyAsObject(rt, "Object");
  objectConstructor.getPropertyAsFunction(rt, "freeze").call(rt, binding);
  if (!rt.global().getProperty(rt, "__enigmCryptoNative").isUndefined()) return;
  jsi::Object descriptor(rt);
  descriptor.setProperty(rt, "value", std::move(binding));
  descriptor.setProperty(rt, "writable", false);
  descriptor.setProperty(rt, "configurable", false);
  descriptor.setProperty(rt, "enumerable", false);
  objectConstructor.getPropertyAsFunction(rt, "defineProperty")
      .call(rt, rt.global(), jsi::String::createFromAscii(rt, "__enigmCryptoNative"), descriptor);
}

}  // namespace

@interface EnigmCrypto : NSObject <RCTBridgeModule, RCTTurboModule, RCTTurboModuleWithJSIBindings>
@end

@implementation EnigmCrypto

RCT_EXPORT_MODULE(EnigmCrypto)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::ObjCTurboModule>(params);
}

- (void)installJSIBindingsWithRuntime:(facebook::jsi::Runtime &)runtime
                          callInvoker:(const std::shared_ptr<facebook::react::CallInvoker> &)callInvoker
{
  install(runtime);
}

@end
