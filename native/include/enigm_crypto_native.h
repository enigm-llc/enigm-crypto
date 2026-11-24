// C ABI of the @enigm/crypto native primitive engine (native/src/lib.rs).
// Callers provide fixed-size output buffers. Return: 0 ok; verify: 1 valid / 0 invalid;
// negative: -1 invalid input, -2 key mismatch (seed does not derive the public key), -3 internal,
// -4 rejected (AES-GCM tag mismatch, X25519 low-order input or zero result).
#ifndef ENIGM_CRYPTO_NATIVE_H
#define ENIGM_CRYPTO_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ENIGM_MLDSA65_PUBLIC_KEY 1952
#define ENIGM_MLDSA65_SIGNATURE 3309
#define ENIGM_MLKEM768_PUBLIC_KEY 1184
#define ENIGM_MLKEM768_CIPHERTEXT 1088
#define ENIGM_SHARED_SECRET 32

uint32_t enigm_crypto_abi_version(void);
int32_t enigm_mldsa65_public_key(const uint8_t *seed, size_t seed_len, uint8_t *out);
int32_t enigm_mldsa65_sign(const uint8_t *seed, size_t seed_len, const uint8_t *public_key, size_t public_key_len,
                           const uint8_t *message, size_t message_len, const uint8_t *context, size_t context_len,
                           const uint8_t *entropy, size_t entropy_len, uint8_t *out);
int32_t enigm_mldsa65_verify(const uint8_t *public_key, size_t public_key_len, const uint8_t *message, size_t message_len,
                             const uint8_t *context, size_t context_len, const uint8_t *signature, size_t signature_len);
int32_t enigm_mlkem768_public_key(const uint8_t *seed, size_t seed_len, uint8_t *out);
int32_t enigm_mlkem768_encapsulate(const uint8_t *public_key, size_t public_key_len, const uint8_t *entropy,
                                   size_t entropy_len, uint8_t *out);
int32_t enigm_mlkem768_decapsulate(const uint8_t *seed, size_t seed_len, const uint8_t *public_key, size_t public_key_len,
                                   const uint8_t *cipher_text, size_t cipher_text_len, uint8_t *out);
int32_t enigm_ed25519_verify(const uint8_t *public_key, size_t public_key_len, const uint8_t *message, size_t message_len,
                             const uint8_t *signature, size_t signature_len);
int32_t enigm_ed25519_public_key(const uint8_t *seed, size_t seed_len, uint8_t *out);
int32_t enigm_ed25519_sign(const uint8_t *seed, size_t seed_len, const uint8_t *message, size_t message_len, uint8_t *out);
int32_t enigm_x25519_public_key(const uint8_t *secret, size_t secret_len, uint8_t *out);
int32_t enigm_x25519(const uint8_t *secret, size_t secret_len, const uint8_t *public_key, size_t public_key_len, uint8_t *out);
int32_t enigm_sha256(const uint8_t *data, size_t len, uint8_t *out);
int32_t enigm_sha512(const uint8_t *data, size_t len, uint8_t *out);
int32_t enigm_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *message, size_t message_len, uint8_t *out);
int32_t enigm_hkdf_sha512(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                          size_t info_len, uint8_t *out, size_t out_len);
// out: plaintext_len + 16 bytes (ciphertext ‖ tag).
int32_t enigm_aes256gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *aad,
                                size_t aad_len, const uint8_t *plaintext, size_t plaintext_len, uint8_t *out);
// out: ciphertext_len - 16 bytes.
int32_t enigm_aes256gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *aad,
                                size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif
