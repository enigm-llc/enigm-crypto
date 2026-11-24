//! Native primitive engine for `@enigm/crypto`.
//!
//! Only the expensive primitives live here; protocol logic, transcripts and validation stay in
//! the TypeScript library, which calls these through a versioned JSI binding. Every function
//! must return exactly what the JavaScript engine (@noble) returns for the same input; the
//! shared vectors in `tests/vectors.rs` and the library's known-answer self-test enforce it.
//!
//! Private keys are seeds: ML-KEM-768 `d‖z` (64 bytes, FIPS 203) and ML-DSA-65 `ξ`
//! (32 bytes, FIPS 204). Operations that take a seed also take the stored public key and
//! return `KEY_MISMATCH` when the seed does not derive it.
//!
//! C ABI: callers pass output buffers of the documented size (no allocation crosses the boundary).
//! Return codes: `0` success, `1`/`0` for verification results, negative values are errors
//! (`-1` input, `-2` key mismatch, `-3` internal, `-4` rejected: GCM tag / X25519 low order).

#![forbid(unsafe_op_in_unsafe_fn)]

use core::slice;
use std::panic::{catch_unwind, AssertUnwindSafe};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey};
use ml_kem::array::Array;
use ml_kem::{ml_kem_768, Decapsulate, KeyExport as KemKeyExport, MlKem768};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as MacKeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub const ABI_VERSION: u32 = 2;
pub const ML_DSA65_SEED: usize = 32;
pub const ML_DSA65_PUBLIC_KEY: usize = 1952;
pub const ML_DSA65_SIGNATURE: usize = 3309;
pub const ML_KEM768_SEED: usize = 64;
pub const ML_KEM768_PUBLIC_KEY: usize = 1184;
pub const ML_KEM768_CIPHERTEXT: usize = 1088;
pub const SHARED_SECRET: usize = 32;

pub const OK: i32 = 0;
pub const VALID: i32 = 1;
pub const INVALID: i32 = 0;
pub const ERR_INPUT: i32 = -1;
pub const ERR_KEY_MISMATCH: i32 = -2;
pub const ERR_INTERNAL: i32 = -3;
pub const ERR_AUTH: i32 = -4;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Input,
    KeyMismatch,
    /// AES-GCM tag mismatch or an X25519 low-order/zero result.
    Rejected,
}

type R<T> = Result<T, Error>;

/// Constant-time byte comparison (public keys are not secret, but keep the habit).
fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn ml_dsa_signing_key(seed: &[u8]) -> R<SigningKey<MlDsa65>> {
    let seed: [u8; ML_DSA65_SEED] = seed.try_into().map_err(|_| Error::Input)?;
    let mut seed = Zeroizing::new(Array::from(seed));
    let key = SigningKey::<MlDsa65>::from_seed(&seed);
    seed.zeroize();
    Ok(key)
}

pub fn ml_dsa65_public_key(seed: &[u8]) -> R<Vec<u8>> {
    let key = ml_dsa_signing_key(seed)?;
    Ok(key.verifying_key().encode().to_vec())
}

/// FIPS 204 ML-DSA.Sign (hedged) with context string and caller-provided 32-byte `rnd`,
/// equal to @noble `ml_dsa65.sign(message, secretKey, { context, extraEntropy })`.
pub fn ml_dsa65_sign(seed: &[u8], expected_public_key: &[u8], message: &[u8], context: &[u8], entropy: &[u8]) -> R<Vec<u8>> {
    if context.len() > 255 {
        return Err(Error::Input);
    }
    let rnd: [u8; 32] = entropy.try_into().map_err(|_| Error::Input)?;
    let mut rnd = Zeroizing::new(Array::from(rnd));
    let key = ml_dsa_signing_key(seed)?;
    if !equal(&key.verifying_key().encode(), expected_public_key) {
        return Err(Error::KeyMismatch);
    }
    // M' = 0 ‖ |ctx| ‖ ctx ‖ M (FIPS 204 Algorithm 2, pure ML-DSA).
    let prefix = [0u8, context.len() as u8];
    let signature = key.expanded_key().sign_internal(&[&prefix, context, message], &rnd);
    rnd.zeroize();
    Ok(signature.encode().to_vec())
}

pub fn ml_dsa65_verify(public_key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    if context.len() > 255 {
        return false;
    }
    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
        return false;
    };
    let Ok(encoded_signature) = EncodedSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(&encoded_signature) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&encoded_key).verify_with_context(message, context, &signature)
}

fn ml_kem_decapsulation_key(seed: &[u8]) -> R<ml_kem_768::DecapsulationKey> {
    let seed: [u8; ML_KEM768_SEED] = seed.try_into().map_err(|_| Error::Input)?;
    let mut seed = Zeroizing::new(ml_kem::Seed::from(seed));
    let key = ml_kem_768::DecapsulationKey::from_seed(*seed);
    seed.zeroize();
    Ok(key)
}

pub fn ml_kem768_public_key(seed: &[u8]) -> R<Vec<u8>> {
    Ok(ml_kem_decapsulation_key(seed)?.encapsulation_key().to_bytes().to_vec())
}

/// FIPS 203 ML-KEM.Encaps_internal with caller-provided 32-byte `m`, equal to @noble
/// `ml_kem768.encapsulate(publicKey, m)`. Rejects public keys that fail the modulus check.
pub fn ml_kem768_encapsulate(public_key: &[u8], entropy: &[u8]) -> R<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let m: [u8; 32] = entropy.try_into().map_err(|_| Error::Input)?;
    let mut m = Zeroizing::new(Array::from(m));
    let encoded: [u8; ML_KEM768_PUBLIC_KEY] = public_key.try_into().map_err(|_| Error::Input)?;
    let key = ml_kem_768::EncapsulationKey::new(&Array::from(encoded)).map_err(|_| Error::Input)?;
    let (cipher_text, mut shared) = key.encapsulate_deterministic(&m);
    m.zeroize();
    let secret = Zeroizing::new(shared.to_vec());
    shared.zeroize();
    Ok((cipher_text.to_vec(), secret))
}

/// FIPS 203 ML-KEM.Decaps from the seed, after checking that it derives `expected_public_key`.
pub fn ml_kem768_decapsulate(seed: &[u8], expected_public_key: &[u8], cipher_text: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    let key = ml_kem_decapsulation_key(seed)?;
    if !equal(&key.encapsulation_key().to_bytes(), expected_public_key) {
        return Err(Error::KeyMismatch);
    }
    let encoded: [u8; ML_KEM768_CIPHERTEXT] = cipher_text.try_into().map_err(|_| Error::Input)?;
    let cipher_text = ml_kem_768::Ciphertext::from(encoded);
    let mut shared = key.decapsulate(&cipher_text);
    let secret = Zeroizing::new(shared.to_vec());
    shared.zeroize();
    Ok(secret)
}

/// Canonical point decoding as in @noble with `zip215: false` (RFC 8032 / FIPS 186-5):
/// y must be < p and x = 0 must not carry a sign bit, i.e. the encoding round-trips.
fn decode_point_strict(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    if point.compress().to_bytes() != *bytes {
        return None;
    }
    Some(point)
}

/// Ed25519 verification with exactly the @noble `ed25519.verify(sig, msg, pk, { zip215: false })`
/// rule: canonical A and R, S < ℓ, small-order A rejected (small-order R allowed), and the
/// cofactored equation [8](R + kA − SB) = 𝒪 with k = SHA-512(R ‖ A ‖ M) mod ℓ.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (<[u8; 32]>::try_from(public_key), <[u8; 64]>::try_from(signature)) else {
        return false;
    };
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("32 bytes");
    let Some(a) = decode_point_strict(&public_key) else {
        return false;
    };
    let Some(r) = decode_point_strict(&r_bytes) else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    if a.is_small_order() {
        return false;
    }
    let mut hash = Sha512::new();
    hash.update(r_bytes);
    hash.update(public_key);
    hash.update(message);
    let digest: [u8; 64] = hash.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&digest);
    // kA − SB computed as kA + (−S)B in variable time (all inputs are public).
    let k_a_minus_s_b = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &a, &(-s));
    (r + k_a_minus_s_b).mul_by_cofactor().is_identity_point()
}

// ---- SHA-2, HMAC, HKDF, AES-GCM ------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = <Hmac<Sha512> as MacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// RFC 5869 HKDF-SHA512 (empty salt = HashLen zeros, as in @noble).
pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> R<Zeroizing<Vec<u8>>> {
    if length == 0 || length > 255 * 64 {
        return Err(Error::Input);
    }
    let mut output = Zeroizing::new(vec![0u8; length]);
    Hkdf::<Sha512>::new(Some(salt), ikm).expand(info, &mut output).map_err(|_| Error::Input)?;
    Ok(output)
}

fn aes(key: &[u8], nonce: &[u8]) -> R<(Aes256Gcm, Nonce<aes_gcm::aes::cipher::consts::U12>)> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(Error::Input);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Input)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| Error::Input)?;
    Ok((cipher, nonce))
}

/// AES-256-GCM with a 96-bit nonce and 128-bit tag: ciphertext ‖ tag.
pub fn aes256_gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> R<Vec<u8>> {
    let (cipher, nonce) = aes(key, nonce)?;
    cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| Error::Input)
}

pub fn aes256_gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    let (cipher, nonce) = aes(key, nonce)?;
    if ciphertext.len() < 16 {
        return Err(Error::Rejected);
    }
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad }).map(Zeroizing::new).map_err(|_| Error::Rejected)
}

// ---- X25519 and Ed25519 signing ----------------------------------------------------------

/// u-coordinates whose order divides the cofactor, as reduced canonical encodings. @noble rejects
/// them before the ladder (after reducing u mod p), so the native engine does the same.
const LOW_ORDER_U: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    },
    // p − 1
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
    [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
];

/// RFC 7748 decodeU: clear bit 255, then reduce modulo p = 2^255 − 19.
fn canonical_u(bytes: &[u8; 32]) -> [u8; 32] {
    let mut u = *bytes;
    u[31] &= 0x7f;
    // u ≥ p only for 2^255 − 19 ≤ u < 2^255: top bytes all 0xff/0x7f and low byte ≥ 0xed.
    let ge_p = u[31] == 0x7f && u[1..31].iter().all(|byte| *byte == 0xff) && u[0] >= 0xed;
    if ge_p {
        u[0] -= 0xed;
        for byte in u.iter_mut().skip(1) {
            *byte = 0;
        }
    }
    u
}

pub fn x25519_public_key(secret: &[u8]) -> R<[u8; 32]> {
    let secret: [u8; 32] = secret.try_into().map_err(|_| Error::Input)?;
    let mut secret = Zeroizing::new(secret);
    let public = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
    secret.zeroize();
    if public == [0u8; 32] {
        return Err(Error::Rejected);
    }
    Ok(public)
}

/// X25519 with @noble's rule: low-order u (after decodeU) and a zero result are rejected.
pub fn x25519(secret: &[u8], public_key: &[u8]) -> R<Zeroizing<[u8; 32]>> {
    let secret: [u8; 32] = secret.try_into().map_err(|_| Error::Input)?;
    let mut secret = Zeroizing::new(secret);
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| Error::Input)?;
    let u = canonical_u(&public_key);
    if LOW_ORDER_U.iter().any(|low| *low == u) {
        return Err(Error::Rejected);
    }
    let shared = Zeroizing::new(MontgomeryPoint(u).mul_clamped(*secret).to_bytes());
    secret.zeroize();
    if *shared == [0u8; 32] {
        return Err(Error::Rejected);
    }
    Ok(shared)
}

struct Ed25519Expanded {
    scalar: Scalar,
    prefix: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

fn ed25519_expand(seed: &[u8]) -> R<Ed25519Expanded> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::Input)?;
    let mut digest = Zeroizing::new(sha512(&seed));
    let mut clamped = Zeroizing::new([0u8; 32]);
    clamped.copy_from_slice(&digest[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(*clamped);
    let mut prefix = Zeroizing::new([0u8; 32]);
    prefix.copy_from_slice(&digest[32..]);
    digest.zeroize();
    let public_key = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
    Ok(Ed25519Expanded { scalar, prefix, public_key })
}

pub fn ed25519_public_key(seed: &[u8]) -> R<[u8; 32]> {
    Ok(ed25519_expand(seed)?.public_key)
}

/// RFC 8032 deterministic Ed25519 (pure), equal to @noble `ed25519.sign(message, seed)`.
pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> R<[u8; 64]> {
    let mut expanded = ed25519_expand(seed)?;
    let mut nonce_hash = Sha512::new();
    nonce_hash.update(*expanded.prefix);
    nonce_hash.update(message);
    let mut nonce_digest: [u8; 64] = nonce_hash.finalize().into();
    let mut nonce = Scalar::from_bytes_mod_order_wide(&nonce_digest);
    nonce_digest.zeroize();
    let r = EdwardsPoint::mul_base(&nonce).compress().to_bytes();
    let mut challenge = Sha512::new();
    challenge.update(r);
    challenge.update(expanded.public_key);
    challenge.update(message);
    let k_digest: [u8; 64] = challenge.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&k_digest);
    let s = nonce + k * expanded.scalar;
    nonce.zeroize();
    expanded.scalar.zeroize();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r);
    signature[32..].copy_from_slice(s.as_bytes());
    Ok(signature)
}

trait IdentityPoint {
    fn is_identity_point(&self) -> bool;
}

impl IdentityPoint for EdwardsPoint {
    fn is_identity_point(&self) -> bool {
        self.compress() == EdwardsPoint::default().compress()
    }
}

// ---- C ABI ---------------------------------------------------------------------------------

/// # Safety
/// `ptr` must be valid for `len` bytes (or `len == 0`).
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        // SAFETY: guaranteed by the caller contract above.
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// # Safety
/// `ptr` must be valid for writes of `len` bytes.
unsafe fn write(ptr: *mut u8, len: usize, value: &[u8]) -> i32 {
    if ptr.is_null() || value.len() != len {
        return ERR_INTERNAL;
    }
    // SAFETY: guaranteed by the caller contract above; lengths are equal.
    unsafe { slice::from_raw_parts_mut(ptr, len) }.copy_from_slice(value);
    OK
}

fn code(error: Error) -> i32 {
    match error {
        Error::Input => ERR_INPUT,
        Error::KeyMismatch => ERR_KEY_MISMATCH,
        Error::Rejected => ERR_AUTH,
    }
}

/// Never unwind across the FFI boundary.
fn guarded(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(ERR_INTERNAL)
}

#[no_mangle]
pub extern "C" fn enigm_crypto_abi_version() -> u32 {
    ABI_VERSION
}

/// # Safety
/// `seed` 32 bytes; `out` writable for 1952 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_mldsa65_public_key(seed: *const u8, seed_len: usize, out: *mut u8) -> i32 {
    guarded(|| match ml_dsa65_public_key(unsafe { input(seed, seed_len) }) {
        Ok(value) => unsafe { write(out, ML_DSA65_PUBLIC_KEY, &value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 3309 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn enigm_mldsa65_sign(
    seed: *const u8,
    seed_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    context: *const u8,
    context_len: usize,
    entropy: *const u8,
    entropy_len: usize,
    out: *mut u8,
) -> i32 {
    guarded(|| {
        let result = unsafe {
            ml_dsa65_sign(
                input(seed, seed_len),
                input(public_key, public_key_len),
                input(message, message_len),
                input(context, context_len),
                input(entropy, entropy_len),
            )
        };
        match result {
            Ok(value) => unsafe { write(out, ML_DSA65_SIGNATURE, &value) },
            Err(error) => code(error),
        }
    })
}

/// # Safety
/// Each pointer valid for its length.
#[no_mangle]
pub unsafe extern "C" fn enigm_mldsa65_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    context: *const u8,
    context_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    guarded(|| {
        let valid = unsafe {
            ml_dsa65_verify(
                input(public_key, public_key_len),
                input(message, message_len),
                input(context, context_len),
                input(signature, signature_len),
            )
        };
        if valid {
            VALID
        } else {
            INVALID
        }
    })
}

/// # Safety
/// `seed` 64 bytes; `out` writable for 1184 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_mlkem768_public_key(seed: *const u8, seed_len: usize, out: *mut u8) -> i32 {
    guarded(|| match ml_kem768_public_key(unsafe { input(seed, seed_len) }) {
        Ok(value) => unsafe { write(out, ML_KEM768_PUBLIC_KEY, &value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 1088 + 32 bytes (ciphertext ‖ secret).
#[no_mangle]
pub unsafe extern "C" fn enigm_mlkem768_encapsulate(
    public_key: *const u8,
    public_key_len: usize,
    entropy: *const u8,
    entropy_len: usize,
    out: *mut u8,
) -> i32 {
    guarded(|| match ml_kem768_encapsulate(unsafe { input(public_key, public_key_len) }, unsafe { input(entropy, entropy_len) }) {
        Ok((cipher_text, secret)) => {
            let mut joined = Zeroizing::new(Vec::with_capacity(ML_KEM768_CIPHERTEXT + SHARED_SECRET));
            joined.extend_from_slice(&cipher_text);
            joined.extend_from_slice(&secret);
            unsafe { write(out, ML_KEM768_CIPHERTEXT + SHARED_SECRET, &joined) }
        }
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_mlkem768_decapsulate(
    seed: *const u8,
    seed_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    cipher_text: *const u8,
    cipher_text_len: usize,
    out: *mut u8,
) -> i32 {
    guarded(|| {
        let result = unsafe {
            ml_kem768_decapsulate(input(seed, seed_len), input(public_key, public_key_len), input(cipher_text, cipher_text_len))
        };
        match result {
            Ok(secret) => unsafe { write(out, SHARED_SECRET, &secret) },
            Err(error) => code(error),
        }
    })
}

/// # Safety
/// Each pointer valid for its length.
#[no_mangle]
pub unsafe extern "C" fn enigm_ed25519_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    guarded(|| {
        let valid = unsafe {
            ed25519_verify(input(public_key, public_key_len), input(message, message_len), input(signature, signature_len))
        };
        if valid {
            VALID
        } else {
            INVALID
        }
    })
}


/// # Safety
/// `data` valid for `len`; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_sha256(data: *const u8, len: usize, out: *mut u8) -> i32 {
    guarded(|| unsafe { write(out, 32, &sha256(input(data, len))) })
}

/// # Safety
/// `data` valid for `len`; `out` writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_sha512(data: *const u8, len: usize, out: *mut u8) -> i32 {
    guarded(|| unsafe { write(out, 64, &sha512(input(data, len))) })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_hmac_sha512(key: *const u8, key_len: usize, message: *const u8, message_len: usize, out: *mut u8) -> i32 {
    guarded(|| unsafe { write(out, 64, &hmac_sha512(input(key, key_len), input(message, message_len))) })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_hkdf_sha512(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    guarded(|| match hkdf_sha512(unsafe { input(ikm, ikm_len) }, unsafe { input(salt, salt_len) }, unsafe { input(info, info_len) }, out_len) {
        Ok(value) => unsafe { write(out, out_len, &value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for `plaintext_len + 16` bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn enigm_aes256gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
) -> i32 {
    guarded(|| {
        let result = unsafe { aes256_gcm_encrypt(input(key, key_len), input(nonce, nonce_len), input(aad, aad_len), input(plaintext, plaintext_len)) };
        match result {
            Ok(value) => unsafe { write(out, plaintext_len + 16, &value) },
            Err(error) => code(error),
        }
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for `ciphertext_len − 16` bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn enigm_aes256gcm_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut u8,
) -> i32 {
    guarded(|| {
        if ciphertext_len < 16 {
            return ERR_AUTH;
        }
        let result = unsafe { aes256_gcm_decrypt(input(key, key_len), input(nonce, nonce_len), input(aad, aad_len), input(ciphertext, ciphertext_len)) };
        match result {
            Ok(value) => unsafe { write(out, ciphertext_len - 16, &value) },
            Err(error) => code(error),
        }
    })
}

/// # Safety
/// `secret` 32 bytes; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_x25519_public_key(secret: *const u8, secret_len: usize, out: *mut u8) -> i32 {
    guarded(|| match x25519_public_key(unsafe { input(secret, secret_len) }) {
        Ok(value) => unsafe { write(out, 32, &value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_x25519(secret: *const u8, secret_len: usize, public_key: *const u8, public_key_len: usize, out: *mut u8) -> i32 {
    guarded(|| match x25519(unsafe { input(secret, secret_len) }, unsafe { input(public_key, public_key_len) }) {
        Ok(value) => unsafe { write(out, 32, &*value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// `seed` 32 bytes; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_ed25519_public_key(seed: *const u8, seed_len: usize, out: *mut u8) -> i32 {
    guarded(|| match ed25519_public_key(unsafe { input(seed, seed_len) }) {
        Ok(value) => unsafe { write(out, 32, &value) },
        Err(error) => code(error),
    })
}

/// # Safety
/// Each pointer valid for its length; `out` writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn enigm_ed25519_sign(seed: *const u8, seed_len: usize, message: *const u8, message_len: usize, out: *mut u8) -> i32 {
    guarded(|| match ed25519_sign(unsafe { input(seed, seed_len) }, unsafe { input(message, message_len) }) {
        Ok(value) => unsafe { write(out, 64, &value) },
        Err(error) => code(error),
    })
}

#[allow(dead_code)]
fn _assert_kem_types(_: MlKem768) {}
