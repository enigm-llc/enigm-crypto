//! The native engine must reproduce the JavaScript engine on every shared vector.
//! Generate first: `node --import tsx native/vectors/generate.ts > native/target/vectors.json`.

use enigm_crypto_native as native;
use serde_json::Value;

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

fn vectors() -> Value {
    let path = std::env::var("ENIGM_NATIVE_VECTORS")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/target/vectors.json").to_string());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing vectors at {path}; run native/vectors/generate.ts"));
    serde_json::from_str(&text).expect("vectors json")
}

#[test]
fn ml_dsa_65_matches_javascript() {
    let all = vectors();
    let cases = all["mlDsa"].as_array().unwrap();
    assert!(cases.len() >= 13);
    for case in cases {
        let seed = hex(&case["seed"]);
        let public_key = hex(&case["publicKey"]);
        let message = hex(&case["message"]);
        let context = hex(&case["context"]);
        let signature = hex(&case["signature"]);
        assert_eq!(native::ml_dsa65_public_key(&seed).unwrap(), public_key);
        if case["entropy"].is_null() {
            assert_eq!(native::ml_dsa65_verify(&public_key, &message, &context, &signature), case["signatureValid"].as_bool().unwrap());
            continue;
        }
        let entropy = hex(&case["entropy"]);
        assert_eq!(native::ml_dsa65_sign(&seed, &public_key, &message, &context, &entropy).unwrap(), signature, "hedged signature");
        assert!(native::ml_dsa65_verify(&public_key, &message, &context, &signature));
        assert_eq!(native::ml_dsa65_verify(&public_key, &message, &context, &hex(&case["tampered"])), case["tamperedValid"].as_bool().unwrap());
        assert_eq!(
            native::ml_dsa65_verify(&public_key, &message, &hex(&case["otherContext"]), &signature),
            case["otherContextValid"].as_bool().unwrap()
        );
        let mut wrong = public_key.clone();
        wrong[0] ^= 1;
        assert_eq!(native::ml_dsa65_sign(&seed, &wrong, &message, &context, &entropy), Err(native::Error::KeyMismatch));
    }
}

#[test]
fn ml_kem_768_matches_javascript() {
    let all = vectors();
    for case in all["mlKem"].as_array().unwrap() {
        if !case["invalidPublicKey"].is_null() {
            let result = native::ml_kem768_encapsulate(&hex(&case["invalidPublicKey"]), &hex(&case["entropy"]));
            assert_eq!(result.is_ok(), case["accepted"].as_bool().unwrap(), "modulus check");
            continue;
        }
        let seed = hex(&case["seed"]);
        let public_key = hex(&case["publicKey"]);
        assert_eq!(native::ml_kem768_public_key(&seed).unwrap(), public_key);
        let (cipher_text, secret) = native::ml_kem768_encapsulate(&public_key, &hex(&case["entropy"])).unwrap();
        assert_eq!(cipher_text, hex(&case["cipherText"]));
        assert_eq!(*secret, hex(&case["sharedSecret"]));
        assert_eq!(*native::ml_kem768_decapsulate(&seed, &public_key, &cipher_text).unwrap(), hex(&case["sharedSecret"]));
        assert_eq!(*native::ml_kem768_decapsulate(&seed, &public_key, &hex(&case["tampered"])).unwrap(), hex(&case["rejectedSecret"]), "implicit rejection");
        let mut other_seed = seed.clone();
        other_seed[0] ^= 1;
        assert_eq!(native::ml_kem768_decapsulate(&other_seed, &public_key, &cipher_text).unwrap_err(), native::Error::KeyMismatch);
        assert_eq!(native::ml_kem768_decapsulate(&seed[..63], &public_key, &cipher_text).unwrap_err(), native::Error::Input);
    }
}

#[test]
fn ed25519_strict_matches_javascript_including_edge_cases() {
    let all = vectors();
    let cases = all["ed25519"].as_array().unwrap();
    assert!(cases.len() >= 60);
    for case in cases {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            native::ed25519_verify(&hex(&case["publicKey"]), &hex(&case["message"]), &hex(&case["signature"])),
            case["valid"].as_bool().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn c_abi_reports_fixed_codes() {
    assert_eq!(native::enigm_crypto_abi_version(), 2);
    let mut out = vec![0u8; native::ML_DSA65_PUBLIC_KEY];
    let short = [0u8; 31];
    assert_eq!(unsafe { native::enigm_mldsa65_public_key(short.as_ptr(), short.len(), out.as_mut_ptr()) }, native::ERR_INPUT);
    let seed = [7u8; 32];
    assert_eq!(unsafe { native::enigm_mldsa65_public_key(seed.as_ptr(), seed.len(), out.as_mut_ptr()) }, native::OK);
    assert_eq!(out, native::ml_dsa65_public_key(&seed).unwrap());
}

#[test]
fn sha2_hmac_hkdf_and_aes_gcm_match_javascript() {
    let all = vectors();
    for case in all["symmetric"].as_array().unwrap() {
        let data = hex(&case["data"]);
        assert_eq!(native::sha256(&data).to_vec(), hex(&case["sha256"]));
        assert_eq!(native::sha512(&data).to_vec(), hex(&case["sha512"]));
        assert_eq!(*native::hmac_sha512(&hex(&case["hmacKey"]), &data), hex(&case["hmacSha512"]));
        let length = case["hkdfLength"].as_u64().unwrap() as usize;
        assert_eq!(*native::hkdf_sha512(&data, &hex(&case["hkdfSalt"]), &hex(&case["hkdfInfo"]), length).unwrap(), hex(&case["hkdfSha512"]));
        let (key, nonce, aad) = (hex(&case["aesKey"]), hex(&case["nonce"]), hex(&case["aad"]));
        let sealed = native::aes256_gcm_encrypt(&key, &nonce, &aad, &data).unwrap();
        assert_eq!(sealed, hex(&case["sealed"]));
        assert_eq!(*native::aes256_gcm_decrypt(&key, &nonce, &aad, &sealed).unwrap(), data);
        assert_eq!(native::aes256_gcm_decrypt(&key, &nonce, &aad, &hex(&case["tampered"])).unwrap_err(), native::Error::Rejected);
    }
}

#[test]
fn x25519_matches_javascript_including_low_order_rejection() {
    let all = vectors();
    for case in all["x25519"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let secret = hex(&case["secret"]);
        if !case["derivedPublic"].is_null() {
            assert_eq!(native::x25519_public_key(&secret).unwrap().to_vec(), hex(&case["derivedPublic"]), "{label}");
            continue;
        }
        let result = native::x25519(&secret, &hex(&case["publicKey"]));
        match case["shared"].as_str() {
            Some(_) => assert_eq!(result.unwrap().to_vec(), hex(&case["shared"]), "{label}"),
            None => assert_eq!(result.unwrap_err(), native::Error::Rejected, "{label}"),
        }
    }
}

#[test]
fn ed25519_signing_matches_javascript() {
    let all = vectors();
    for case in all["ed25519Sign"].as_array().unwrap() {
        let seed = hex(&case["seed"]);
        assert_eq!(native::ed25519_public_key(&seed).unwrap().to_vec(), hex(&case["publicKey"]));
        let signature = native::ed25519_sign(&seed, &hex(&case["message"])).unwrap();
        assert_eq!(signature.to_vec(), hex(&case["signature"]));
        assert!(native::ed25519_verify(&hex(&case["publicKey"]), &hex(&case["message"]), &signature));
    }
}
