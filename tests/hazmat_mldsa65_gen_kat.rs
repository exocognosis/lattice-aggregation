#![cfg(feature = "hazmat-real-mldsa")]

use std::{env, fs, path::PathBuf};

use dytallix_pq_threshold::{
    mldsa65::{
        derive_mldsa65_expanded_secret_key_from_seed, derive_mldsa65_public_key_from_seed,
        sign_mldsa65_external_pure_deterministic_from_expanded_secret_key,
        sign_mldsa65_internal_deterministic_from_expanded_secret_key, MLDSA65_KEYGEN_SEED_BYTES,
    },
    MLDSA65_PUBLICKEY_BYTES, MLDSA65_SECRETKEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};
use serde_json::Value;

#[derive(Debug, Eq, PartialEq)]
struct KeyGenKat {
    tc_id: u64,
    seed: Vec<u8>,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct SigGenKat {
    tc_id: u64,
    mode: SigGenMode,
    message: Vec<u8>,
    context: Vec<u8>,
    secret_key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigGenMode {
    ExternalPure,
    InternalMessage,
}

#[test]
fn hazmat_acvp_keygen_loader_extracts_mldsa65_vectors() {
    let sample = sample_keygen();
    let vectors = load_acvp_keygen_vectors(&sample).unwrap();

    assert_eq!(vectors.len(), 1);
    assert_eq!(vectors[0].tc_id, 11);
    assert_eq!(vectors[0].seed, vec![0xAA; MLDSA65_KEYGEN_SEED_BYTES]);
    assert_eq!(vectors[0].public_key, vec![0xBB; MLDSA65_PUBLICKEY_BYTES]);
    assert_eq!(vectors[0].secret_key, vec![0xCC; MLDSA65_SECRETKEY_BYTES]);
}

#[test]
fn hazmat_acvp_siggen_loader_extracts_external_and_internal_vectors() {
    let sample = sample_siggen();
    let vectors = load_acvp_siggen_vectors(&sample).unwrap();

    assert_eq!(vectors.len(), 2);
    assert_eq!(vectors[0].tc_id, 21);
    assert_eq!(vectors[0].mode, SigGenMode::ExternalPure);
    assert_eq!(vectors[0].message, vec![0xAB, 0xCD]);
    assert_eq!(vectors[0].context, vec![0x01]);
    assert_eq!(vectors[1].tc_id, 31);
    assert_eq!(vectors[1].mode, SigGenMode::InternalMessage);
    assert_eq!(vectors[1].message, vec![0xCA, 0xFE]);
    assert!(vectors[1].context.is_empty());
}

#[test]
fn hazmat_acvp_generation_loaders_reject_bad_hex() {
    assert_eq!(
        load_acvp_keygen_vectors(SAMPLE_KEYGEN_BAD_HEX),
        Err("invalid hex character")
    );
    assert_eq!(
        load_acvp_siggen_vectors(SAMPLE_SIGGEN_BAD_HEX),
        Err("invalid hex character")
    );
}

#[test]
fn official_mldsa65_keygen_kats_pass_when_configured() {
    let Some(path) = env::var_os("DYTALLIX_MLDSA65_KEYGEN_KAT").map(PathBuf::from) else {
        return;
    };
    let json = fs::read_to_string(&path).expect("read ML-DSA-65 keyGen KAT fixture");
    let vectors = load_acvp_keygen_vectors(&json).expect("parse ML-DSA-65 keyGen KAT fixture");

    for vector in vectors {
        if vector.seed.len() != MLDSA65_KEYGEN_SEED_BYTES
            || vector.public_key.len() != MLDSA65_PUBLICKEY_BYTES
            || vector.secret_key.len() != MLDSA65_SECRETKEY_BYTES
        {
            continue;
        }

        let seed: [u8; MLDSA65_KEYGEN_SEED_BYTES] =
            vector.seed.try_into().expect("seed length checked");
        let public_key = derive_mldsa65_public_key_from_seed(&seed).expect("derive public key");
        let secret_key =
            derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive secret key");

        assert_eq!(
            public_key.as_bytes().as_slice(),
            vector.public_key.as_slice(),
            "tcId {} keyGen public key mismatch",
            vector.tc_id
        );
        assert_eq!(
            secret_key.as_bytes().as_slice(),
            vector.secret_key.as_slice(),
            "tcId {} keyGen secret key mismatch",
            vector.tc_id
        );
    }
}

#[test]
fn official_mldsa65_siggen_kats_pass_when_configured() {
    let Some(path) = env::var_os("DYTALLIX_MLDSA65_SIGGEN_KAT").map(PathBuf::from) else {
        return;
    };
    let json = fs::read_to_string(&path).expect("read ML-DSA-65 sigGen KAT fixture");
    let vectors = load_acvp_siggen_vectors(&json).expect("parse ML-DSA-65 sigGen KAT fixture");

    for vector in vectors {
        if vector.secret_key.len() != MLDSA65_SECRETKEY_BYTES
            || vector.signature.len() != MLDSA65_SIGNATURE_BYTES
        {
            continue;
        }

        let signature = match vector.mode {
            SigGenMode::ExternalPure => {
                sign_mldsa65_external_pure_deterministic_from_expanded_secret_key(
                    &vector.secret_key,
                    &vector.message,
                    &vector.context,
                )
            }
            SigGenMode::InternalMessage => {
                sign_mldsa65_internal_deterministic_from_expanded_secret_key(
                    &vector.secret_key,
                    &vector.message,
                )
            }
        }
        .expect("sign from expanded secret KAT");

        assert_eq!(
            signature.as_bytes().as_slice(),
            vector.signature.as_slice(),
            "tcId {} sigGen signature mismatch",
            vector.tc_id
        );
    }
}

fn load_acvp_keygen_vectors(json: &str) -> Result<Vec<KeyGenKat>, &'static str> {
    let vector_set = normalized_vector_set(json)?;

    if vector_set.get("algorithm").and_then(Value::as_str) != Some("ML-DSA") {
        return Err("unsupported algorithm");
    }
    if vector_set.get("mode").and_then(Value::as_str) != Some("keyGen") {
        return Err("unsupported mode");
    }

    let mut vectors = Vec::new();
    for group in vector_set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing testGroups")?
    {
        if group.get("parameterSet").and_then(Value::as_str) != Some("ML-DSA-65") {
            continue;
        }

        for test in group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?
        {
            vectors.push(KeyGenKat {
                tc_id: test
                    .get("tcId")
                    .and_then(Value::as_u64)
                    .ok_or("missing tcId")?,
                seed: decode_hex(required_string(test, &["seed", "xi", "d"])?)?,
                public_key: decode_hex(required_string(test, &["pk", "publicKey"])?)?,
                secret_key: decode_hex(required_string(test, &["sk", "secretKey"])?)?,
            });
        }
    }

    Ok(vectors)
}

fn load_acvp_siggen_vectors(json: &str) -> Result<Vec<SigGenKat>, &'static str> {
    let vector_set = normalized_vector_set(json)?;

    if vector_set.get("algorithm").and_then(Value::as_str) != Some("ML-DSA") {
        return Err("unsupported algorithm");
    }
    if vector_set.get("mode").and_then(Value::as_str) != Some("sigGen") {
        return Err("unsupported mode");
    }

    let mut vectors = Vec::new();
    for group in vector_set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing testGroups")?
    {
        if group.get("parameterSet").and_then(Value::as_str) != Some("ML-DSA-65") {
            continue;
        }

        let mode = match (
            group.get("signatureInterface").and_then(Value::as_str),
            group.get("preHash").and_then(Value::as_str),
            group.get("externalMu").and_then(Value::as_bool),
        ) {
            (Some("external"), None | Some("pure"), _) => Some(SigGenMode::ExternalPure),
            (Some("internal"), None | Some("none"), None | Some(false)) => {
                Some(SigGenMode::InternalMessage)
            }
            _ => None,
        };
        let Some(mode) = mode else {
            continue;
        };

        let group_secret_key = group
            .get("sk")
            .or_else(|| group.get("secretKey"))
            .and_then(Value::as_str)
            .map(decode_hex)
            .transpose()?;

        for test in group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?
        {
            let secret_key = test
                .get("sk")
                .or_else(|| test.get("secretKey"))
                .and_then(Value::as_str)
                .map(decode_hex)
                .transpose()?
                .or_else(|| group_secret_key.clone())
                .ok_or("missing secret key")?;

            vectors.push(SigGenKat {
                tc_id: test
                    .get("tcId")
                    .and_then(Value::as_u64)
                    .ok_or("missing tcId")?,
                mode,
                message: decode_hex(required_string(test, &["message", "msg"])?)?,
                context: test
                    .get("context")
                    .or_else(|| test.get("ctx"))
                    .and_then(Value::as_str)
                    .map(decode_hex)
                    .transpose()?
                    .unwrap_or_default(),
                secret_key,
                signature: decode_hex(required_string(test, &["signature", "sig"])?)?,
            });
        }
    }

    Ok(vectors)
}

fn normalized_vector_set(json: &str) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_str(json).map_err(|_| "invalid json")?;
    Ok(value
        .as_array()
        .and_then(|items| items.get(1))
        .cloned()
        .unwrap_or(value))
}

fn required_string<'a>(value: &'a Value, names: &[&str]) -> Result<&'a str, &'static str> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .ok_or("missing string")
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string has odd length");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let high = decode_nibble(chunk[0])?;
        let low = decode_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn decode_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character"),
    }
}

fn repeated_hex(byte: u8, len: usize) -> String {
    format!("{byte:02x}").repeat(len)
}

const SAMPLE_KEYGEN_BAD_HEX: &str = r#"{
  "algorithm": "ML-DSA",
  "mode": "keyGen",
  "testGroups": [
    {
      "parameterSet": "ML-DSA-65",
      "tests": [
        { "tcId": 1, "seed": "zz", "pk": "00", "sk": "00" }
      ]
    }
  ]
}"#;

const SAMPLE_SIGGEN_BAD_HEX: &str = r#"{
  "algorithm": "ML-DSA",
  "mode": "sigGen",
  "testGroups": [
    {
      "parameterSet": "ML-DSA-65",
      "signatureInterface": "external",
      "sk": "00",
      "tests": [
        { "tcId": 1, "message": "zz", "signature": "00" }
      ]
    }
  ]
}"#;

fn sample_keygen() -> String {
    format!(
        r#"{{
  "algorithm": "ML-DSA",
  "mode": "keyGen",
  "testGroups": [
    {{
      "parameterSet": "ML-DSA-65",
      "tests": [
        {{ "tcId": 11, "seed": "{}", "pk": "{}", "sk": "{}" }}
      ]
    }}
  ]
}}"#,
        repeated_hex(0xAA, MLDSA65_KEYGEN_SEED_BYTES),
        repeated_hex(0xBB, MLDSA65_PUBLICKEY_BYTES),
        repeated_hex(0xCC, MLDSA65_SECRETKEY_BYTES)
    )
}

fn sample_siggen() -> String {
    format!(
        r#"{{
  "algorithm": "ML-DSA",
  "mode": "sigGen",
  "testGroups": [
    {{
      "parameterSet": "ML-DSA-65",
      "signatureInterface": "external",
      "sk": "{}",
      "tests": [
        {{ "tcId": 21, "message": "abcd", "context": "01", "signature": "{}" }}
      ]
    }},
    {{
      "parameterSet": "ML-DSA-65",
      "signatureInterface": "internal",
      "sk": "{}",
      "tests": [
        {{ "tcId": 31, "message": "cafe", "signature": "{}" }}
      ]
    }}
  ]
}}"#,
        repeated_hex(0x10, MLDSA65_SECRETKEY_BYTES),
        repeated_hex(0x20, MLDSA65_SIGNATURE_BYTES),
        repeated_hex(0x30, MLDSA65_SECRETKEY_BYTES),
        repeated_hex(0x40, MLDSA65_SIGNATURE_BYTES)
    )
}
