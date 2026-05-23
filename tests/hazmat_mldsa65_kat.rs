#![cfg(feature = "hazmat-real-mldsa")]

use std::{env, fs, path::PathBuf};

use dytallix_pq_threshold::{
    mldsa65::verify_mldsa65_external_pure, ThresholdPublicKey, ThresholdSignature,
    MLDSA65_PUBLICKEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};
use serde_json::Value;

#[derive(Debug, Eq, PartialEq)]
struct SigVerKat {
    tc_id: u64,
    message: Vec<u8>,
    context: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    expected_valid: bool,
}

#[test]
fn hazmat_acvp_sigver_loader_extracts_mldsa65_vectors() {
    let vectors = load_acvp_sigver_vectors(SAMPLE_ACVP_SIGVER).unwrap();

    assert_eq!(vectors.len(), 1);
    assert_eq!(vectors[0].tc_id, 7);
    assert_eq!(vectors[0].message, vec![0xAB, 0xCD]);
    assert_eq!(vectors[0].context, vec![0xAA]);
    assert_eq!(vectors[0].public_key, vec![0x01, 0x02]);
    assert_eq!(vectors[0].signature, vec![0x03, 0x04]);
    assert!(vectors[0].expected_valid);
}

#[test]
fn hazmat_acvp_sigver_loader_ignores_other_parameter_sets() {
    let vectors = load_acvp_sigver_vectors(SAMPLE_OTHER_PARAMETER_SET).unwrap();

    assert!(vectors.is_empty());
}

#[test]
fn hazmat_acvp_sigver_loader_ignores_unsupported_interfaces() {
    let vectors = load_acvp_sigver_vectors(SAMPLE_EXTERNAL_INTERFACE).unwrap();

    assert!(vectors.is_empty());
}

#[test]
fn hazmat_acvp_sigver_loader_extracts_non_empty_context_vectors() {
    let vectors = load_acvp_sigver_vectors(SAMPLE_NON_EMPTY_CONTEXT).unwrap();

    assert_eq!(vectors.len(), 1);
    assert_eq!(vectors[0].context, vec![0x01]);
}

#[test]
fn hazmat_acvp_sigver_loader_rejects_bad_hex() {
    assert_eq!(
        load_acvp_sigver_vectors(SAMPLE_BAD_HEX),
        Err("invalid hex character")
    );
}

#[test]
fn official_mldsa65_sigver_kats_pass() {
    let path = env::var_os("DYTALLIX_MLDSA65_SIGVER_KAT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/fixtures/ml_dsa_65_sigver_acvp.json"));
    let json = fs::read_to_string(&path).expect("read ML-DSA-65 ACVP sigVer fixture");
    let vectors = load_acvp_sigver_vectors(&json).expect("parse ML-DSA-65 ACVP sigVer fixture");

    assert!(
        vectors.iter().any(|vector| vector.expected_valid),
        "fixture must contain at least one valid ML-DSA-65 signature"
    );

    for vector in vectors {
        if vector.public_key.len() != MLDSA65_PUBLICKEY_BYTES
            || vector.signature.len() != MLDSA65_SIGNATURE_BYTES
        {
            panic!("tcId {} has invalid ML-DSA-65 byte lengths", vector.tc_id);
        }

        let public_key = ThresholdPublicKey(
            vector
                .public_key
                .try_into()
                .expect("public key length checked"),
        );
        let signature = ThresholdSignature(
            vector
                .signature
                .try_into()
                .expect("signature length checked"),
        );
        let verified =
            verify_mldsa65_external_pure(&public_key, &vector.message, &vector.context, &signature);
        let verified_bool = match verified {
            Ok(value) => value,
            Err(_) if !vector.expected_valid => false,
            Err(error) => panic!(
                "tcId {} valid signature returned verifier error: {:?}",
                vector.tc_id, error
            ),
        };

        assert_eq!(
            verified_bool, vector.expected_valid,
            "tcId {} verification mismatch",
            vector.tc_id
        );
    }
}

fn load_acvp_sigver_vectors(json: &str) -> Result<Vec<SigVerKat>, &'static str> {
    let value: Value = serde_json::from_str(json).map_err(|_| "invalid json")?;
    let vector_set = value
        .as_array()
        .and_then(|items| items.get(1))
        .unwrap_or(&value);

    if vector_set.get("algorithm").and_then(Value::as_str) != Some("ML-DSA") {
        return Err("unsupported algorithm");
    }
    if vector_set.get("mode").and_then(Value::as_str) != Some("sigVer") {
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
        if group.get("signatureInterface").and_then(Value::as_str) != Some("external") {
            continue;
        }
        if !matches!(
            group.get("preHash").and_then(Value::as_str),
            None | Some("pure")
        ) {
            continue;
        }

        let public_key = group
            .get("pk")
            .or_else(|| group.get("publicKey"))
            .and_then(Value::as_str)
            .map(decode_hex)
            .transpose()?;

        for test in group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?
        {
            let test_public_key = test
                .get("pk")
                .or_else(|| test.get("publicKey"))
                .and_then(Value::as_str)
                .map(decode_hex)
                .transpose()?
                .or_else(|| public_key.clone())
                .ok_or("missing public key")?;

            vectors.push(SigVerKat {
                tc_id: test
                    .get("tcId")
                    .and_then(Value::as_u64)
                    .ok_or("missing tcId")?,
                message: decode_hex(required_string(test, "message")?)?,
                context: test
                    .get("context")
                    .and_then(Value::as_str)
                    .map(decode_hex)
                    .transpose()?
                    .unwrap_or_default(),
                public_key: test_public_key,
                signature: decode_hex(required_string(test, "signature")?)?,
                expected_valid: expected_valid(test)?,
            });
        }
    }

    Ok(vectors)
}

fn required_string<'a>(value: &'a Value, key: &'static str) -> Result<&'a str, &'static str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("missing string")
}

fn expected_valid(value: &Value) -> Result<bool, &'static str> {
    if let Some(test_passed) = value.get("testPassed").and_then(Value::as_bool) {
        return Ok(test_passed);
    }
    if let Some(result) = value.get("result").and_then(Value::as_str) {
        return match result {
            "valid" | "passed" | "pass" => Ok(true),
            "invalid" | "failed" | "fail" => Ok(false),
            _ => Err("unsupported result"),
        };
    }
    Err("missing expected validity")
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length");
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

const SAMPLE_ACVP_SIGVER: &str = r#"[
  { "acvVersion": "1.0" },
  {
    "algorithm": "ML-DSA",
    "mode": "sigVer",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-65",
        "signatureInterface": "external",
        "preHash": "pure",
        "pk": "0102",
        "tests": [
          {
            "tcId": 7,
            "message": "abcd",
            "context": "aa",
            "signature": "0304",
            "testPassed": true
          }
        ]
      }
    ]
  }
]"#;

const SAMPLE_OTHER_PARAMETER_SET: &str = r#"[
  { "acvVersion": "1.0" },
  {
    "algorithm": "ML-DSA",
    "mode": "sigVer",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-44",
        "pk": "0102",
        "tests": [
          {
            "tcId": 7,
            "message": "abcd",
            "signature": "0304",
            "testPassed": true
          }
        ]
      }
    ]
  }
]"#;

const SAMPLE_EXTERNAL_INTERFACE: &str = r#"[
  { "acvVersion": "1.0" },
  {
    "algorithm": "ML-DSA",
    "mode": "sigVer",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-65",
        "signatureInterface": "internal",
        "preHash": "preHash",
        "pk": "0102",
        "tests": [
          {
            "tcId": 7,
            "message": "abcd",
            "signature": "0304",
            "testPassed": true
          }
        ]
      }
    ]
  }
]"#;

const SAMPLE_NON_EMPTY_CONTEXT: &str = r#"[
  { "acvVersion": "1.0" },
  {
    "algorithm": "ML-DSA",
    "mode": "sigVer",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-65",
        "signatureInterface": "external",
        "preHash": "pure",
        "pk": "0102",
        "tests": [
          {
            "tcId": 7,
            "message": "abcd",
            "context": "01",
            "signature": "0304",
            "testPassed": true
          }
        ]
      }
    ]
  }
]"#;

const SAMPLE_BAD_HEX: &str = r#"[
  { "acvVersion": "1.0" },
  {
    "algorithm": "ML-DSA",
    "mode": "sigVer",
    "revision": "FIPS204",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-DSA-65",
        "signatureInterface": "external",
        "preHash": "pure",
        "pk": "zz",
        "tests": [
          {
            "tcId": 7,
            "message": "abcd",
            "signature": "0304",
            "testPassed": true
          }
        ]
      }
    ]
  }
]"#;
