#![cfg(feature = "hazmat-real-mldsa")]

use std::{fs, path::PathBuf};

use dytallix_pq_threshold::{
    mldsa65::{
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_public_key_from_expanded_secret_key, derive_mldsa65_public_key_from_seed,
        sign_mldsa65_external_pure_deterministic_from_expanded_secret_key,
        sign_mldsa65_external_pure_deterministic_from_seed,
        sign_mldsa65_internal_deterministic_from_seed, verify_mldsa65_external_pure,
        verify_mldsa65_internal_message, MLDSA65_KEYGEN_SEED_BYTES,
    },
    ThresholdPublicKey, ThresholdSignature, MLDSA65_PUBLICKEY_BYTES, MLDSA65_SECRETKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
};
use ml_dsa::{signature::Keypair, Seed as ReferenceSeed};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey as ReferenceExpandedSigningKey,
    MlDsa65, Signature as ReferenceSignature, SigningKey as ReferenceSigningKey,
    VerifyingKey as ReferenceVerifyingKey,
};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferentialMode {
    ExternalPure,
    InternalMessage,
}

#[derive(Debug)]
struct DifferentialVector {
    tc_id: u64,
    mode: DifferentialMode,
    message: Vec<u8>,
    context: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

#[test]
fn rustcrypto_mldsa65_agrees_on_supported_acvp_sigver_paths() {
    let path = PathBuf::from("tests/fixtures/ml_dsa_65_sigver_acvp.json");
    let json = fs::read_to_string(&path).expect("read ML-DSA-65 ACVP sigVer fixture");
    let vectors =
        load_differential_vectors(&json).expect("parse supported ML-DSA-65 differential vectors");

    assert!(
        vectors
            .iter()
            .any(|vector| vector.mode == DifferentialMode::ExternalPure),
        "fixture must contain at least one external pure differential vector"
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.mode == DifferentialMode::InternalMessage),
        "fixture must contain at least one internal message differential vector"
    );

    for vector in vectors {
        assert_eq!(
            vector.public_key.len(),
            MLDSA65_PUBLICKEY_BYTES,
            "tcId {} public key length mismatch",
            vector.tc_id
        );
        assert_eq!(
            vector.signature.len(),
            MLDSA65_SIGNATURE_BYTES,
            "tcId {} signature length mismatch",
            vector.tc_id
        );

        let local_public_key = ThresholdPublicKey(
            vector
                .public_key
                .clone()
                .try_into()
                .expect("public key length checked"),
        );
        let local_signature = ThresholdSignature(
            vector
                .signature
                .clone()
                .try_into()
                .expect("signature length checked"),
        );

        let local_verified = match vector.mode {
            DifferentialMode::ExternalPure => verify_mldsa65_external_pure(
                &local_public_key,
                &vector.message,
                &vector.context,
                &local_signature,
            ),
            DifferentialMode::InternalMessage => verify_mldsa65_internal_message(
                &local_public_key,
                &vector.message,
                &local_signature,
            ),
        }
        .unwrap_or(false);

        let reference_verified = reference_verify(&vector);

        assert_eq!(
            local_verified, reference_verified,
            "tcId {} differential verification mismatch",
            vector.tc_id
        );
    }
}

#[test]
fn local_keygen_public_key_derivation_matches_rustcrypto() {
    let seeds = [
        [0u8; MLDSA65_KEYGEN_SEED_BYTES],
        [0xA5u8; MLDSA65_KEYGEN_SEED_BYTES],
        core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(3)),
    ];

    for seed_bytes in seeds {
        let local_public_key =
            derive_mldsa65_public_key_from_seed(&seed_bytes).expect("derive local public key");
        let reference_seed =
            ReferenceSeed::try_from(seed_bytes.as_slice()).expect("construct reference seed");
        let reference_public_key = ReferenceSigningKey::<MlDsa65>::from_seed(&reference_seed)
            .verifying_key()
            .encode();

        assert_eq!(
            local_public_key.as_bytes().as_slice(),
            reference_public_key.as_slice(),
            "local ML-DSA-65 public-key derivation diverged from RustCrypto"
        );
    }
}

#[test]
fn local_expanded_secret_key_derivation_matches_rustcrypto() {
    let seeds = [
        [0u8; MLDSA65_KEYGEN_SEED_BYTES],
        core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(7)),
    ];

    for seed_bytes in seeds {
        let local_secret_key = derive_mldsa65_expanded_secret_key_from_seed(&seed_bytes)
            .expect("derive local secret key");
        let reference_seed =
            ReferenceSeed::try_from(seed_bytes.as_slice()).expect("construct reference seed");
        #[allow(deprecated)]
        let reference_secret_key =
            ReferenceExpandedSigningKey::<MlDsa65>::from_seed(&reference_seed).to_expanded();

        assert_eq!(local_secret_key.as_bytes().len(), MLDSA65_SECRETKEY_BYTES);
        assert_eq!(
            local_secret_key.as_bytes().as_slice(),
            reference_secret_key.as_slice(),
            "local ML-DSA-65 expanded secret-key derivation diverged from RustCrypto"
        );
    }
}

#[test]
fn local_expanded_secret_key_decoding_derives_public_key_and_signs() {
    let seed_bytes = core::array::from_fn(|index| (index as u8).wrapping_mul(31).wrapping_add(13));
    let message = b"expanded secret key decode signing";
    let context = b"decode-context";

    let local_secret_key =
        derive_mldsa65_expanded_secret_key_from_seed(&seed_bytes).expect("derive local secret key");
    let local_public_key =
        derive_mldsa65_public_key_from_expanded_secret_key(local_secret_key.as_bytes())
            .expect("derive public key from expanded secret key");
    let local_signature = sign_mldsa65_external_pure_deterministic_from_expanded_secret_key(
        local_secret_key.as_bytes(),
        message,
        context,
    )
    .expect("sign from expanded secret key");

    let reference_seed =
        ReferenceSeed::try_from(seed_bytes.as_slice()).expect("construct reference seed");
    #[allow(deprecated)]
    let reference_expanded = ReferenceExpandedSigningKey::<MlDsa65>::from_seed(&reference_seed);
    let reference_public_key = reference_expanded.verifying_key().encode();
    let reference_signature = reference_expanded
        .sign_deterministic(message, context)
        .expect("reference external deterministic signing")
        .encode();

    assert_eq!(
        local_public_key.as_bytes().as_slice(),
        reference_public_key.as_slice(),
        "decoded expanded secret key derived the wrong public key"
    );
    assert_eq!(
        local_signature.as_bytes().as_slice(),
        reference_signature.as_slice(),
        "decoded expanded secret key produced the wrong signature"
    );
}

#[test]
fn local_internal_deterministic_signing_matches_rustcrypto() {
    let cases = [
        ([0u8; MLDSA65_KEYGEN_SEED_BYTES], b"".as_slice()),
        (
            core::array::from_fn(|index| (index as u8).wrapping_mul(11).wrapping_add(9)),
            b"dytallix hazmat internal signing differential".as_slice(),
        ),
    ];
    let deterministic_rnd = [0u8; MLDSA65_KEYGEN_SEED_BYTES];

    for (seed_bytes, message) in cases {
        let local_signature = sign_mldsa65_internal_deterministic_from_seed(&seed_bytes, message)
            .expect("derive local internal signature");
        let reference_seed =
            ReferenceSeed::try_from(seed_bytes.as_slice()).expect("construct reference seed");
        let reference_rnd =
            ReferenceSeed::try_from(deterministic_rnd.as_slice()).expect("construct rnd seed");
        let reference_signature =
            ReferenceExpandedSigningKey::<MlDsa65>::from_seed(&reference_seed)
                .sign_internal(&[message], &reference_rnd)
                .encode();

        assert_eq!(
            local_signature.as_bytes().as_slice(),
            reference_signature.as_slice(),
            "local deterministic ML-DSA-65 internal signing diverged from RustCrypto"
        );

        let local_public_key =
            derive_mldsa65_public_key_from_seed(&seed_bytes).expect("derive local public key");
        let verified = verify_mldsa65_internal_message(
            &ThresholdPublicKey(*local_public_key.as_bytes()),
            message,
            &ThresholdSignature(*local_signature.as_bytes()),
        )
        .expect("verify generated internal signature");
        assert!(
            verified,
            "local verifier rejected locally generated signature"
        );
    }
}

#[test]
fn local_external_pure_deterministic_signing_matches_rustcrypto() {
    let cases = [
        (
            [0x5Au8; MLDSA65_KEYGEN_SEED_BYTES],
            b"external pure signing message".as_slice(),
            b"dytallix-context".as_slice(),
        ),
        (
            core::array::from_fn(|index| (index as u8).wrapping_mul(23).wrapping_add(1)),
            b"".as_slice(),
            b"".as_slice(),
        ),
    ];

    for (seed_bytes, message, context) in cases {
        let local_signature =
            sign_mldsa65_external_pure_deterministic_from_seed(&seed_bytes, message, context)
                .expect("derive local external pure signature");
        let reference_seed =
            ReferenceSeed::try_from(seed_bytes.as_slice()).expect("construct reference seed");
        let reference_signature =
            ReferenceExpandedSigningKey::<MlDsa65>::from_seed(&reference_seed)
                .sign_deterministic(message, context)
                .expect("reference external deterministic signing")
                .encode();

        assert_eq!(
            local_signature.as_bytes().as_slice(),
            reference_signature.as_slice(),
            "local deterministic ML-DSA-65 external signing diverged from RustCrypto"
        );

        let local_public_key =
            derive_mldsa65_public_key_from_seed(&seed_bytes).expect("derive local public key");
        let verified = verify_mldsa65_external_pure(
            &ThresholdPublicKey(*local_public_key.as_bytes()),
            message,
            context,
            &ThresholdSignature(*local_signature.as_bytes()),
        )
        .expect("verify generated external signature");
        assert!(
            verified,
            "local verifier rejected locally generated external signature"
        );
    }
}

fn reference_verify(vector: &DifferentialVector) -> bool {
    let public_key = match EncodedVerifyingKey::<MlDsa65>::try_from(vector.public_key.as_slice()) {
        Ok(encoded) => ReferenceVerifyingKey::<MlDsa65>::decode(&encoded),
        Err(_) => return false,
    };
    let signature = match EncodedSignature::<MlDsa65>::try_from(vector.signature.as_slice()) {
        Ok(encoded) => match ReferenceSignature::<MlDsa65>::decode(&encoded) {
            Some(signature) => signature,
            None => return false,
        },
        Err(_) => return false,
    };

    match vector.mode {
        DifferentialMode::ExternalPure => {
            public_key.verify_with_context(&vector.message, &vector.context, &signature)
        }
        DifferentialMode::InternalMessage => {
            public_key.verify_internal(&vector.message, &signature)
        }
    }
}

fn load_differential_vectors(json: &str) -> Result<Vec<DifferentialVector>, &'static str> {
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

        let mode = match (
            group.get("signatureInterface").and_then(Value::as_str),
            group.get("preHash").and_then(Value::as_str),
            group.get("externalMu").and_then(Value::as_bool),
        ) {
            (Some("external"), None | Some("pure"), _) => DifferentialMode::ExternalPure,
            (Some("internal"), None | Some("none"), None | Some(false)) => {
                DifferentialMode::InternalMessage
            }
            _ => continue,
        };

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

            vectors.push(DifferentialVector {
                tc_id: test
                    .get("tcId")
                    .and_then(Value::as_u64)
                    .ok_or("missing tcId")?,
                mode,
                message: test
                    .get("message")
                    .and_then(Value::as_str)
                    .map(decode_hex)
                    .transpose()?
                    .unwrap_or_default(),
                context: test
                    .get("context")
                    .and_then(Value::as_str)
                    .map(decode_hex)
                    .transpose()?
                    .unwrap_or_default(),
                public_key: test_public_key,
                signature: decode_hex(required_string(test, "signature")?)?,
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
