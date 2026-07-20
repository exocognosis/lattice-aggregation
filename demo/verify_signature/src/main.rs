//! Independently verify a threshold ML-DSA-65 signature produced by the
//! distributed signing run, using the third party RustCrypto `ml-dsa` crate.
//!
//! This deliberately does NOT use this project's own verifier. It reads the
//! public key, message, and signature straight out of a run artifact and asks
//! an unrelated library whether the signature is valid. It also confirms a
//! tampered message is rejected, so a constant "true" stub cannot pass.
//!
//! Usage: verify_signature <artifact-dir>
//!   where <artifact-dir> contains params.json and sign-stdout.json.

use ml_dsa::signature::Verifier;
use ml_dsa::{MlDsa65, Signature, VerifyingKey};

fn read_json(path: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

fn hex_field<'a>(v: &'a serde_json::Value, key: &str, file: &str) -> Vec<u8> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string field '{key}' in {file}"));
    hex::decode(s).unwrap_or_else(|e| panic!("field '{key}' in {file} is not hex: {e}"))
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../../artifacts/real-small-distributed-aggregation/latest".to_string());
    let params = read_json(&format!("{dir}/params.json"));
    let signed = read_json(&format!("{dir}/sign-stdout.json"));

    let pk = hex_field(&params, "public_key_hex", "params.json");
    let sig = hex_field(&signed, "signature_hex", "sign-stdout.json");
    let message = params
        .get("message")
        .and_then(|x| x.as_str())
        .expect("missing 'message' in params.json")
        .as_bytes()
        .to_vec();

    println!("artifact dir : {dir}");
    println!("public key   : {} bytes", pk.len());
    println!("signature    : {} bytes", sig.len());
    println!("message      : {:?}", String::from_utf8_lossy(&message));

    let vk = VerifyingKey::<MlDsa65>::decode(
        pk.as_slice().try_into().expect("public key wrong length"),
    );
    let signature = Signature::<MlDsa65>::decode(
        sig.as_slice().try_into().expect("signature wrong length"),
    )
    .expect("signature failed to decode");

    let valid = vk.verify(&message, &signature).is_ok();

    let mut tampered = message.clone();
    tampered[0] ^= 0x01;
    let tampered_rejected = vk.verify(&tampered, &signature).is_err();

    println!();
    println!("signature valid          : {valid}");
    println!("tampered message rejected : {tampered_rejected}");
    println!();

    if valid && tampered_rejected {
        println!("PASS: a third party library accepts this threshold-produced ML-DSA-65 signature.");
        std::process::exit(0);
    } else {
        println!("FAIL: verification did not hold. Do not trust this artifact.");
        std::process::exit(1);
    }
}
