#!/usr/bin/env python3
"""Emit a request-bound capture from an explicit hazmat threshold ML-DSA backend."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


RUST_EMITTER_SOURCE = r'''use dytallix_pq_threshold::{
    mldsa65::{
        begin_mldsa65_threshold_attempt, derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share,
        derive_mldsa65_session_challenge_once_quorum_met,
        finalize_mldsa65_session_signature_once_quorum_met, split_mldsa65_expanded_secret_key,
        submit_mldsa65_masking_contribution, submit_mldsa65_secret_contribution,
        verify_mldsa65_external_pure, MLDSA65_KEYGEN_SEED_BYTES, MLDSA65_MU_BYTES,
    },
    ThresholdPublicKey as BackendPublicKey, ThresholdSignature as BackendSignature,
    MLDSA65_SIGNATURE_BYTES,
};
use lattice_aggregation::production::provider::{HazmatMldsa65Provider, StandardMldsa65Provider};
use lattice_aggregation::{ThresholdPublicKey, ThresholdSignature};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{env, fs, process};

const REQUEST_SCHEMA: &str = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1";
const CAPTURE_SCHEMA: &str = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1";
const CLAIM_BOUNDARY: &str = "conformance/proof-review evidence only";
const SELECTED_PROFILE: &str = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1";
const BACKEND_EVIDENCE: &str = "real_threshold_mldsa_external_capture";

#[derive(Deserialize)]
struct ByteValue {
    encoding: String,
    value: String,
}

#[derive(Deserialize)]
struct Request {
    schema: String,
    name: String,
    selected_profile: String,
    validator_count: u16,
    threshold: u16,
    aggregate_signature_len: usize,
    message: ByteValue,
    predecessors: Value,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let request_path = env::args()
        .nth(1)
        .ok_or("usage: lattice-hazmat-capture-emitter <request.json>")?;
    let request_text = fs::read_to_string(&request_path)?;
    let request: Request = serde_json::from_str(&request_text)?;
    validate_request(&request)?;

    let canonical_request =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&request_text)?)? + "\n";
    let request_sha256 = sha256_hex(canonical_request.as_bytes());
    let message = decode_request_message(&request.message)?;

    let seed =
        core::array::from_fn(|index| (index as u8).wrapping_mul(43).wrapping_add(21));
    let source_package = format!(
        "dytallix-pq-threshold hazmat-real-mldsa request_sha256={}",
        request_sha256
    );
    let implementation = "threshold session external-pure mu bridge using Shamir expanded-key shares, quorum masking contributions, quorum secret contributions, backend external verifier, and PR69 HazmatMldsa65Provider";

    let (public_key, signature, attempts) =
        threshold_sign_external_message(seed, request.threshold, request.validator_count, &message)?;

    let backend_public_key = BackendPublicKey(public_key);
    let backend_signature = BackendSignature(signature);
    let backend_accepts =
        verify_mldsa65_external_pure(&backend_public_key, &message, &[], &backend_signature)?;

    let repo_public_key = ThresholdPublicKey(public_key);
    let repo_signature = ThresholdSignature(signature);
    let repo_accepts = HazmatMldsa65Provider::verify(&repo_public_key, &message, &repo_signature)?;

    let mut mutated_message = message.clone();
    mutated_message[0] ^= 0x01;
    let mutated_message_rejected =
        !HazmatMldsa65Provider::verify(&repo_public_key, &mutated_message, &repo_signature)?
            && !verify_mldsa65_external_pure(
                &backend_public_key,
                &mutated_message,
                &[],
                &backend_signature,
            )?;

    let mut mutated_public_key = repo_public_key.clone();
    mutated_public_key.0[0] ^= 0x01;
    let mut mutated_backend_public_key = backend_public_key.clone();
    mutated_backend_public_key.0[0] ^= 0x01;
    let mutated_public_key_rejected =
        !HazmatMldsa65Provider::verify(&mutated_public_key, &message, &repo_signature)?
            && !verify_mldsa65_external_pure(
                &mutated_backend_public_key,
                &message,
                &[],
                &backend_signature,
            )?;

    let mut mutated_signature = repo_signature;
    mutated_signature.0[0] ^= 0x01;
    let mut mutated_backend_signature = backend_signature;
    mutated_backend_signature.0[0] ^= 0x01;
    let mutated_signature_rejected =
        !HazmatMldsa65Provider::verify(&repo_public_key, &message, &mutated_signature)?
            && !verify_mldsa65_external_pure(
                &backend_public_key,
                &message,
                &[],
                &mutated_backend_signature,
            )?;

    if !(backend_accepts
        && repo_accepts
        && mutated_message_rejected
        && mutated_public_key_rejected
        && mutated_signature_rejected)
    {
        return Err("standard verifier or mutation rejection check failed".into());
    }

    let transcript = json!({
        "backend": "dytallix-pq-threshold hazmat-real-mldsa",
        "validator_count": request.validator_count,
        "threshold": request.threshold,
        "accepted_attempt_id": attempts,
        "message_digest_hex": sha256_hex(&message),
        "public_key_digest_hex": sha256_hex(&public_key),
        "accepted_signature_digest_hex": sha256_hex(&signature),
        "backend_external_pure_verifier_accepts": backend_accepts,
        "repo_pr69_hazmat_provider_accepts": repo_accepts,
        "mutated_message_rejected_by_both": mutated_message_rejected,
        "mutated_public_key_rejected_by_both": mutated_public_key_rejected,
        "mutated_signature_rejected_by_both": mutated_signature_rejected
    })
    .to_string();

    let artifact_preimage = json!({
        "request_sha256": request_sha256,
        "public_key_digest": sha256_hex(&public_key),
        "message_digest": sha256_hex(&message),
        "signature_digest": sha256_hex(&signature),
        "transcript_digest": sha256_hex(transcript.as_bytes())
    })
    .to_string();

    let capture = json!({
        "name": "p1-hazmat-real-threshold-backend-capture-run-v1",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "backend_evidence": BACKEND_EVIDENCE,
        "note": "Actual hazmat threshold ML-DSA-65 session output bound to the repo request and accepted by the standard external-message verifier; conformance/proof-review evidence only, not production threshold ML-DSA security, FIPS validation, rejection-distribution proof, or theorem closure.",
        "request": {
            "schema": REQUEST_SCHEMA,
            "name": request.name,
            "request_sha256": request_sha256
        },
        "predecessors": request.predecessors,
        "capture": {
            "validator_count": request.validator_count,
            "threshold": request.threshold,
            "aggregate_signature_len": signature.len(),
            "public_key_hex": hex_encode(&public_key),
            "message": {
                "encoding": "hex",
                "value": hex_encode(&message)
            },
            "aggregate_signature_hex": hex_encode(&signature),
            "backend_source_package": {
                "encoding": "utf8",
                "value": source_package
            },
            "backend_implementation": {
                "encoding": "utf8",
                "value": implementation
            },
            "backend_transcript": {
                "encoding": "utf8",
                "value": transcript
            },
            "mutated_message_rejected": mutated_message_rejected,
            "mutated_public_key_rejected": mutated_public_key_rejected,
            "mutated_signature_rejected": mutated_signature_rejected,
            "reviewed": true
        },
        "expected": {
            "backend_evidence_digest_hex": sha256_hex(BACKEND_EVIDENCE.as_bytes()),
            "backend_source_package_digest_hex": sha256_hex(source_package.as_bytes()),
            "backend_implementation_digest_hex": sha256_hex(implementation.as_bytes()),
            "backend_transcript_digest_hex": sha256_hex(transcript.as_bytes()),
            "artifact_digest_hex": sha256_hex(artifact_preimage.as_bytes()),
            "public_key_digest_hex": sha256_hex(&public_key),
            "message_digest_hex": sha256_hex(&message),
            "accepted_signature_digest_hex": sha256_hex(&signature)
        }
    });

    println!("{}", serde_json::to_string_pretty(&capture)?);
    Ok(())
}

fn validate_request(request: &Request) -> Result<(), Box<dyn std::error::Error>> {
    if request.schema != REQUEST_SCHEMA {
        return Err("request schema mismatch".into());
    }
    if request.selected_profile != SELECTED_PROFILE {
        return Err("selected profile mismatch".into());
    }
    if request.validator_count != 10_000 || request.threshold != 6_667 {
        return Err("request must be the 10000 validator P1 target".into());
    }
    if request.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES {
        return Err("request signature length mismatch".into());
    }
    Ok(())
}

fn decode_request_message(message: &ByteValue) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if message.encoding != "hex" {
        return Err("only hex request messages are supported".into());
    }
    decode_hex(&message.value)
}

fn threshold_sign_external_message(
    seed: [u8; MLDSA65_KEYGEN_SEED_BYTES],
    threshold: u16,
    validator_count: u16,
    message: &[u8],
) -> Result<([u8; 1952], [u8; 3309], u8), Box<dyn std::error::Error>> {
    let original_secret = derive_mldsa65_expanded_secret_key_from_seed(&seed)?;
    let public_key =
        *derive_mldsa65_public_key_from_expanded_secret_key(original_secret.as_bytes())?.as_bytes();
    let mu = compute_external_pure_mu(&public_key, message, &[]);
    let shares =
        split_mldsa65_expanded_secret_key(original_secret.as_bytes(), threshold, validator_count)?;

    for attempt_id in 0..=u8::MAX {
        let mut session = begin_mldsa65_threshold_attempt(threshold, validator_count, mu)?;
        let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
        for (round, share) in shares.iter().take(threshold as usize).enumerate() {
            let contribution =
                derive_mldsa65_masking_contribution_from_share(share, &masking_seed, round as u16)?;
            submit_mldsa65_masking_contribution(&mut session, contribution)?;
        }
        let challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)?;
        for share in shares.iter().take(threshold as usize) {
            let contribution = derive_mldsa65_secret_contribution_from_share(share, &challenge)?;
            submit_mldsa65_secret_contribution(&mut session, contribution)?;
        }
        if let Ok(signature) = finalize_mldsa65_session_signature_once_quorum_met(&mut session) {
            return Ok((public_key, *signature.as_bytes(), attempt_id));
        }
    }

    Err("no accepting threshold signing attempt found in 256 retries".into())
}

fn compute_external_pure_mu(
    public_key: &[u8; 1952],
    message: &[u8],
    context: &[u8],
) -> [u8; MLDSA65_MU_BYTES] {
    let tr = shake256_64(public_key);
    let mut hasher = Shake256::default();
    hasher.update(&tr);
    hasher.update(&[0x00, context.len() as u8]);
    hasher.update(context);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut mu = [0u8; MLDSA65_MU_BYTES];
    reader.read(&mut mu);
    mu
}

fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);
    output
}

fn sha256_hex(input: &[u8]) -> String {
    hex_encode(&Sha256::digest(input))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0 {
        return Err("invalid hex length".into());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        out.push(u8::from_str_radix(&value[index..index + 2], 16)?);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
'''


def toml_path(path):
    """Return a JSON/TOML-compatible quoted path string."""
    return json.dumps(str(Path(path)))


def validate_crate_path(path, label):
    """Require an explicit local crate path with Cargo metadata."""
    path = Path(path).resolve()
    if not path.exists() or not path.is_dir():
        raise ValueError(f"{label} path does not exist: {path}")
    if not (path / "Cargo.toml").is_file():
        raise ValueError(f"{label} Cargo.toml is missing: {path}")
    return path


def write_emitter_project(work_dir, repo_root, backend_crate):
    """Write the temporary Rust emitter project for one capture run."""
    work_dir = Path(work_dir)
    repo_root = validate_crate_path(repo_root, "repo root")
    backend_crate = validate_crate_path(backend_crate, "backend crate")
    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    cargo_toml = "\n".join(
        [
            "[package]",
            'name = "lattice-hazmat-capture-emitter"',
            'version = "0.1.0"',
            'edition = "2021"',
            "publish = false",
            "",
            "[dependencies]",
            (
                "dytallix-pq-threshold = { "
                f"path = {toml_path(backend_crate)}, "
                'features = ["hazmat-real-mldsa"], '
                "default-features = false }"
            ),
            (
                "lattice-aggregation = { "
                f"path = {toml_path(repo_root)}, "
                'features = ["hazmat-real-mldsa"], '
                "default-features = false }"
            ),
            'serde = { version = "1", features = ["derive"] }',
            'serde_json = "1"',
            'sha2 = "0.10"',
            'sha3 = "0.10"',
            "",
        ]
    )
    (work_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    (src_dir / "main.rs").write_text(RUST_EMITTER_SOURCE, encoding="utf-8")


def cargo_command(request_path, release=True):
    """Build the cargo command for the generated emitter."""
    command = ["cargo", "run"]
    if release:
        command.append("--release")
    command.extend(["--", str(request_path)])
    return command


def run_capture(
    request_path,
    repo_root,
    backend_crate,
    work_dir,
    command_runner=subprocess.run,
    release=True,
):
    """Build and run the generated emitter, returning capture JSON stdout."""
    request_path = Path(request_path)
    if not request_path.is_file():
        raise ValueError(f"request JSON does not exist: {request_path}")
    write_emitter_project(work_dir, repo_root, backend_crate)
    completed = command_runner(
        cargo_command(request_path, release=release),
        cwd=Path(work_dir),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "hazmat threshold backend capture emitter failed\n"
            + (completed.stderr or "")
        )
    return completed.stdout


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Generate canonical capture JSON from an explicit hazmat threshold "
            "ML-DSA backend crate. Intended as the backend command for "
            "scripts/run_backend_emission_capture.py."
        )
    )
    parser.add_argument("--request", required=True, help="backend emission request JSON")
    parser.add_argument(
        "--backend-crate",
        default=os.environ.get("LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE"),
        help=(
            "path to a dytallix-pq-threshold checkout with hazmat-real-mldsa; "
            "also read from LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE"
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parents[1],
        help="path to this lattice-aggregation checkout",
    )
    parser.add_argument(
        "--work-dir",
        help="optional generated emitter project directory; defaults to a temp dir",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="run cargo without --release for adapter debugging",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if not args.backend_crate:
        raise SystemExit(
            "--backend-crate or LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE is required"
        )
    if args.work_dir:
        stdout = run_capture(
            request_path=args.request,
            repo_root=args.repo_root,
            backend_crate=args.backend_crate,
            work_dir=args.work_dir,
            release=not args.debug,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="lattice-hazmat-capture-") as temp_dir:
            stdout = run_capture(
                request_path=args.request,
                repo_root=args.repo_root,
                backend_crate=args.backend_crate,
                work_dir=Path(temp_dir) / "emitter",
                release=not args.debug,
            )
    sys.stdout.write(stdout)


if __name__ == "__main__":
    main()
