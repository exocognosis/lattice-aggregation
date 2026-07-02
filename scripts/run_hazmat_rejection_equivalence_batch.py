#!/usr/bin/env python3
"""Run a hazmat threshold-vs-centralized ML-DSA rejection-predicate batch."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


RUST_EMITTER_SOURCE = r'''use dytallix_pq_threshold::{
    mldsa65::{
        begin_mldsa65_threshold_attempt,
        derive_mldsa65_centralized_domain_masking_contribution_from_share,
        derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key,
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share,
        derive_mldsa65_session_challenge_once_quorum_met,
        derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met,
        finalize_mldsa65_session_signature_once_quorum_met, split_mldsa65_expanded_secret_key,
        submit_mldsa65_masking_contribution, submit_mldsa65_secret_contribution,
        verify_mldsa65_external_pure, MLDSA65_KEYGEN_SEED_BYTES, MLDSA65_MU_BYTES,
    },
    ThresholdError as BackendThresholdError, ThresholdPublicKey as BackendPublicKey,
    ThresholdSignature as BackendSignature,
};
use lattice_aggregation::production::provider::{HazmatMldsa65Provider, StandardMldsa65Provider};
use lattice_aggregation::{ThresholdPublicKey, ThresholdSignature};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{env, process};

const SCHEMA: &str = "lattice-aggregation:p1-rejection-equivalence-batch:v1";
const CLAIM_BOUNDARY: &str = "conformance/proof-review evidence only";
const SELECTED_PROFILE: &str = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1";
const BACKEND_EVIDENCE: &str = "mldsa65-centralized-vs-threshold-rejection-batch";

#[derive(Clone, Copy)]
struct Config {
    validator_count: u16,
    threshold: u16,
    attempts: u8,
    aligned_mask_domain: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config()?;
    let message = b"p1 rejection equivalence comparator batch";
    let seed =
        core::array::from_fn(|index| (index as u8).wrapping_mul(43).wrapping_add(21));
    let central_rnd = [0u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret = derive_mldsa65_expanded_secret_key_from_seed(&seed)?;
    let public_key =
        *derive_mldsa65_public_key_from_expanded_secret_key(original_secret.as_bytes())?.as_bytes();
    let mu = compute_external_pure_mu(&public_key, message, &[]);
    let shares = split_mldsa65_expanded_secret_key(
        original_secret.as_bytes(),
        config.threshold,
        config.validator_count,
    )?;

    let mut threshold_attempts = Vec::new();
    let mut centralized_attempts = Vec::new();
    let mut predicate_mismatches = Vec::new();
    let mut accepted_signature: Option<[u8; 3309]> = None;
    let mut saw_threshold_rejected = false;
    let mut saw_threshold_accepted = false;

    for attempt_id in 0..config.attempts {
        let threshold_attempt = derive_threshold_attempt(
            &shares,
            config.threshold,
            config.validator_count,
            mu,
            original_secret.as_bytes(),
            &central_rnd,
            attempt_id,
            config.aligned_mask_domain,
        )?;
        let centralized_attempt =
            derive_centralized_attempt(original_secret.as_bytes(), &mu, &central_rnd, attempt_id)?;

        if threshold_attempt.accepted {
            saw_threshold_accepted = true;
        } else {
            saw_threshold_rejected = true;
        }

        compare_attempts(attempt_id, &threshold_attempt, &centralized_attempt, &mut predicate_mismatches);
        if accepted_signature.is_none() {
            accepted_signature = threshold_attempt.signature;
        }

        threshold_attempts.push(threshold_attempt.into_json());
        centralized_attempts.push(centralized_attempt.into_json());
    }

    let mut standard_verifier_accepts = false;
    let mut repo_provider_accepts = false;
    if let Some(signature) = accepted_signature {
        let backend_public_key = BackendPublicKey(public_key);
        let backend_signature = BackendSignature(signature);
        standard_verifier_accepts =
            verify_mldsa65_external_pure(&backend_public_key, message, &[], &backend_signature)?;

        let repo_public_key = ThresholdPublicKey(public_key);
        let repo_signature = ThresholdSignature(signature);
        repo_provider_accepts = HazmatMldsa65Provider::verify(&repo_public_key, message, &repo_signature)?;
    }

    let close_candidate = predicate_mismatches.is_empty()
        && saw_threshold_rejected
        && saw_threshold_accepted
        && standard_verifier_accepts
        && repo_provider_accepts;

    let result = json!({
        "attempts_compared": config.attempts,
        "predicate_mismatch_count": predicate_mismatches.len(),
        "challenge_digest_mismatch_count": predicate_mismatches.iter().filter(|item| item["field"] == "challenge_digest_hex").count(),
        "accepted_outcome_mismatch_count": predicate_mismatches.iter().filter(|item| item["field"] == "accepted_or_rejected").count(),
        "challenge_digest_matches": !predicate_mismatches.iter().any(|item| item["field"] == "challenge_digest_hex"),
        "accepted_or_rejected_matches": !predicate_mismatches.iter().any(|item| item["field"] == "accepted_or_rejected"),
        "saw_threshold_rejected_attempt": saw_threshold_rejected,
        "saw_threshold_accepted_attempt": saw_threshold_accepted,
        "standard_verifier_accepts_threshold_signature": standard_verifier_accepts,
        "repo_provider_accepts_threshold_signature": repo_provider_accepts,
        "close_candidate": close_candidate
    });

    let artifact = json!({
        "name": "p1-hazmat-rejection-equivalence-batch-v1",
        "schema": SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "backend_evidence": BACKEND_EVIDENCE,
        "note": "Hazmat centralized-vs-threshold ML-DSA-65 rejection-predicate comparator; conformance/proof-review evidence only, not theorem closure.",
        "parameters": {
            "validator_count": config.validator_count,
            "threshold": config.threshold,
            "attempts": config.attempts,
            "aligned_mask_domain": config.aligned_mask_domain,
            "mask_domain": if config.aligned_mask_domain { "centralized-rho-double-prime-kappa" } else { "threshold-share-derived-mask-seed" },
            "message_digest_hex": sha256_hex(message),
            "public_key_digest_hex": sha256_hex(&public_key),
            "centralized_rnd_digest_hex": sha256_hex(&central_rnd)
        },
        "result": result,
        "threshold_attempts": threshold_attempts,
        "centralized_attempts": centralized_attempts,
        "predicate_mismatches": predicate_mismatches,
        "claim_flags": {
            "claims_rejection_distribution_preservation": false,
            "claims_theorem_closure": false,
            "close_candidate_requires_external_review": close_candidate
        },
        "artifact_digest_hex": sha256_hex(
            json!({
                "schema": SCHEMA,
                "parameters": {
                    "validator_count": config.validator_count,
                    "threshold": config.threshold,
                    "attempts": config.attempts,
                    "aligned_mask_domain": config.aligned_mask_domain,
                    "mask_domain": if config.aligned_mask_domain { "centralized-rho-double-prime-kappa" } else { "threshold-share-derived-mask-seed" },
                    "message_digest_hex": sha256_hex(message),
                    "public_key_digest_hex": sha256_hex(&public_key)
                },
                "predicate_mismatches": predicate_mismatches
            }).to_string().as_bytes()
        )
    });

    println!("{}", serde_json::to_string_pretty(&artifact)?);
    Ok(())
}

fn parse_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config {
        validator_count: 5,
        threshold: 3,
        attempts: 16,
        aligned_mask_domain: false,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--validator-count" => {
                config.validator_count = args.next().ok_or("missing --validator-count value")?.parse()?;
            }
            "--threshold" => {
                config.threshold = args.next().ok_or("missing --threshold value")?.parse()?;
            }
            "--attempts" => {
                config.attempts = args.next().ok_or("missing --attempts value")?.parse()?;
            }
            "--aligned-mask-domain" => {
                config.aligned_mask_domain = true;
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    if config.threshold == 0 || config.threshold > config.validator_count {
        return Err("invalid threshold shape".into());
    }
    if config.attempts == 0 {
        return Err("attempts must be nonzero".into());
    }
    Ok(config)
}

struct AttemptRecord {
    attempt_id: u8,
    mask_seed_digest_hex: String,
    challenge_digest_hex: String,
    z_bound_result: bool,
    r0_bound_result: bool,
    ct0_bound_result: bool,
    hint_bound_result: bool,
    accepted: bool,
    signature: Option<[u8; 3309]>,
}

impl AttemptRecord {
    fn into_json(self) -> Value {
        json!({
            "attempt_id": self.attempt_id,
            "mask_seed_digest_hex": self.mask_seed_digest_hex,
            "challenge_digest_hex": self.challenge_digest_hex,
            "z_bound_result": self.z_bound_result,
            "r0_bound_result": self.r0_bound_result,
            "ct0_bound_result": self.ct0_bound_result,
            "hint_bound_result": self.hint_bound_result,
            "accepted_or_rejected": if self.accepted { "accepted" } else { "rejected" },
            "signature_digest_hex": self.signature.map(|signature| sha256_hex(&signature))
        })
    }
}

fn derive_threshold_attempt(
    shares: &[dytallix_pq_threshold::mldsa65::Mldsa65ExpandedSecretKeyShare],
    threshold: u16,
    validator_count: u16,
    mu: [u8; MLDSA65_MU_BYTES],
    secret_key: &[u8],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    attempt_id: u8,
    aligned_mask_domain: bool,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let mut session = begin_mldsa65_threshold_attempt(threshold, validator_count, mu)?;
    let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
    for (round, share) in shares.iter().take(threshold as usize).enumerate() {
        let contribution = if aligned_mask_domain {
            derive_mldsa65_centralized_domain_masking_contribution_from_share(
                secret_key,
                share,
                round as u16,
                &mu,
                rnd,
                u16::from(attempt_id),
            )?
        } else {
            derive_mldsa65_masking_contribution_from_share(share, &masking_seed, round as u16)?
        };
        submit_mldsa65_masking_contribution(&mut session, contribution)?;
    }
    let challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)?;
    for share in shares.iter().take(threshold as usize) {
        let contribution = derive_mldsa65_secret_contribution_from_share(share, &challenge)?;
        submit_mldsa65_secret_contribution(&mut session, contribution)?;
    }
    let predicate = derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met(&session)?;
    let signature = match finalize_mldsa65_session_signature_once_quorum_met(&mut session) {
        Ok(signature) => {
            if !predicate.accepted() {
                return Err("threshold predicate rejected accepted finalization".into());
            }
            Some(*signature.as_bytes())
        }
        Err(BackendThresholdError::RejectionSamplingFailed { .. }) => {
            if predicate.accepted() {
                return Err("threshold predicate accepted rejected finalization".into());
            }
            None
        }
        Err(err) => return Err(err.into()),
    };

    Ok(AttemptRecord {
        attempt_id,
        mask_seed_digest_hex: sha256_hex(&masking_seed),
        challenge_digest_hex: hex_encode(predicate.challenge_digest()),
        z_bound_result: predicate.z_bound_result(),
        r0_bound_result: predicate.r0_bound_result(),
        ct0_bound_result: predicate.ct0_bound_result(),
        hint_bound_result: predicate.hint_bound_result(),
        accepted: predicate.accepted(),
        signature,
    })
}

fn derive_centralized_attempt(
    secret_key: &[u8],
    mu: &[u8; MLDSA65_MU_BYTES],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    attempt_id: u8,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let predicate = derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key(
        secret_key,
        mu,
        rnd,
        u16::from(attempt_id),
    )?;

    Ok(AttemptRecord {
        attempt_id,
        mask_seed_digest_hex: sha256_hex(rnd),
        challenge_digest_hex: hex_encode(predicate.challenge_digest()),
        z_bound_result: predicate.z_bound_result(),
        r0_bound_result: predicate.r0_bound_result(),
        ct0_bound_result: predicate.ct0_bound_result(),
        hint_bound_result: predicate.hint_bound_result(),
        accepted: predicate.accepted(),
        signature: None,
    })
}

fn compare_attempts(
    attempt_id: u8,
    threshold: &AttemptRecord,
    centralized: &AttemptRecord,
    predicate_mismatches: &mut Vec<Value>,
) {
    compare_field(
        attempt_id,
        "challenge_digest_hex",
        &threshold.challenge_digest_hex,
        &centralized.challenge_digest_hex,
        predicate_mismatches,
    );
    compare_field(
        attempt_id,
        "z_bound_result",
        threshold.z_bound_result,
        centralized.z_bound_result,
        predicate_mismatches,
    );
    compare_field(
        attempt_id,
        "r0_bound_result",
        threshold.r0_bound_result,
        centralized.r0_bound_result,
        predicate_mismatches,
    );
    compare_field(
        attempt_id,
        "ct0_bound_result",
        threshold.ct0_bound_result,
        centralized.ct0_bound_result,
        predicate_mismatches,
    );
    compare_field(
        attempt_id,
        "hint_bound_result",
        threshold.hint_bound_result,
        centralized.hint_bound_result,
        predicate_mismatches,
    );
    compare_field(
        attempt_id,
        "accepted_or_rejected",
        if threshold.accepted { "accepted" } else { "rejected" },
        if centralized.accepted { "accepted" } else { "rejected" },
        predicate_mismatches,
    );
}

fn compare_field<T: PartialEq + std::fmt::Debug>(
    attempt_id: u8,
    field: &str,
    threshold_value: T,
    centralized_value: T,
    predicate_mismatches: &mut Vec<Value>,
) {
    if threshold_value != centralized_value {
        predicate_mismatches.push(json!({
            "attempt_id": attempt_id,
            "field": field,
            "threshold_value": format!("{threshold_value:?}"),
            "centralized_value": format!("{centralized_value:?}")
        }));
    }
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
    """Write the temporary Rust emitter project for one comparator batch."""
    work_dir = Path(work_dir)
    repo_root = validate_crate_path(repo_root, "repo root")
    backend_crate = validate_crate_path(backend_crate, "backend crate")
    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    cargo_toml = "\n".join(
        [
            "[package]",
            'name = "lattice-hazmat-rejection-equivalence-emitter"',
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
            'serde_json = "1"',
            'sha2 = "0.10"',
            'sha3 = "0.10"',
            "",
        ]
    )
    (work_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    (src_dir / "main.rs").write_text(RUST_EMITTER_SOURCE, encoding="utf-8")


def cargo_command(release=True, emitter_args=None):
    """Build the cargo command for the generated emitter."""
    command = ["cargo", "run"]
    if release:
        command.append("--release")
    if emitter_args:
        command.append("--")
        command.extend(emitter_args)
    return command


def run_batch(
    repo_root,
    backend_crate,
    work_dir,
    command_runner=subprocess.run,
    release=True,
    emitter_args=None,
):
    """Build and run the generated comparator, returning JSON stdout."""
    write_emitter_project(work_dir, repo_root, backend_crate)
    completed = command_runner(
        cargo_command(release=release, emitter_args=emitter_args),
        cwd=Path(work_dir),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "hazmat rejection-equivalence emitter failed\n" + (completed.stderr or "")
        )
    return completed.stdout


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Generate a hazmat centralized-vs-threshold ML-DSA rejection "
            "predicate comparison batch."
        )
    )
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
    parser.add_argument("--validator-count", type=int, help="validator universe size")
    parser.add_argument("--threshold", type=int, help="threshold signer count")
    parser.add_argument("--attempts", type=int, help="attempts to compare")
    parser.add_argument(
        "--aligned-mask-domain",
        action="store_true",
        help="derive threshold masking contributions from the centralized ML-DSA rho''/kappa mask domain",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="run cargo without --release for adapter debugging",
    )
    return parser.parse_args(argv)


def emitter_args_from_options(args):
    emitter_args = []
    if args.validator_count is not None:
        emitter_args.extend(["--validator-count", str(args.validator_count)])
    if args.threshold is not None:
        emitter_args.extend(["--threshold", str(args.threshold)])
    if args.attempts is not None:
        emitter_args.extend(["--attempts", str(args.attempts)])
    if args.aligned_mask_domain:
        emitter_args.append("--aligned-mask-domain")
    return emitter_args


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if not args.backend_crate:
        raise SystemExit(
            "--backend-crate or LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE is required"
        )
    emitter_args = emitter_args_from_options(args)
    if args.work_dir:
        stdout = run_batch(
            repo_root=args.repo_root,
            backend_crate=args.backend_crate,
            work_dir=args.work_dir,
            release=not args.debug,
            emitter_args=emitter_args,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="lattice-rejection-equivalence-") as temp_dir:
            stdout = run_batch(
                repo_root=args.repo_root,
                backend_crate=args.backend_crate,
                work_dir=Path(temp_dir) / "emitter",
                release=not args.debug,
                emitter_args=emitter_args,
            )
    sys.stdout.write(stdout)


if __name__ == "__main__":
    main()
