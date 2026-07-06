#!/usr/bin/env python3
"""Build the P1 external-backend cryptographic closure-candidate artifact."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1"
NAME = "p1-external-backend-cryptographic-closure-candidate-v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
STATUS = "evidence_present_unclosed"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
NONCE_GATE_SCHEMA = "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1"
NONCE_GATE_READY = "actual_external_capture_ready"
EXPECTED_NONCE_SOURCE_PROFILE = "admissible_external_backend_capture"
BACKEND_CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
BACKEND_REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
BACKEND_EVIDENCE = "real_threshold_mldsa_external_capture"
REJECTION_BATCH_SCHEMA = "lattice-aggregation:p1-rejection-equivalence-batch:v1"
REJECTION_BATCH_NONCE_PRODUCER = "distributed-nonce-prf-output-shares"
MLDSA65_SIGNATURE_BYTES = 3309
SMOKE_CORE_MODES = {
    "centralized_mldsa65_provider_with_threshold_evidence_envelope",
}
SMOKE_SIGNATURE_ORIGINS = {
    "single_seed_standard_mldsa65_provider",
}


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return SHA-256 for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    """Return SHA-256 for a file path, or None when absent."""
    path = Path(path)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json_if_present(path):
    """Load JSON if present; otherwise return None."""
    path = Path(path)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def is_nonzero_hex_digest(value):
    """Return true for a nonzero 32-byte hex digest string."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return raw != b"\x00" * 32


def nonce_gate_ready(nonce_gate, blockers):
    """Check the strict actual external nonce-producer gate."""
    ready = (
        isinstance(nonce_gate, dict)
        and nonce_gate.get("schema") == NONCE_GATE_SCHEMA
        and nonce_gate.get("claim_boundary") == CLAIM_BOUNDARY
        and nonce_gate.get("gate_status") == NONCE_GATE_READY
        and nonce_gate.get("actual_external_capture_ready") is True
        and nonce_gate.get("expected_source_profile") == EXPECTED_NONCE_SOURCE_PROFILE
        and nonce_gate.get("attempt_source_profile") == EXPECTED_NONCE_SOURCE_PROFILE
        and nonce_gate.get("handoff_source_profile") == EXPECTED_NONCE_SOURCE_PROFILE
    )
    if not ready:
        blockers.append("actual external nonce capture readiness required")
    return ready


def backend_core_admissible(backend_manifest, backend_capture, blockers):
    """Reject centralized/single-key smoke captures from the strict core path."""
    admissible = True
    manifest_admissibility = (
        backend_manifest.get("backend_core_admissibility")
        if isinstance(backend_manifest, dict)
        else None
    )
    cryptographic_core = (
        backend_capture.get("cryptographic_core")
        if isinstance(backend_capture, dict)
        else None
    )
    if isinstance(manifest_admissibility, dict):
        if manifest_admissibility.get("strict_threshold_core_admissible") is not True:
            blockers.append(
                "backend capture is quarantined from strict threshold-core closure"
            )
            admissible = False
    if not isinstance(cryptographic_core, dict):
        blockers.append("backend capture is missing cryptographic core accounting")
        return False
    core_mode = cryptographic_core.get("core_mode")
    signature_origin = cryptographic_core.get("signature_origin")
    distributed_core = cryptographic_core.get("distributed_threshold_core")
    if core_mode in SMOKE_CORE_MODES or signature_origin in SMOKE_SIGNATURE_ORIGINS:
        blockers.append(
            "centralized/single-seed smoke capture cannot satisfy real threshold emission"
        )
        admissible = False
    if not isinstance(distributed_core, dict):
        blockers.append("backend capture is missing distributed threshold core status")
        return False
    required_flags = (
        "distributed_keygen_vss",
        "partial_signing_over_secret_shares",
        "partial_z_i_hint_aggregation",
        "fips204_rejection_loop_over_threshold_partials",
    )
    missing = [flag for flag in required_flags if distributed_core.get(flag) is not True]
    if missing:
        blockers.append(
            "backend capture lacks strict threshold core evidence: " + ", ".join(missing)
        )
        admissible = False
    return admissible


def backend_capture_present(backend_manifest, backend_capture, blockers):
    """Check actual real-threshold backend emission capture evidence."""
    if not isinstance(backend_manifest, dict) or not isinstance(backend_capture, dict):
        blockers.append("real threshold backend emission capture is missing")
        return False
    manifest_ready = (
        backend_manifest.get("claim_boundary") == CLAIM_BOUNDARY
        and backend_manifest.get("runner_status") == STATUS
        and backend_manifest.get("capture_schema") == BACKEND_CAPTURE_SCHEMA
        and backend_manifest.get("request_schema") == BACKEND_REQUEST_SCHEMA
        and backend_manifest.get("backend_evidence") == BACKEND_EVIDENCE
        and backend_manifest.get("exit_code") in (0, None)
        and backend_manifest.get("validator_count") == 10000
        and backend_manifest.get("threshold") == 6667
        and backend_manifest.get("aggregate_signature_len") == MLDSA65_SIGNATURE_BYTES
    )
    capture_payload = backend_capture.get("capture") if isinstance(backend_capture, dict) else {}
    capture_ready = (
        backend_capture.get("schema") == BACKEND_CAPTURE_SCHEMA
        and backend_capture.get("claim_boundary") == CLAIM_BOUNDARY
        and backend_capture.get("selected_profile") == SELECTED_PROFILE
        and backend_capture.get("backend_evidence") == BACKEND_EVIDENCE
        and isinstance(backend_capture.get("request"), dict)
        and backend_capture["request"].get("schema") == BACKEND_REQUEST_SCHEMA
        and isinstance(capture_payload, dict)
        and capture_payload.get("validator_count") == 10000
        and capture_payload.get("threshold") == 6667
        and capture_payload.get("aggregate_signature_len") == MLDSA65_SIGNATURE_BYTES
        and capture_payload.get("reviewed") is True
    )
    core_ready = backend_core_admissible(backend_manifest, backend_capture, blockers)
    ready = manifest_ready and capture_ready and core_ready
    if not ready:
        blockers.append("real threshold backend emission capture is incomplete")
    return ready


def standard_verifier_acceptance_present(backend_capture, blockers):
    """Check for request-bound standard-size verifier acceptance evidence."""
    expected = backend_capture.get("expected") if isinstance(backend_capture, dict) else {}
    payload = backend_capture.get("capture") if isinstance(backend_capture, dict) else {}
    present = (
        isinstance(expected, dict)
        and isinstance(payload, dict)
        and payload.get("aggregate_signature_len") == MLDSA65_SIGNATURE_BYTES
        and payload.get("reviewed") is True
        and is_nonzero_hex_digest(expected.get("artifact_digest_hex"))
        and is_nonzero_hex_digest(expected.get("public_key_digest_hex"))
        and is_nonzero_hex_digest(expected.get("message_digest_hex"))
        and is_nonzero_hex_digest(expected.get("accepted_signature_digest_hex"))
    )
    if not present:
        blockers.append("standard-verifier acceptance evidence is missing")
    return present


def mutation_rejection_complete(backend_capture, blockers):
    """Check mutated message/public-key/signature rejection evidence."""
    payload = backend_capture.get("capture") if isinstance(backend_capture, dict) else {}
    complete = (
        isinstance(payload, dict)
        and payload.get("mutated_message_rejected") is True
        and payload.get("mutated_public_key_rejected") is True
        and payload.get("mutated_signature_rejected") is True
    )
    if not complete:
        blockers.append("mutation rejection evidence is incomplete")
    return complete


def rejection_distribution_present(rejection_batch, blockers):
    """Check the rejection-distribution comparison artifact shape."""
    if not isinstance(rejection_batch, dict):
        blockers.append("rejection-distribution comparison is missing")
        return False
    result = rejection_batch.get("result")
    parameters = rejection_batch.get("parameters")
    claim_flags = rejection_batch.get("claim_flags", {})
    present = (
        rejection_batch.get("schema") == REJECTION_BATCH_SCHEMA
        and rejection_batch.get("claim_boundary") == CLAIM_BOUNDARY
        and rejection_batch.get("selected_profile") == SELECTED_PROFILE
        and isinstance(parameters, dict)
        and parameters.get("validator_count") == 10000
        and parameters.get("threshold") == 6667
        and parameters.get("nonce_prf_producer") == REJECTION_BATCH_NONCE_PRODUCER
        and parameters.get("reviewed_distributed_nonce_producer_present") is True
        and is_nonzero_hex_digest(parameters.get("distributed_nonce_producer_artifact_digest"))
        and isinstance(result, dict)
        and result.get("predicate_mismatch_count") == 0
        and result.get("challenge_digest_matches") is True
        and result.get("accepted_or_rejected_matches") is True
        and result.get("saw_threshold_rejected_attempt") is True
        and result.get("saw_threshold_accepted_attempt") is True
        and result.get("standard_verifier_accepts_threshold_signature") is True
        and result.get("repo_provider_accepts_threshold_signature") is True
        and claim_flags.get("claims_theorem_closure") is False
        and claim_flags.get("claims_rejection_distribution_preservation") is False
    )
    if not present:
        blockers.append("rejection-distribution comparison is incomplete")
    return present


def rejection_distribution_close_candidate(rejection_batch, blockers):
    """Check the comparison's own close-candidate flag."""
    result = rejection_batch.get("result") if isinstance(rejection_batch, dict) else {}
    close = isinstance(result, dict) and result.get("close_candidate") is True
    if not close:
        blockers.append("rejection-distribution comparison requires close-candidate evidence")
    return close


def build_report(
    root,
    nonce_gate_path=None,
    backend_manifest_path=None,
    backend_capture_path=None,
    rejection_batch_path=None,
    generated_at=None,
):
    """Build the Batch 7 closure-candidate report from existing artifacts."""
    root = Path(root)
    nonce_gate_path = Path(
        nonce_gate_path
        or root / "artifacts" / "nonce-producer-actual-external-gate" / "latest" / "manifest.json"
    )
    backend_manifest_path = Path(
        backend_manifest_path
        or root / "artifacts" / "backend-emission-capture" / "latest" / "manifest.json"
    )
    backend_capture_path = Path(
        backend_capture_path
        or root / "artifacts" / "backend-emission-capture" / "latest" / "capture.json"
    )
    rejection_batch_path = Path(
        rejection_batch_path
        or root / "artifacts" / "p1-rejection-equivalence-batch" / "latest" / "batch.json"
    )
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    nonce_gate = load_json_if_present(nonce_gate_path)
    backend_manifest = load_json_if_present(backend_manifest_path)
    backend_capture = load_json_if_present(backend_capture_path)
    rejection_batch = load_json_if_present(rejection_batch_path)
    blockers = []

    checks = {
        "strict_external_nonce_capture_ready": nonce_gate_ready(nonce_gate, blockers),
        "real_threshold_emission_present": backend_capture_present(
            backend_manifest,
            backend_capture,
            blockers,
        ),
        "standard_verifier_acceptance_present": standard_verifier_acceptance_present(
            backend_capture or {},
            blockers,
        ),
        "mutation_rejection_complete": mutation_rejection_complete(
            backend_capture or {},
            blockers,
        ),
        "rejection_distribution_comparison_present": rejection_distribution_present(
            rejection_batch,
            blockers,
        ),
        "comparison_close_candidate": rejection_distribution_close_candidate(
            rejection_batch or {},
            blockers,
        ),
    }
    claim_flags = {
        "claims_theorem_closure": False,
        "claims_rejection_distribution_preservation": False,
        "claims_selected_backend_proof_closure": False,
        "claims_standard_verifier_compatibility": False,
        "claims_production_threshold_mldsa_security": False,
        "claims_cavp_acvts_validation": False,
        "claims_fips_validation": False,
    }
    close_candidate = all(checks.values()) and not any(claim_flags.values())
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "checks": checks,
        "inputs": {
            "actual_external_nonce_gate_manifest": input_record(nonce_gate_path),
            "real_threshold_backend_capture_manifest": input_record(backend_manifest_path),
            "real_threshold_backend_capture_json": input_record(backend_capture_path),
            "rejection_equivalence_batch_json": input_record(rejection_batch_path),
        },
        "close_candidate": close_candidate,
        "claim_flags": claim_flags,
    }

    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "status": STATUS,
        "close_candidate": close_candidate,
        "checks": checks,
        "blockers": blockers,
        "inputs": digest_material["inputs"],
        "candidate_digest_sha256": sha256_text(canonical_json(digest_material)),
        **claim_flags,
        "closure_boundary": (
            "External-backend cryptographic closure-candidate artifact only; "
            "pending theorem-closure review, requires rejection-distribution preservation proof, and "
            "requires selected-backend proof closure evidence."
        ),
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def render_summary(manifest):
    """Render a concise closure-candidate summary."""
    lines = [
        "# P1 External Backend Cryptographic Closure Candidate",
        "",
        "This artifact composes the actual external nonce gate, real-threshold "
        "backend emission capture, standard-verifier evidence, and rejection "
        "comparison evidence for Batch 7.",
        "",
        f"- Status: `{manifest['status']}`",
        f"- Close candidate: `{str(manifest['close_candidate']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Candidate digest SHA-256: `{manifest['candidate_digest_sha256']}`",
        "",
        "Checks:",
    ]
    for name, passed in manifest["checks"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")
    if manifest["blockers"]:
        lines.extend(["", "Blockers:"])
        for blocker in manifest["blockers"]:
            lines.append(f"- {blocker}")
    lines.extend(
        [
            "",
            "This is pending theorem-closure review. It requires Criterion 2 proof review, "
            "rejection-distribution preservation, selected-backend proof "
            "closure, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or completed cryptographic proof.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    """Build final artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }


def render_checksums(contents):
    """Render deterministic SHA-256 checksums for artifact files."""
    return "\n".join(
        f"{sha256_text(contents[name])}  {name}" for name in sorted(contents)
    ) + "\n"


def write_artifacts(report, out_dir):
    """Write candidate artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build the P1 external-backend cryptographic closure-candidate artifact"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--nonce-gate",
        default=None,
        help="actual external nonce-producer gate manifest",
    )
    parser.add_argument(
        "--backend-manifest",
        default=None,
        help="real-threshold backend capture manifest",
    )
    parser.add_argument(
        "--backend-capture",
        default=None,
        help="real-threshold backend capture JSON",
    )
    parser.add_argument(
        "--rejection-batch",
        default=None,
        help="rejection-equivalence batch JSON",
    )
    parser.add_argument(
        "--out",
        default="artifacts/p1-external-backend-cryptographic-closure-candidate/latest",
        help="output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(
        Path(args.root),
        nonce_gate_path=args.nonce_gate,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        rejection_batch_path=args.rejection_batch,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote P1 external backend closure-candidate artifacts to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
