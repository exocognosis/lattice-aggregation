#!/usr/bin/env python3
"""Run the Batch 8 external-backend evidence closure-candidate attempt."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-external-backend-evidence-attempt:v1"
NAME = "p1-external-backend-evidence-attempt-v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
REVIEW_PACKAGE_SCHEMA = "lattice-aggregation:p1-external-backend-evidence-package-review:v1"
REVIEW_STATUS_READY = "reviewed_external_backend_evidence_ready"
REVIEW_SOURCE_ORIGIN = "outside_repo_review_manifest"
REVIEW_SOURCE_PROFILE = "admissible_external_backend_capture"
STATUS_READY = "external_evidence_close_candidate_ready"
STATUS_BLOCKED = "blocked_external_evidence_missing"
FORBIDDEN_SOURCE_MARKERS = (
    "hazmat",
    "simulation",
    "simulated",
    "deterministic",
    "localnet",
    "fixture",
    "test-vector",
    "test_vector",
    "single-key",
    "single_key",
    "standardprovidersinglekey",
    "standard_provider_single_key",
    "repo_reference_cli_capture",
    "quarantined_local_schema_replay",
    "centralized-oracle",
    "centralized oracle",
)
REQUIRED_CANDIDATE_CHECK_KEYS = (
    "strict_external_nonce_capture_ready",
    "real_threshold_emission_present",
    "standard_verifier_acceptance_present",
    "mutation_rejection_complete",
    "rejection_distribution_comparison_present",
    "comparison_close_candidate",
)
REQUIRED_REVIEW_DIGEST_KEYS = (
    "external_review_digest_hex",
    "reviewer_identity_digest_hex",
    "operator_identity_digest_hex",
    "external_source_package_digest_hex",
    "capture_environment_digest_hex",
    "backend_command_digest_hex",
)
REQUIRED_REVIEW_SOURCE_EXCLUSIONS = (
    "hazmat_prf_oracle",
    "centralized_expanded_secret_key_helper",
    "fixture_harness",
    "localnet_or_deterministic_simulation",
    "single_key_standard_provider_output",
)
REQUIRED_REVIEW_CLAIM_FLAGS = (
    "claims_theorem_closure",
    "claims_rejection_distribution_preservation",
    "claims_selected_backend_proof_closure",
    "claims_production_threshold_mldsa_security",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)


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
    """Load JSON from a path if present."""
    path = Path(path)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def is_nonzero_hex_digest(value):
    """Return true for a nonzero 32-byte hex digest string."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return raw != b"\x00" * 32


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def default_nonce_gate(root):
    return (
        Path(root)
        / "artifacts"
        / "nonce-producer-actual-external-gate"
        / "latest"
        / "manifest.json"
    )


def default_backend_manifest(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "capture.json"


def default_rejection_batch(root):
    return Path(root) / "artifacts" / "p1-rejection-equivalence-batch" / "latest" / "batch.json"


def default_candidate_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-cryptographic-closure-candidate"
        / "latest"
    )


def default_review_package(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-evidence-package-review"
        / "latest"
        / "manifest.json"
    )


def load_closure_candidate_builder():
    """Load the Batch 7 closure-candidate builder beside this script."""
    script = Path(__file__).resolve().parent / (
        "build_p1_external_backend_cryptographic_closure_candidate.py"
    )
    spec = importlib.util.spec_from_file_location(
        "build_p1_external_backend_cryptographic_closure_candidate",
        script,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_marker_blockers(*documents):
    """Return blockers for hazmat/simulation/local fixture source markers."""
    blockers = []
    for label, document in documents:
        if document is None:
            continue
        for value in string_values(document):
            lowered = value.lower()
            for marker in FORBIDDEN_SOURCE_MARKERS:
                if marker in lowered:
                    blockers.append(
                        f"forbidden external-evidence source marker in {label}: {marker}"
                    )
    return blockers


def string_values(value):
    """Yield only JSON string values, not field names, for source-marker checks."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from string_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from string_values(item)


def review_package_expected_input_sha256s(
    nonce_gate_path,
    backend_manifest_path,
    backend_capture_path,
    rejection_batch_path,
    candidate_digest_sha256,
):
    """Build the input digest map a reviewed external evidence package must bind."""
    return {
        "actual_external_nonce_gate_manifest": sha256_path(nonce_gate_path),
        "real_threshold_backend_capture_manifest": sha256_path(backend_manifest_path),
        "real_threshold_backend_capture_json": sha256_path(backend_capture_path),
        "rejection_equivalence_batch_json": sha256_path(rejection_batch_path),
        "candidate_digest_sha256": candidate_digest_sha256,
    }


def review_package_checks(review_package, expected_input_sha256s, blockers):
    """Validate the independently reviewed external evidence package."""
    present = isinstance(review_package, dict)
    if not present:
        blockers.append("reviewed external evidence package is missing")
        return {
            "review_package_present": False,
            "review_package_binds_inputs": False,
            "review_package_claim_boundary_passed": False,
            "review_package_source_exclusions_passed": False,
            "review_package_review_digests_present": False,
        }

    input_sha256s = review_package.get("input_sha256s")
    review_digests = review_package.get("review_digests")
    source_exclusions = review_package.get("source_exclusions")
    claim_flags = review_package.get("claim_flags")
    boundary_passed = (
        review_package.get("schema") == REVIEW_PACKAGE_SCHEMA
        and review_package.get("claim_boundary") == CLAIM_BOUNDARY
        and review_package.get("selected_profile") == SELECTED_PROFILE
        and review_package.get("review_status") == REVIEW_STATUS_READY
        and review_package.get("source_origin") == REVIEW_SOURCE_ORIGIN
        and review_package.get("package_source_profile") == REVIEW_SOURCE_PROFILE
        and isinstance(claim_flags, dict)
        and all(claim_flags.get(flag) is False for flag in REQUIRED_REVIEW_CLAIM_FLAGS)
    )
    binds_inputs = isinstance(input_sha256s, dict) and all(
        input_sha256s.get(key) == value
        for key, value in expected_input_sha256s.items()
        if value is not None
    )
    binds_inputs = binds_inputs and all(
        input_sha256s.get(key) is not None for key in expected_input_sha256s
    )
    source_exclusions_passed = isinstance(source_exclusions, dict) and all(
        source_exclusions.get(key) is False for key in REQUIRED_REVIEW_SOURCE_EXCLUSIONS
    )
    review_digests_present = isinstance(review_digests, dict) and all(
        is_nonzero_hex_digest(review_digests.get(key))
        for key in REQUIRED_REVIEW_DIGEST_KEYS
    )

    if not boundary_passed:
        blockers.append("reviewed external evidence package boundary is invalid")
    if not binds_inputs:
        blockers.append("review package input digest mismatch")
    if not source_exclusions_passed:
        blockers.append("review package source exclusions failed")
    if not review_digests_present:
        blockers.append("review package digests are incomplete")

    return {
        "review_package_present": True,
        "review_package_binds_inputs": binds_inputs,
        "review_package_claim_boundary_passed": boundary_passed,
        "review_package_source_exclusions_passed": source_exclusions_passed,
        "review_package_review_digests_present": review_digests_present,
    }


def build_report(
    root,
    nonce_gate_path=None,
    backend_manifest_path=None,
    backend_capture_path=None,
    rejection_batch_path=None,
    review_package_path=None,
    candidate_out=None,
    generated_at=None,
):
    """Build the Batch 8 external evidence attempt report."""
    root = Path(root)
    nonce_gate_path = Path(nonce_gate_path or default_nonce_gate(root))
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    review_package_path = Path(review_package_path or default_review_package(root))
    candidate_out = Path(candidate_out or default_candidate_out(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    nonce_gate = load_json_if_present(nonce_gate_path)
    backend_manifest = load_json_if_present(backend_manifest_path)
    backend_capture = load_json_if_present(backend_capture_path)
    rejection_batch = load_json_if_present(rejection_batch_path)
    review_package = load_json_if_present(review_package_path)

    candidate_builder = load_closure_candidate_builder()
    candidate_report = candidate_builder.build_report(
        root,
        nonce_gate_path=nonce_gate_path,
        backend_manifest_path=backend_manifest_path,
        backend_capture_path=backend_capture_path,
        rejection_batch_path=rejection_batch_path,
        generated_at=generated_at,
    )
    candidate_builder.write_artifacts(candidate_report, candidate_out)
    candidate_manifest = candidate_report["manifest"]

    source_blockers = source_marker_blockers(
        ("actual external nonce gate", nonce_gate),
        ("real-threshold backend manifest", backend_manifest),
        ("real-threshold backend capture", backend_capture),
        ("rejection-distribution batch", rejection_batch),
    )
    review_blockers = []
    review_checks = review_package_checks(
        review_package,
        review_package_expected_input_sha256s(
            nonce_gate_path,
            backend_manifest_path,
            backend_capture_path,
            rejection_batch_path,
            candidate_manifest.get("candidate_digest_sha256"),
        ),
        review_blockers,
    )
    missing_check_blockers = [
        f"closure candidate missing required check: {key}"
        for key in REQUIRED_CANDIDATE_CHECK_KEYS
        if key not in candidate_manifest["checks"]
    ]
    checks = {
        **{key: False for key in REQUIRED_CANDIDATE_CHECK_KEYS},
        **candidate_manifest["checks"],
        "source_exclusion_passed": not source_blockers,
        **review_checks,
    }
    blockers = list(
        dict.fromkeys(
            candidate_manifest["blockers"]
            + source_blockers
            + review_blockers
            + missing_check_blockers
        )
    )
    close_candidate = (
        bool(candidate_manifest["close_candidate"])
        and not source_blockers
        and all(review_checks.values())
        and not missing_check_blockers
    )
    claim_flags = {
        "claims_theorem_closure": False,
        "claims_rejection_distribution_preservation": False,
        "claims_selected_backend_proof_closure": False,
        "claims_standard_verifier_compatibility": False,
        "claims_production_threshold_mldsa_security": False,
        "claims_cavp_acvts_validation": False,
        "claims_fips_validation": False,
    }
    candidate_manifest_path = candidate_out / "manifest.json"
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "checks": checks,
        "close_candidate": close_candidate,
        "claim_flags": claim_flags,
        "inputs": {
            "actual_external_nonce_gate_manifest": input_record(nonce_gate_path),
            "real_threshold_backend_capture_manifest": input_record(backend_manifest_path),
            "real_threshold_backend_capture_json": input_record(backend_capture_path),
            "rejection_equivalence_batch_json": input_record(rejection_batch_path),
            "reviewed_external_evidence_package": input_record(review_package_path),
            "closure_candidate_manifest": input_record(candidate_manifest_path),
        },
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "attempt_status": STATUS_READY if close_candidate else STATUS_BLOCKED,
        "close_candidate": close_candidate,
        "checks": checks,
        "blockers": blockers,
        "inputs": digest_material["inputs"],
        "candidate_manifest_path": str(candidate_manifest_path),
        "candidate_manifest_sha256": sha256_path(candidate_manifest_path),
        "review_package_path": str(review_package_path),
        "review_package_sha256": sha256_path(review_package_path),
        "candidate_digest_sha256": candidate_manifest.get("candidate_digest_sha256"),
        "attempt_digest_sha256": sha256_text(canonical_json(digest_material)),
        **claim_flags,
        "closure_boundary": (
            "Batch 8 external evidence attempt only; not theorem closure, not "
            "rejection-distribution preservation, and not selected-backend proof closure."
        ),
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def render_summary(manifest):
    """Render a concise Batch 8 attempt summary."""
    lines = [
        "# P1 External Backend Evidence Attempt",
        "",
        "This artifact groups the actual external nonce gate, real-threshold backend "
        "emission capture, standard-verifier acceptance evidence, mutation rejection "
        "evidence, rejection-distribution comparison, and independently reviewed "
        "external evidence package into the Batch 7 closure-candidate gate.",
        "",
        f"- Status: `{manifest['attempt_status']}`",
        f"- Close candidate: `{str(manifest['close_candidate']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Candidate manifest SHA-256: `{manifest['candidate_manifest_sha256']}`",
        f"- Review package SHA-256: `{manifest['review_package_sha256']}`",
        f"- Attempt digest SHA-256: `{manifest['attempt_digest_sha256']}`",
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
            "This is not theorem closure. It does not prove Criterion 2, "
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
    """Write Batch 8 attempt artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run the P1 external-backend evidence closure-candidate attempt"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--nonce-gate", default=None, help="actual external nonce gate")
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
        "--review-package",
        default=None,
        help="reviewed external evidence package manifest",
    )
    parser.add_argument(
        "--candidate-out",
        default=None,
        help="Batch 7 closure-candidate output directory",
    )
    parser.add_argument(
        "--out",
        default="artifacts/p1-external-backend-evidence-attempt/latest",
        help="Batch 8 attempt output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero until the grouped external evidence attempt is a close candidate",
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
        review_package_path=args.review_package,
        candidate_out=args.candidate_out,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote P1 external backend evidence attempt artifacts to {args.out}")
    if args.strict and not report["manifest"]["close_candidate"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
