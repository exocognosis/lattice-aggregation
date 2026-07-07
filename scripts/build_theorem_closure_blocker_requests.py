#!/usr/bin/env python3
"""Build explicit request artifacts for the remaining theorem-closure blockers."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:theorem-closure-blocker-requests:v1"
NAME = "theorem-closure-blocker-requests-v1"
CLAIM_BOUNDARY = "readiness preflight only; pending external proof and validation"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
REQUEST_STATUS = "blocker_inputs_required"
REJECTION_PACKAGE_SCHEMA = (
    "lattice-aggregation:p1-rejection-distribution-preservation-review:v1"
)
REJECTION_PACKAGE_READY = "reviewed_rejection_distribution_preservation_ready"
VALIDATION_PACKAGE_SCHEMA = "lattice-aggregation:p1-full-kat-cavp-validation-review:v1"
VALIDATION_PACKAGE_READY = "reviewed_full_kat_cavp_validation_ready"

CLAIM_FLAG_KEYS = (
    "claims_theorem_closure",
    "claims_criterion_met",
    "claims_selected_backend_proof_closure",
    "claims_rejection_distribution_preservation",
    "claims_standard_verifier_compatibility_complete",
    "claims_production_threshold_mldsa_security",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)

REJECTION_DISTRIBUTION_PACKAGE_CHECKS = (
    "accepted_distribution_distance_bound_reviewed",
    "threshold_accepted_distribution_reviewed",
    "centralized_mldsa_reference_distribution_reviewed",
    "rejection_sampling_conditioning_reviewed",
    "selective_abort_withholding_bound_reviewed",
    "restart_leakage_bound_reviewed",
    "concurrency_model_reviewed",
    "concrete_loss_bound_nonvacuous",
    "binds_rejection_batch_digest",
    "binds_distribution_abort_review_digest",
    "external_reviewer_digest_present",
)

FULL_KAT_VALIDATION_PACKAGE_CHECKS = (
    "provider_kat_vectors_passed",
    "fips204_mldsa65_kat_passed",
    "acvts_or_cavp_campaign_reviewed",
    "signing_verification_vectors_reviewed",
    "mutation_negative_vectors_reviewed",
    "public_key_signature_length_vectors_reviewed",
    "implementation_digest_bound",
    "binds_backend_capture_digest",
    "binds_backend_manifest_digest",
    "external_reviewer_digest_present",
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


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def false_claim_flags():
    """Return all theorem/security claim flags pinned false."""
    return {key: False for key in CLAIM_FLAG_KEYS}


def default_rejection_batch(root):
    return Path(root) / "artifacts/p1-rejection-equivalence-batch/latest/batch.json"


def default_distribution_abort_review(root):
    return (
        Path(root)
        / "artifacts/p1-accepted-distribution-abort-review/latest/manifest.json"
    )


def default_backend_manifest(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/capture.json"


def default_criterion2_manifest(root):
    return Path(root) / "docs/cryptography/criterion-2-proof-substance.json"


def default_rejection_package(root):
    return (
        Path(root)
        / "artifacts/p1-rejection-distribution-preservation-review/latest/manifest.json"
    )


def default_validation_package(root):
    return Path(root) / "artifacts/p1-full-kat-cavp-validation-review/latest/manifest.json"


def default_out(root):
    return Path(root) / "artifacts/theorem-closure-blocker-requests/latest"


def package_status(path, missing_status):
    """Report whether a requested package already exists."""
    return "candidate_package_present_pending_review" if Path(path).is_file() else missing_status


def build_required_packages(
    rejection_batch_path,
    distribution_abort_review_path,
    backend_manifest_path,
    backend_capture_path,
    rejection_package_path,
    validation_package_path,
):
    """Build exact remaining proof/validation package requests."""
    rejection_batch_sha256 = sha256_path(rejection_batch_path)
    distribution_abort_sha256 = sha256_path(distribution_abort_review_path)
    backend_manifest_sha256 = sha256_path(backend_manifest_path)
    backend_capture_sha256 = sha256_path(backend_capture_path)
    return {
        "rejection_distribution_preservation_review": {
            "schema": REJECTION_PACKAGE_SCHEMA,
            "package_class": "rejection_distribution_preservation_review",
            "ready_status": REJECTION_PACKAGE_READY,
            "expected_path": str(default_rejection_package(".")),
            "current_status": package_status(
                rejection_package_path,
                "required_external_proof_unavailable",
            ),
            "satisfies_review_flag": "rejection_distribution_preservation_reviewed",
            "can_be_satisfied_from_current_repo": False,
            "required_checks": list(REJECTION_DISTRIBUTION_PACKAGE_CHECKS),
            "required_source_inputs": {
                "rejection_batch_sha256": rejection_batch_sha256,
                "accepted_distribution_abort_review_sha256": distribution_abort_sha256,
            },
            "required_claim_boundary": "conformance/proof-review evidence",
            "required_claim_flags": false_claim_flags(),
            "description": (
                "Externally reviewed proof package that bounds accepted threshold "
                "signature distribution against centralized ML-DSA behavior and "
                "covers selective abort, withholding, restart leakage, concurrency, "
                "and concrete loss terms."
            ),
        },
        "full_kat_cavp_validation_review": {
            "schema": VALIDATION_PACKAGE_SCHEMA,
            "package_class": "full_kat_cavp_validation_review",
            "ready_status": VALIDATION_PACKAGE_READY,
            "expected_path": str(default_validation_package(".")),
            "current_status": package_status(
                validation_package_path,
                "required_external_validation_unavailable",
            ),
            "satisfies_review_flag": "full_kat_validation_reviewed",
            "can_be_satisfied_from_current_repo": False,
            "required_checks": list(FULL_KAT_VALIDATION_PACKAGE_CHECKS),
            "required_source_inputs": {
                "backend_capture_sha256": backend_capture_sha256,
                "backend_manifest_sha256": backend_manifest_sha256,
            },
            "required_claim_boundary": "conformance/proof-review evidence",
            "required_claim_flags": false_claim_flags(),
            "description": (
                "Externally reviewed ML-DSA-65 KAT/CAVP validation package for "
                "the selected provider and capture, including positive vectors, "
                "negative mutation vectors, length vectors, and implementation "
                "digest binding."
            ),
        },
    }


def build_report(
    root,
    rejection_batch_path=None,
    distribution_abort_review_path=None,
    backend_manifest_path=None,
    backend_capture_path=None,
    criterion2_manifest_path=None,
    rejection_package_path=None,
    validation_package_path=None,
    generated_at=None,
):
    """Build the blocker-request report."""
    root = Path(root)
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    distribution_abort_review_path = Path(
        distribution_abort_review_path or default_distribution_abort_review(root)
    )
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    criterion2_manifest_path = Path(
        criterion2_manifest_path or default_criterion2_manifest(root)
    )
    rejection_package_path = Path(rejection_package_path or default_rejection_package(root))
    validation_package_path = Path(validation_package_path or default_validation_package(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    inputs = {
        "rejection_batch": input_record(rejection_batch_path),
        "accepted_distribution_abort_review": input_record(distribution_abort_review_path),
        "backend_manifest": input_record(backend_manifest_path),
        "backend_capture": input_record(backend_capture_path),
        "criterion2_manifest": input_record(criterion2_manifest_path),
        "rejection_distribution_preservation_review": input_record(
            rejection_package_path
        ),
        "full_kat_cavp_validation_review": input_record(validation_package_path),
    }
    required_packages = build_required_packages(
        rejection_batch_path,
        distribution_abort_review_path,
        backend_manifest_path,
        backend_capture_path,
        rejection_package_path,
        validation_package_path,
    )
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "selected_profile": SELECTED_PROFILE,
        "required_packages": required_packages,
        "inputs": inputs,
        "claim_flags": false_claim_flags(),
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "claim_boundary": CLAIM_BOUNDARY,
        "request_status": REQUEST_STATUS,
        "required_packages": required_packages,
        "claim_flags": false_claim_flags(),
        "inputs": inputs,
        "request_digest_sha256": sha256_text(canonical_json(digest_material)),
        "request_boundary": (
            "This artifact defines the exact externally reviewed proof and "
            "validation packages required to satisfy the remaining theorem-review "
            "flags. It does not assert theorem closure or validation."
        ),
    }
    contents = artifact_contents({"manifest": manifest, "summary_md": render_summary(manifest)})
    return {
        "manifest": manifest,
        "summary_md": contents["summary.md"],
        "artifact_contents": contents,
    }


def render_summary(manifest):
    """Render a concise blocker-request summary."""
    lines = [
        "# Theorem Closure Blocker Requests",
        "",
        "This artifact defines the remaining external proof and validation inputs "
        "needed before theorem-closure assessment can become ready.",
        "",
        f"- Request status: `{manifest['request_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Request digest SHA-256: `{manifest['request_digest_sha256']}`",
        "",
        "Required Packages:",
    ]
    for name, package in manifest["required_packages"].items():
        lines.append(f"- `{name}`: `{package['current_status']}`")
        lines.append(f"  - schema: `{package['schema']}`")
        lines.append(f"  - expected path: `{package['expected_path']}`")
        lines.append(f"  - satisfies: `{package['satisfies_review_flag']}`")
    lines.append("")
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
    """Write blocker-request artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build theorem-closure blocker request artifacts"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--rejection-batch", default=None)
    parser.add_argument("--distribution-abort-review", default=None)
    parser.add_argument("--backend-manifest", default=None)
    parser.add_argument("--backend-capture", default=None)
    parser.add_argument("--criterion2-manifest", default=None)
    parser.add_argument("--rejection-package", default=None)
    parser.add_argument("--validation-package", default=None)
    parser.add_argument("--out", default=None, help="artifact output directory")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        rejection_batch_path=args.rejection_batch,
        distribution_abort_review_path=args.distribution_abort_review,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        criterion2_manifest_path=args.criterion2_manifest,
        rejection_package_path=args.rejection_package,
        validation_package_path=args.validation_package,
    )
    out = Path(args.out) if args.out else default_out(root)
    write_artifacts(report, out)
    print(f"wrote theorem-closure blocker request artifacts to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
