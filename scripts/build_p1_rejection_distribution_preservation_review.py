#!/usr/bin/env python3
"""Build the P1 rejection-distribution preservation review package."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-rejection-distribution-preservation-review:v1"
NAME = "p1-rejection-distribution-preservation-review"
READY_STATUS = "reviewed_rejection_distribution_preservation_ready"
BLOCKED_STATUS = "blocked_rejection_distribution_preservation_review"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
PROOF_EVIDENCE_SCHEMA = "external-review:p1-rejection-distribution-preservation:v1"

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

REQUIRED_CHECKS = (
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

REQUIRED_THEOREM_LINKS = (
    "Noise Lemma D",
    "Noise Lemma F",
    "Noise Lemma H",
    "FST-L7",
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


def load_json(path):
    """Load JSON from a required path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_json_if_present(path):
    """Load JSON from a path when present."""
    path = Path(path)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def false_claim_flags():
    """Return all theorem/security claim flags pinned false."""
    return {key: False for key in CLAIM_FLAG_KEYS}


def digest_json(domain, data):
    """Return a domain-separated SHA-256 digest over JSON data."""
    return sha256_text(canonical_json({"domain": domain, "data": data}))


def default_rejection_batch(root):
    return Path(root) / "artifacts/p1-rejection-equivalence-batch/latest/batch.json"


def default_distribution_abort_review(root):
    return (
        Path(root)
        / "artifacts/p1-accepted-distribution-abort-review/latest/manifest.json"
    )


def default_proof_evidence(root):
    return (
        Path(root)
        / "artifacts/p1-rejection-distribution-proof-input/latest/evidence.json"
    )


def default_out(root):
    return (
        Path(root)
        / "artifacts/p1-rejection-distribution-preservation-review/latest"
    )


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def is_digest(value):
    """Return true for nonzero 64-character hex digests."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    if value == "0" * 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def proof_checks(
    rejection_batch,
    distribution_abort_review,
    proof_evidence,
    rejection_batch_sha256,
    distribution_abort_sha256,
):
    """Build rejection-distribution preservation review checks."""
    evidence_checks = (
        proof_evidence.get("checks", {}) if isinstance(proof_evidence, dict) else {}
    )
    proof_schema_valid = (
        isinstance(proof_evidence, dict)
        and proof_evidence.get("schema") == PROOF_EVIDENCE_SCHEMA
    )
    theorem_links = (
        proof_evidence.get("theorem_links", [])
        if isinstance(proof_evidence, dict)
        else []
    )
    result = rejection_batch.get("result", {}) if isinstance(rejection_batch, dict) else {}
    distribution_checks = (
        distribution_abort_review.get("checks", {})
        if isinstance(distribution_abort_review, dict)
        else {}
    )
    reviewer_digest = (
        proof_evidence.get("external_reviewer_digest_hex")
        if isinstance(proof_evidence, dict)
        else None
    )
    source_bound_rejection = (
        isinstance(proof_evidence, dict)
        and proof_evidence.get("rejection_batch_sha256") == rejection_batch_sha256
    ) or proof_evidence is None
    source_bound_distribution = (
        isinstance(proof_evidence, dict)
        and proof_evidence.get("accepted_distribution_abort_review_sha256")
        == distribution_abort_sha256
    ) or proof_evidence is None
    return {
        "accepted_distribution_distance_bound_reviewed": (
            proof_schema_valid
            and evidence_checks.get("accepted_distribution_distance_bound_reviewed")
            is True
            and all(link in theorem_links for link in REQUIRED_THEOREM_LINKS)
        ),
        "threshold_accepted_distribution_reviewed": (
            proof_schema_valid
            and evidence_checks.get("threshold_accepted_distribution_reviewed") is True
            and result.get("saw_threshold_accepted_attempt") is True
        ),
        "centralized_mldsa_reference_distribution_reviewed": (
            proof_schema_valid
            and evidence_checks.get("centralized_mldsa_reference_distribution_reviewed")
            is True
            and result.get("predicate_mismatch_count") == 0
        ),
        "rejection_sampling_conditioning_reviewed": (
            proof_schema_valid
            and evidence_checks.get("rejection_sampling_conditioning_reviewed") is True
            and result.get("saw_threshold_rejected_attempt") is True
        ),
        "selective_abort_withholding_bound_reviewed": (
            proof_schema_valid
            and evidence_checks.get("selective_abort_withholding_bound_reviewed")
            is True
            and distribution_checks.get("selective_abort_withholding_reviewed") is True
        ),
        "restart_leakage_bound_reviewed": (
            proof_schema_valid
            and evidence_checks.get("restart_leakage_bound_reviewed") is True
            and distribution_checks.get("observable_restart_leakage_reviewed") is True
        ),
        "concurrency_model_reviewed": (
            proof_schema_valid
            and evidence_checks.get("concurrency_model_reviewed") is True
            and distribution_checks.get("concurrent_session_abort_model_reviewed") is True
        ),
        "concrete_loss_bound_nonvacuous": (
            proof_schema_valid
            and evidence_checks.get("concrete_loss_bound_nonvacuous") is True
            and bool(proof_evidence.get("concrete_loss_bound"))
        ),
        "binds_rejection_batch_digest": source_bound_rejection,
        "binds_distribution_abort_review_digest": source_bound_distribution,
        "external_reviewer_digest_present": is_digest(reviewer_digest),
    }


def build_report(
    root,
    rejection_batch_path=None,
    distribution_abort_review_path=None,
    proof_evidence_path=None,
    generated_at=None,
):
    """Build the rejection-distribution preservation review report."""
    root = Path(root)
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    distribution_abort_review_path = Path(
        distribution_abort_review_path or default_distribution_abort_review(root)
    )
    proof_evidence_path = Path(proof_evidence_path or default_proof_evidence(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    rejection_batch = load_json(rejection_batch_path)
    distribution_abort_review = load_json(distribution_abort_review_path)
    proof_evidence = load_json_if_present(proof_evidence_path)
    rejection_batch_sha256 = sha256_path(rejection_batch_path)
    distribution_abort_sha256 = sha256_path(distribution_abort_review_path)

    checks = proof_checks(
        rejection_batch,
        distribution_abort_review,
        proof_evidence,
        rejection_batch_sha256,
        distribution_abort_sha256,
    )
    ready = all(checks.values())
    blockers = [name for name, passed in checks.items() if not passed]
    source_inputs = {
        "rejection_batch_sha256": rejection_batch_sha256,
        "accepted_distribution_abort_review_sha256": distribution_abort_sha256,
        "proof_evidence_sha256": sha256_path(proof_evidence_path),
    }
    review_material = {
        "rejection_batch_result": rejection_batch.get("result", {}),
        "accepted_distribution_abort_review": distribution_abort_review.get("checks", {}),
        "proof_evidence": proof_evidence,
        "checks": checks,
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "package_class": "rejection_distribution_preservation_review",
        "claim_boundary": CLAIM_BOUNDARY,
        "review_status": READY_STATUS if ready else BLOCKED_STATUS,
        "checks": checks,
        "blockers": blockers,
        "source_inputs": source_inputs,
        "review_digests": {
            "accepted_distribution_distance_digest_hex": digest_json(
                "accepted_distribution_distance",
                review_material,
            ),
            "threshold_distribution_digest_hex": digest_json(
                "threshold_distribution",
                rejection_batch.get("attempts", []),
            ),
            "centralized_reference_distribution_digest_hex": digest_json(
                "centralized_reference_distribution",
                rejection_batch.get("result", {}),
            ),
            "abort_withholding_bound_digest_hex": digest_json(
                "abort_withholding_bound",
                distribution_abort_review,
            ),
            "concrete_loss_bound_digest_hex": digest_json(
                "concrete_loss_bound",
                proof_evidence.get("concrete_loss_bound")
                if isinstance(proof_evidence, dict)
                else None,
            ),
            "reviewer_identity_digest_hex": (
                proof_evidence.get("external_reviewer_digest_hex")
                if isinstance(proof_evidence, dict)
                else None
            ),
        },
        "claim_flags": false_claim_flags(),
        "package_boundary": (
            "This package records reviewed rejection-distribution preservation "
            "input for theorem-readiness. It does not assert theorem closure or "
            "production threshold ML-DSA security by itself."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    """Render a concise package summary."""
    lines = [
        "# P1 Rejection-Distribution Preservation Review",
        "",
        "This package records whether reviewed rejection-distribution and abort "
        "bounds are bound to the current rejection batch.",
        "",
        f"- Review status: `{manifest['review_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        "",
        "Checks:",
    ]
    for name, passed in manifest["checks"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")
    lines.extend(["", "Blockers:"])
    if manifest["blockers"]:
        for blocker in manifest["blockers"]:
            lines.append(f"- `{blocker}`")
    else:
        lines.append("- none")
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
    """Write package artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build P1 rejection-distribution preservation review package"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--rejection-batch", default=None)
    parser.add_argument("--distribution-abort-review", default=None)
    parser.add_argument("--proof-evidence", default=None)
    parser.add_argument(
        "--out",
        default=None,
        help="rejection-distribution review artifact output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        rejection_batch_path=args.rejection_batch,
        distribution_abort_review_path=args.distribution_abort_review,
        proof_evidence_path=args.proof_evidence,
    )
    write_artifacts(report, Path(args.out or default_out(root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
