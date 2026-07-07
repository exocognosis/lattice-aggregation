#!/usr/bin/env python3
"""Build the theorem-closure review manifest from current evidence artifacts."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:theorem-closure-review:v1"
NAME = "theorem-closure-review-v1"
CLAIM_BOUNDARY = "readiness preflight only; pending theorem-closure review"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
READY_STATUS = "theorem_closure_review_ready"
INCOMPLETE_STATUS = "theorem_closure_review_incomplete"
EXTERNAL_ATTEMPT_READY = "external_evidence_close_candidate_ready"
THEOREM_LINKAGE_SCHEMA = "lattice-aggregation:p1-theorem-linkage-review:v1"
THEOREM_LINKAGE_READY = "reviewed_theorem_linkage_ready"
DISTRIBUTION_ABORT_SCHEMA = "lattice-aggregation:p1-accepted-distribution-abort-review:v1"
DISTRIBUTION_ABORT_READY = "reviewed_distribution_abort_ready"

REVIEW_FLAGS = (
    "proof_payload_reviewed",
    "full_kat_validation_reviewed",
    "rejection_distribution_preservation_reviewed",
    "standard_verifier_compatibility_reviewed",
    "theorem_linkage_reviewed",
)

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
    """Load JSON from a path if present."""
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


def false_claim_flags():
    """Return all theorem/security claim flags pinned false."""
    return {key: False for key in CLAIM_FLAG_KEYS}


def empty_blocker_groups():
    """Return stable review blocker groups."""
    return {
        "proof_payload_review": [],
        "validation": [],
        "rejection_distribution_review": [],
        "standard_verifier_review": [],
        "theorem_linkage_review": [],
        "claim_boundary": [],
    }


def add_blocker(groups, group, message):
    """Append a blocker without duplicates."""
    if message not in groups[group]:
        groups[group].append(message)


def default_backend_manifest(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/capture.json"


def default_rejection_batch(root):
    return Path(root) / "artifacts/p1-rejection-equivalence-batch/latest/batch.json"


def default_closure_candidate(root):
    return (
        Path(root)
        / "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json"
    )


def default_external_attempt(root):
    return Path(root) / "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json"


def default_theorem_linkage_review(root):
    return Path(root) / "artifacts/p1-theorem-linkage-review/latest/manifest.json"


def default_distribution_abort_review(root):
    return (
        Path(root)
        / "artifacts/p1-accepted-distribution-abort-review/latest/manifest.json"
    )


def default_criterion2_manifest(root):
    return Path(root) / "docs/cryptography/criterion-2-proof-substance.json"


def default_out(root):
    return Path(root) / "artifacts/theorem-closure-review/latest"


def claim_boundary_is_preserved(*documents):
    """Return true only when every present claim flag is false."""
    for document in documents:
        if not isinstance(document, dict):
            return False
        flags = document.get("claim_flags")
        if isinstance(flags, dict):
            values = [flags.get(key) is False for key in flags]
        else:
            values = [
                document.get(key) is False
                for key in document
                if isinstance(key, str) and key.startswith("claims_")
            ]
        if values and not all(values):
            return False
    return True


def backend_standard_verifier_checks(backend_capture):
    """Extract standard verifier and mutation checks from backend capture."""
    payload = backend_capture.get("capture", {}) if isinstance(backend_capture, dict) else {}
    public_key_hex = payload.get("public_key_hex", "")
    signature_hex = payload.get("aggregate_signature_hex", "")
    return {
        "public_key_len_1952": len(bytes.fromhex(public_key_hex)) == 1952,
        "signature_len_3309": len(bytes.fromhex(signature_hex)) == 3309,
        "standard_verifier_accepts": payload.get("standard_verifier_accepts") is True,
        "mutated_message_rejected": payload.get("mutated_message_rejected") is True,
        "mutated_public_key_rejected": payload.get("mutated_public_key_rejected")
        is True,
        "mutated_signature_rejected": payload.get("mutated_signature_rejected") is True,
    }


def strict_backend_checks(backend_manifest):
    """Extract strict backend admissibility checks."""
    admissibility = (
        backend_manifest.get("backend_core_admissibility", {})
        if isinstance(backend_manifest, dict)
        else {}
    )
    return {
        "strict_threshold_core_admissible": (
            admissibility.get("strict_threshold_core_admissible") is True
        ),
        "not_quarantined": admissibility.get("quarantined") is False,
        "core_mode": admissibility.get("core_mode"),
        "signature_origin": admissibility.get("signature_origin"),
    }


def rejection_batch_checks(rejection_batch):
    """Extract predicate and distribution review checks from rejection batch."""
    result = rejection_batch.get("result", {}) if isinstance(rejection_batch, dict) else {}
    scope = (
        rejection_batch.get("equivalence_scope", {})
        if isinstance(rejection_batch, dict)
        else {}
    )
    return {
        "predicate_mismatch_count": result.get("predicate_mismatch_count"),
        "predicate_mismatches_absent": result.get("predicate_mismatch_count") == 0,
        "accepted_or_rejected_matches": result.get("accepted_or_rejected_matches")
        is True,
        "per_attempt_records_present": result.get("per_attempt_records_present") is True,
        "saw_threshold_accepted_attempt": result.get("saw_threshold_accepted_attempt")
        is True,
        "saw_threshold_rejected_attempt": result.get("saw_threshold_rejected_attempt")
        is True,
        "saw_accepted_and_rejected": (
            result.get("saw_threshold_accepted_attempt") is True
            and result.get("saw_threshold_rejected_attempt") is True
        ),
        "standard_verifier_accepts_threshold_signature": (
            result.get("standard_verifier_accepts_threshold_signature") is True
        ),
        "repo_provider_accepts_threshold_signature": (
            result.get("repo_provider_accepts_threshold_signature") is True
        ),
        "distribution_compatibility_proven": (
            result.get("distribution_compatibility_proven") is True
            and scope.get("accepted_aggregate_distribution_compatibility_proven")
            is True
        ),
    }


def theorem_linkage_review_checks(theorem_linkage_review):
    """Extract theorem-linkage package checks."""
    if not isinstance(theorem_linkage_review, dict):
        return {
            "present": False,
            "schema_valid": False,
            "review_status_ready": False,
            "claim_boundary_preserved": False,
            "source_checks_pass": False,
            "claims_false": False,
        }
    claim_flags = theorem_linkage_review.get("claim_flags", {})
    source_checks = theorem_linkage_review.get("checks", {})
    return {
        "present": True,
        "schema_valid": theorem_linkage_review.get("schema") == THEOREM_LINKAGE_SCHEMA,
        "review_status_ready": (
            theorem_linkage_review.get("review_status") == THEOREM_LINKAGE_READY
        ),
        "claim_boundary_preserved": (
            theorem_linkage_review.get("claim_boundary") == "conformance/proof-review evidence"
            and theorem_linkage_review.get("selected_profile") == SELECTED_PROFILE
        ),
        "source_checks_pass": (
            isinstance(source_checks, dict)
            and len(source_checks) > 0
            and all(value is True for value in source_checks.values())
        ),
        "claims_false": (
            isinstance(claim_flags, dict)
            and len(claim_flags) > 0
            and all(value is False for value in claim_flags.values())
        ),
    }


def distribution_abort_review_checks(distribution_abort_review):
    """Extract non-promoting accepted-distribution/abort review checks."""
    if not isinstance(distribution_abort_review, dict):
        return {
            "present": False,
            "schema_valid": False,
            "review_status_ready": False,
            "claims_false": False,
        }
    claim_flags = distribution_abort_review.get("claim_flags", {})
    return {
        "present": True,
        "schema_valid": (
            distribution_abort_review.get("schema") == DISTRIBUTION_ABORT_SCHEMA
        ),
        "review_status_ready": (
            distribution_abort_review.get("review_status") == DISTRIBUTION_ABORT_READY
        ),
        "claims_false": (
            isinstance(claim_flags, dict)
            and len(claim_flags) > 0
            and all(value is False for value in claim_flags.values())
        ),
    }


def criterion2_validation_slot_checks(criterion2):
    """Return non-promoting validation proof-slot status from Criterion 2."""
    proof_payload = criterion2.get("proof_payload", {}) if isinstance(criterion2, dict) else {}
    artifact_refs = proof_payload.get("artifact_fixture_refs", [])
    required_slots = proof_payload.get("required_artifact_slots", [])
    validation_refs = [
        item
        for item in artifact_refs
        if isinstance(item, dict)
        and item.get("slot_id") == "full_kat_validation_artifact_digest"
    ]
    validation_required_slots = [
        item
        for item in required_slots
        if isinstance(item, dict)
        and item.get("id") == "full_kat_validation_artifact_digest"
    ]
    slot_present = len(validation_refs) > 0 or len(validation_required_slots) > 0
    status_evidence_present = any(
        item.get("current_status") == "evidence_present_unclosed"
        for item in validation_refs
    )
    status_evidence_present = status_evidence_present or any(
        item.get("current_status") == "evidence_present_unclosed"
        for item in validation_required_slots
    )
    claim_boundary_preserved = any(
        item.get("claim_boundary") == "conformance/proof-review evidence"
        for item in validation_refs
    )
    claim_boundary_preserved = claim_boundary_preserved or any(
        item.get("claim_boundary") == "conformance/proof-review evidence"
        for item in validation_required_slots
    )
    return {
        "slot_present": slot_present,
        "slot_status_evidence_present_unclosed": status_evidence_present,
        "slot_claim_boundary_preserved": claim_boundary_preserved,
    }


def external_evidence_checks(candidate, attempt):
    """Extract close-candidate and external-evidence attempt checks."""
    attempt_checks = attempt.get("checks", {}) if isinstance(attempt, dict) else {}
    return {
        "candidate_close_candidate": candidate.get("close_candidate") is True,
        "candidate_has_no_blockers": candidate.get("blockers") == [],
        "attempt_close_candidate": attempt.get("close_candidate") is True,
        "attempt_status_ready": attempt.get("attempt_status") == EXTERNAL_ATTEMPT_READY,
        "attempt_has_no_blockers": attempt.get("blockers") == [],
        "source_exclusion_passed": attempt_checks.get("source_exclusion_passed")
        is True,
        "review_package_binds_inputs": attempt_checks.get("review_package_binds_inputs")
        is True,
        "review_package_present": attempt_checks.get("review_package_present") is True,
    }


def build_report(
    root,
    backend_manifest_path=None,
    backend_capture_path=None,
    rejection_batch_path=None,
    closure_candidate_path=None,
    external_attempt_path=None,
    theorem_linkage_review_path=None,
    distribution_abort_review_path=None,
    criterion2_manifest_path=None,
    generated_at=None,
):
    """Build the theorem-closure review report."""
    root = Path(root)
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    closure_candidate_path = Path(closure_candidate_path or default_closure_candidate(root))
    external_attempt_path = Path(external_attempt_path or default_external_attempt(root))
    theorem_linkage_review_path = Path(
        theorem_linkage_review_path or default_theorem_linkage_review(root)
    )
    distribution_abort_review_path = Path(
        distribution_abort_review_path or default_distribution_abort_review(root)
    )
    criterion2_manifest_path = Path(
        criterion2_manifest_path or default_criterion2_manifest(root)
    )
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    backend_manifest = load_json(backend_manifest_path)
    backend_capture = load_json(backend_capture_path)
    rejection_batch = load_json(rejection_batch_path)
    candidate = load_json(closure_candidate_path)
    attempt = load_json(external_attempt_path)
    theorem_linkage_review = load_json_if_present(theorem_linkage_review_path)
    distribution_abort_review = load_json_if_present(distribution_abort_review_path)
    criterion2 = load_json(criterion2_manifest_path)

    blockers = empty_blocker_groups()
    backend_checks = strict_backend_checks(backend_manifest)
    verifier_checks = backend_standard_verifier_checks(backend_capture)
    batch_checks = rejection_batch_checks(rejection_batch)
    theorem_linkage_checks = theorem_linkage_review_checks(theorem_linkage_review)
    distribution_abort_checks = distribution_abort_review_checks(distribution_abort_review)
    validation_slot_checks = criterion2_validation_slot_checks(criterion2)
    external_checks = external_evidence_checks(candidate, attempt)
    claim_boundary_preserved = claim_boundary_is_preserved(
        candidate,
        attempt,
        rejection_batch,
    )

    proof_payload_reviewed = (
        all(
            external_checks[key]
            for key in (
                "candidate_close_candidate",
                "candidate_has_no_blockers",
                "attempt_close_candidate",
                "attempt_status_ready",
                "attempt_has_no_blockers",
                "source_exclusion_passed",
                "review_package_binds_inputs",
                "review_package_present",
            )
        )
        and backend_checks["strict_threshold_core_admissible"]
        and backend_checks["not_quarantined"]
        and batch_checks["predicate_mismatches_absent"]
        and claim_boundary_preserved
    )
    standard_verifier_compatibility_reviewed = (
        all(verifier_checks.values())
        and batch_checks["standard_verifier_accepts_threshold_signature"]
        and batch_checks["repo_provider_accepts_threshold_signature"]
    )
    rejection_distribution_preservation_reviewed = batch_checks[
        "distribution_compatibility_proven"
    ]
    full_kat_validation_reviewed = False
    theorem_linkage_reviewed = all(theorem_linkage_checks.values())

    if not proof_payload_reviewed:
        add_blocker(
            blockers,
            "proof_payload_review",
            "close-candidate proof payload is not fully review-ready",
        )
    if not standard_verifier_compatibility_reviewed:
        add_blocker(
            blockers,
            "standard_verifier_review",
            "standard-verifier compatibility checks are incomplete",
        )
    if not rejection_distribution_preservation_reviewed:
        add_blocker(
            blockers,
            "rejection_distribution_review",
            "rejection-distribution preservation is not proven by the batch",
        )
    if not full_kat_validation_reviewed:
        add_blocker(
            blockers,
            "validation",
            "full KAT/CAVP validation package is not present",
        )
    if not theorem_linkage_reviewed:
        add_blocker(
            blockers,
            "theorem_linkage_review",
            "theorem-linkage review package is not ready",
        )
    if not claim_boundary_preserved:
        add_blocker(
            blockers,
            "claim_boundary",
            "input claim boundary is not preserved",
        )

    review_flags = {
        "proof_payload_reviewed": proof_payload_reviewed,
        "full_kat_validation_reviewed": full_kat_validation_reviewed,
        "rejection_distribution_preservation_reviewed": (
            rejection_distribution_preservation_reviewed
        ),
        "standard_verifier_compatibility_reviewed": (
            standard_verifier_compatibility_reviewed
        ),
        "theorem_linkage_reviewed": theorem_linkage_reviewed,
    }
    review_ready = all(review_flags.values()) and all(
        len(group) == 0 for group in blockers.values()
    )
    evidence_summary = {
        "strict_backend": backend_checks,
        "external_evidence": external_checks,
        "predicate_mismatch_count": batch_checks["predicate_mismatch_count"],
        "saw_accepted_and_rejected": batch_checks["saw_accepted_and_rejected"],
        "standard_verifier_accepts": (
            verifier_checks["standard_verifier_accepts"]
            and batch_checks["standard_verifier_accepts_threshold_signature"]
        ),
        "mutation_rejections": {
            "message": verifier_checks["mutated_message_rejected"],
            "public_key": verifier_checks["mutated_public_key_rejected"],
            "signature": verifier_checks["mutated_signature_rejected"],
        },
        "distribution_compatibility_proven": batch_checks[
            "distribution_compatibility_proven"
        ],
        "distribution_abort_review": distribution_abort_checks,
        "validation_artifact_slot": validation_slot_checks,
        "full_kat_validation_reviewed": full_kat_validation_reviewed,
        "theorem_linkage_review": theorem_linkage_checks,
        "claim_boundary_preserved": claim_boundary_preserved,
    }
    inputs = {
        "backend_manifest": input_record(backend_manifest_path),
        "backend_capture": input_record(backend_capture_path),
        "rejection_batch": input_record(rejection_batch_path),
        "closure_candidate": input_record(closure_candidate_path),
        "external_attempt": input_record(external_attempt_path),
        "theorem_linkage_review": input_record(theorem_linkage_review_path),
        "accepted_distribution_abort_review": input_record(distribution_abort_review_path),
        "criterion2_manifest": input_record(criterion2_manifest_path),
    }
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "selected_profile": SELECTED_PROFILE,
        "review_flags": review_flags,
        "evidence_summary": evidence_summary,
        "blocker_groups": blockers,
        "inputs": inputs,
        "criterion2_promotion_requires_sha256": sha256_text(
            canonical_json(criterion2.get("promotion_requires", []))
        ),
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "claim_boundary": CLAIM_BOUNDARY,
        "review_status": READY_STATUS if review_ready else INCOMPLETE_STATUS,
        "review_flags": review_flags,
        "claim_flags": false_claim_flags(),
        "evidence_summary": evidence_summary,
        "blocker_groups": blockers,
        "inputs": inputs,
        "review_digest_sha256": sha256_text(canonical_json(digest_material)),
        "assessment_boundary": (
            "This manifest reviews whether current close-candidate artifacts are "
            "ready for theorem-closure assessment. It does not assert theorem "
            "closure, rejection-distribution preservation, production security, "
            "CAVP/ACVTS validation, or FIPS validation."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    """Render a concise theorem-review summary."""
    lines = [
        "# Theorem Closure Review",
        "",
        "This artifact reviews the current external-backend close-candidate "
        "evidence for theorem-readiness. It does not claim theorem closure.",
        "",
        f"- Review status: `{manifest['review_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Review digest SHA-256: `{manifest['review_digest_sha256']}`",
        "",
        "Review Flags:",
    ]
    for name, passed in manifest["review_flags"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")
    lines.extend(["", "Evidence Summary:"])
    summary = manifest["evidence_summary"]
    lines.append(
        "- `predicate_mismatch_count`: "
        f"`{summary['predicate_mismatch_count']}`"
    )
    lines.append(
        "- `saw_accepted_and_rejected`: "
        f"`{str(summary['saw_accepted_and_rejected']).lower()}`"
    )
    lines.append(
        "- `standard_verifier_accepts`: "
        f"`{str(summary['standard_verifier_accepts']).lower()}`"
    )
    lines.append(
        "- `distribution_compatibility_proven`: "
        f"`{str(summary['distribution_compatibility_proven']).lower()}`"
    )
    lines.append(
        "- `theorem_linkage_reviewed`: "
        f"`{str(manifest['review_flags']['theorem_linkage_reviewed']).lower()}`"
    )
    lines.append(
        "- `full_kat_validation_reviewed`: "
        f"`{str(manifest['review_flags']['full_kat_validation_reviewed']).lower()}`"
    )
    lines.extend(["", "Blocker Groups:"])
    for group, blockers in manifest["blocker_groups"].items():
        lines.append(f"- `{group}`: `{len(blockers)}` blocker(s)")
        for blocker in blockers:
            lines.append(f"  - {blocker}")
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
    """Write theorem-review artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build theorem-closure review manifest"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--backend-manifest", default=None)
    parser.add_argument("--backend-capture", default=None)
    parser.add_argument("--rejection-batch", default=None)
    parser.add_argument("--closure-candidate", default=None)
    parser.add_argument("--external-attempt", default=None)
    parser.add_argument("--theorem-linkage-review", default=None)
    parser.add_argument("--distribution-abort-review", default=None)
    parser.add_argument("--criterion2-manifest", default=None)
    parser.add_argument(
        "--out",
        default=None,
        help="theorem-review artifact output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        rejection_batch_path=args.rejection_batch,
        closure_candidate_path=args.closure_candidate,
        external_attempt_path=args.external_attempt,
        theorem_linkage_review_path=args.theorem_linkage_review,
        distribution_abort_review_path=args.distribution_abort_review,
        criterion2_manifest_path=args.criterion2_manifest,
    )
    out = Path(args.out) if args.out else default_out(root)
    write_artifacts(report, out)
    print(f"wrote theorem-closure review artifacts to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
