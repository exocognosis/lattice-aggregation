#!/usr/bin/env python3
"""Assess whether theorem-closure assessment can begin."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:theorem-closure-assessment-readiness:v1"
NAME = "theorem-closure-assessment-readiness-v1"
CLAIM_BOUNDARY = "readiness preflight only; pending theorem-closure review"
STATUS_READY = "ready_for_theorem_closure_assessment"
STATUS_BLOCKED = "blocked_before_theorem_closure_assessment"
CRITERION2_SCHEMA = "lattice-aggregation.criterion-2-proof-substance.v1"
EXTERNAL_ATTEMPT_READY = "external_evidence_close_candidate_ready"
THEOREM_REVIEW_SCHEMA = "lattice-aggregation:theorem-closure-review:v1"
THEOREM_REVIEW_READY = "theorem_closure_review_ready"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
PRODUCTION_DKG_REVIEW_PACKAGE_CLASS = "production_dkg_no_single_secret_review"
PRODUCTION_DKG_REVIEW_ROUTES = {
    "tee_hsm_no_export",
    "distributed_dkg_vss",
}
PRODUCTION_DKG_REVIEW_READY = "reviewed_production_dkg_no_single_secret_ready"
ACCEPTED_DISTRIBUTION_ABORT_REVIEW_PACKAGE_CLASS = (
    "accepted_distribution_abort_review"
)
ACCEPTED_DISTRIBUTION_ABORT_REVIEW_READY = "reviewed_distribution_abort_ready"
ACCEPTED_HYPOTHESIS_CLAIM_BOUNDARIES = {
    "research scaffold evidence",
    "closure-run implementation track",
}

REQUIRED_REVIEW_FLAGS = {
    "proof_payload_reviewed": "proof_payload_review",
    "full_kat_validation_reviewed": "validation",
    "rejection_distribution_preservation_reviewed": "rejection_distribution_review",
    "standard_verifier_compatibility_reviewed": "standard_verifier_review",
    "theorem_linkage_reviewed": "theorem_linkage_review",
}

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


def default_criterion2_manifest(root):
    return Path(root) / "docs" / "cryptography" / "criterion-2-proof-substance.json"


def default_hypothesis_assessment(root):
    return Path(root) / "artifacts" / "hypothesis" / "latest" / "assessment.json"


def default_closure_candidate(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-cryptographic-closure-candidate"
        / "latest"
        / "manifest.json"
    )


def default_external_attempt(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-evidence-attempt"
        / "latest"
        / "manifest.json"
    )


def default_theorem_review(root):
    return (
        Path(root)
        / "artifacts"
        / "theorem-closure-review"
        / "latest"
        / "manifest.json"
    )


def empty_blocker_groups():
    return {
        "external_backend_evidence": [],
        "proof_payload_review": [],
        "validation": [],
        "rejection_distribution_review": [],
        "standard_verifier_review": [],
        "theorem_linkage_review": [],
        "criterion2_manifest": [],
        "hypothesis_assessment": [],
        "claim_boundary": [],
    }


def add_blocker(blocker_groups, group, message):
    """Append a blocker to a group without duplicates."""
    if message not in blocker_groups[group]:
        blocker_groups[group].append(message)


def group_for_requirement(requirement):
    """Map a Criterion 2 promotion requirement to a readiness group."""
    lowered = requirement.lower()
    if "batch 7" in lowered or "batch 8" in lowered or "batch 9" in lowered:
        return "external_backend_evidence"
    if "kat" in lowered or "validation" in lowered:
        return "validation"
    if "rejection-distribution" in lowered:
        return "rejection_distribution_review"
    if "standard-verifier" in lowered:
        return "standard_verifier_review"
    if "theorem-linkage" in lowered:
        return "theorem_linkage_review"
    return "proof_payload_review"


def false_claim_flags():
    return {key: False for key in CLAIM_FLAG_KEYS}


def review_manifest_checks(theorem_review, blocker_groups):
    """Validate optional theorem-review readiness manifest."""
    checks = {
        "theorem_review_manifest_present": isinstance(theorem_review, dict),
        "theorem_review_manifest_boundary_valid": False,
        "theorem_review_status_ready": False,
    }
    for flag in REQUIRED_REVIEW_FLAGS:
        checks[flag] = False
    for flag in CLAIM_FLAG_KEYS:
        checks[f"review_{flag}_false"] = False

    if not isinstance(theorem_review, dict):
        for flag, group in REQUIRED_REVIEW_FLAGS.items():
            add_blocker(
                blocker_groups,
                group,
                f"theorem review manifest is missing required ready flag: {flag}",
            )
        return checks

    claim_flags = theorem_review.get("claim_flags")
    checks["theorem_review_manifest_boundary_valid"] = (
        theorem_review.get("schema") == THEOREM_REVIEW_SCHEMA
        and theorem_review.get("claim_boundary") == CLAIM_BOUNDARY
        and theorem_review.get("selected_profile") == SELECTED_PROFILE
        and isinstance(claim_flags, dict)
    )
    checks["theorem_review_status_ready"] = (
        theorem_review.get("review_status") == THEOREM_REVIEW_READY
    )
    if not checks["theorem_review_manifest_boundary_valid"]:
        add_blocker(
            blocker_groups,
            "proof_payload_review",
            "theorem review manifest boundary is invalid",
        )
    if not checks["theorem_review_status_ready"]:
        add_blocker(
            blocker_groups,
            "proof_payload_review",
            "theorem review manifest is not ready",
        )

    review_flags = theorem_review.get("review_flags", {})
    for flag, group in REQUIRED_REVIEW_FLAGS.items():
        checks[flag] = isinstance(review_flags, dict) and review_flags.get(flag) is True
        if not checks[flag]:
            add_blocker(
                blocker_groups,
                group,
                f"theorem review manifest has not satisfied {flag}",
            )

    for flag in CLAIM_FLAG_KEYS:
        checks[f"review_{flag}_false"] = (
            isinstance(claim_flags, dict) and claim_flags.get(flag) is False
        )
        if not checks[f"review_{flag}_false"]:
            add_blocker(
                blocker_groups,
                "claim_boundary",
                f"theorem review manifest must keep {flag}=false",
            )

    return checks


def criterion2_checks(criterion2, blocker_groups):
    """Validate Criterion 2 manifest and map its promotion requirements."""
    checks = {
        "criterion2_manifest_present": isinstance(criterion2, dict),
        "criterion2_manifest_schema_valid": False,
        "criterion2_claim_boundary_preserved": False,
        "criterion2_promotion_requirements_present": False,
    }
    unresolved = []
    if not isinstance(criterion2, dict):
        add_blocker(
            blocker_groups,
            "criterion2_manifest",
            "Criterion 2 proof-substance manifest is missing",
        )
        return checks, unresolved

    checks["criterion2_manifest_schema_valid"] = criterion2.get("schema") == CRITERION2_SCHEMA
    boundary = criterion2.get("claim_boundary", {})
    checks["criterion2_claim_boundary_preserved"] = (
        isinstance(boundary, dict)
        and all(boundary.get(flag) is False for flag in CLAIM_FLAG_KEYS)
    )
    requirements = criterion2.get("promotion_requires", [])
    checks["criterion2_promotion_requirements_present"] = (
        isinstance(requirements, list) and len(requirements) > 0
    )

    if not checks["criterion2_manifest_schema_valid"]:
        add_blocker(
            blocker_groups,
            "criterion2_manifest",
            "Criterion 2 proof-substance manifest schema is invalid",
        )
    if not checks["criterion2_claim_boundary_preserved"]:
        add_blocker(
            blocker_groups,
            "claim_boundary",
            "Criterion 2 proof-substance manifest claim boundary is invalid",
        )
    if not checks["criterion2_promotion_requirements_present"]:
        add_blocker(
            blocker_groups,
            "criterion2_manifest",
            "Criterion 2 promotion requirements are missing",
        )
        return checks, unresolved

    for requirement in requirements:
        group = group_for_requirement(requirement)
        unresolved.append({"group": group, "requirement": requirement})

    return checks, unresolved


def external_evidence_checks(candidate, attempt, blocker_groups):
    """Validate external evidence readiness from Batch 7/8/9 artifacts."""
    attempt_checks = attempt.get("checks", {}) if isinstance(attempt, dict) else {}
    review_packages = (
        attempt.get("review_packages", {}) if isinstance(attempt, dict) else {}
    )
    dkg_review_package = (
        review_packages.get("production_dkg_no_single_secret_review")
        if isinstance(review_packages, dict)
        else None
    )
    distribution_abort_review_package = (
        review_packages.get("accepted_distribution_abort_review")
        if isinstance(review_packages, dict)
        else None
    )
    checks = {
        "external_closure_candidate_manifest_present": isinstance(candidate, dict),
        "external_closure_candidate_ready": (
            isinstance(candidate, dict) and candidate.get("close_candidate") is True
        ),
        "external_evidence_attempt_manifest_present": isinstance(attempt, dict),
        "external_evidence_attempt_ready": (
            isinstance(attempt, dict)
            and attempt.get("attempt_status") == EXTERNAL_ATTEMPT_READY
            and attempt.get("close_candidate") is True
        ),
        "external_source_exclusions_passed": (
            isinstance(attempt_checks, dict)
            and attempt_checks.get("source_exclusion_passed") is True
        ),
        "external_review_package_binds_inputs": (
            isinstance(attempt_checks, dict)
            and attempt_checks.get("review_package_binds_inputs") is True
        ),
        "external_review_package_ready": (
            isinstance(attempt_checks, dict)
            and attempt_checks.get("review_package_present") is True
            and attempt_checks.get("review_package_claim_boundary_passed") is True
            and attempt_checks.get("review_package_source_exclusions_passed") is True
            and attempt_checks.get("review_package_review_digests_present") is True
        ),
        "external_production_dkg_no_single_secret_review_ready": (
            isinstance(attempt_checks, dict)
            and attempt_checks.get("production_dkg_no_single_secret_review_present")
            is True
        ),
        "external_production_dkg_no_single_secret_review_package_valid": (
            isinstance(dkg_review_package, dict)
            and dkg_review_package.get("package_class")
            == PRODUCTION_DKG_REVIEW_PACKAGE_CLASS
            and dkg_review_package.get("route") in PRODUCTION_DKG_REVIEW_ROUTES
            and dkg_review_package.get("review_status") == PRODUCTION_DKG_REVIEW_READY
        ),
        "external_distribution_abort_review_ready": (
            isinstance(attempt_checks, dict)
            and attempt_checks.get("distribution_abort_review_present") is True
        ),
        "external_accepted_distribution_abort_review_package_valid": (
            isinstance(distribution_abort_review_package, dict)
            and distribution_abort_review_package.get("package_class")
            == ACCEPTED_DISTRIBUTION_ABORT_REVIEW_PACKAGE_CLASS
            and distribution_abort_review_package.get("review_status")
            == ACCEPTED_DISTRIBUTION_ABORT_REVIEW_READY
        ),
    }
    if not checks["external_closure_candidate_manifest_present"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "Batch 7 external-backend closure-candidate manifest is missing",
        )
    elif not checks["external_closure_candidate_ready"]:
        for blocker in candidate.get("blockers", []):
            add_blocker(blocker_groups, "external_backend_evidence", blocker)

    if not checks["external_evidence_attempt_manifest_present"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "Batch 8/9 external evidence attempt manifest is missing",
        )
    else:
        for blocker in attempt.get("blockers", []):
            add_blocker(blocker_groups, "external_backend_evidence", blocker)
    if not checks["external_production_dkg_no_single_secret_review_ready"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "production DKG/no-single-secret review is not ready",
        )
    if not checks["external_production_dkg_no_single_secret_review_package_valid"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "production DKG/no-single-secret review package class or route is not ready",
        )
    if not checks["external_distribution_abort_review_ready"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "accepted distribution/abort review is not ready",
        )
    if not checks["external_accepted_distribution_abort_review_package_valid"]:
        add_blocker(
            blocker_groups,
            "external_backend_evidence",
            "accepted distribution/abort review package class is not ready",
        )
    return checks


def hypothesis_checks(assessment, blocker_groups):
    """Record current top-level assessment boundary."""
    checks = {
        "hypothesis_assessment_present": isinstance(assessment, dict),
        "hypothesis_boundary_is_research_scaffold_only": False,
        "hypothesis_not_already_completely_proven": True,
    }
    if not isinstance(assessment, dict):
        add_blocker(
            blocker_groups,
            "hypothesis_assessment",
            "hypothesis assessment artifact is missing",
        )
        return checks
    checks["hypothesis_boundary_is_research_scaffold_only"] = (
        assessment.get("claim_boundary") in ACCEPTED_HYPOTHESIS_CLAIM_BOUNDARIES
    )
    checks["hypothesis_not_already_completely_proven"] = (
        assessment.get("overall_verdict") != "completely_proven"
    )
    if not checks["hypothesis_boundary_is_research_scaffold_only"]:
        add_blocker(
            blocker_groups,
            "claim_boundary",
            "hypothesis assessment claim boundary is not an accepted non-closure track",
        )
    return checks


def build_report(
    root,
    criterion2_manifest_path=None,
    hypothesis_assessment_path=None,
    closure_candidate_path=None,
    external_attempt_path=None,
    theorem_review_path=None,
    generated_at=None,
):
    """Build theorem-closure assessment readiness report."""
    root = Path(root)
    criterion2_manifest_path = Path(
        criterion2_manifest_path or default_criterion2_manifest(root)
    )
    hypothesis_assessment_path = Path(
        hypothesis_assessment_path or default_hypothesis_assessment(root)
    )
    closure_candidate_path = Path(closure_candidate_path or default_closure_candidate(root))
    external_attempt_path = Path(external_attempt_path or default_external_attempt(root))
    theorem_review_path = Path(theorem_review_path or default_theorem_review(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    criterion2 = load_json_if_present(criterion2_manifest_path)
    assessment = load_json_if_present(hypothesis_assessment_path)
    candidate = load_json_if_present(closure_candidate_path)
    attempt = load_json_if_present(external_attempt_path)
    theorem_review = load_json_if_present(theorem_review_path)
    blocker_groups = empty_blocker_groups()

    criterion2_result, unresolved = criterion2_checks(criterion2, blocker_groups)
    checks = {
        **criterion2_result,
        **hypothesis_checks(assessment, blocker_groups),
        **external_evidence_checks(candidate, attempt, blocker_groups),
        **review_manifest_checks(theorem_review, blocker_groups),
    }
    ready_checks = [
        "criterion2_manifest_present",
        "criterion2_manifest_schema_valid",
        "criterion2_claim_boundary_preserved",
        "criterion2_promotion_requirements_present",
        "hypothesis_assessment_present",
        "hypothesis_boundary_is_research_scaffold_only",
        "external_closure_candidate_manifest_present",
        "external_closure_candidate_ready",
        "external_evidence_attempt_manifest_present",
        "external_evidence_attempt_ready",
        "external_source_exclusions_passed",
        "external_review_package_binds_inputs",
        "external_review_package_ready",
        "external_production_dkg_no_single_secret_review_ready",
        "external_production_dkg_no_single_secret_review_package_valid",
        "external_distribution_abort_review_ready",
        "external_accepted_distribution_abort_review_package_valid",
        "theorem_review_manifest_present",
        "theorem_review_manifest_boundary_valid",
        "theorem_review_status_ready",
        *REQUIRED_REVIEW_FLAGS.keys(),
        *(f"review_{flag}_false" for flag in CLAIM_FLAG_KEYS),
    ]
    theorem_closure_assessment_ready = all(checks.get(key) is True for key in ready_checks)
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "checks": checks,
        "blocker_groups": blocker_groups,
        "claim_flags": false_claim_flags(),
        "inputs": {
            "criterion2_manifest": input_record(criterion2_manifest_path),
            "hypothesis_assessment": input_record(hypothesis_assessment_path),
            "external_closure_candidate_manifest": input_record(closure_candidate_path),
            "external_evidence_attempt_manifest": input_record(external_attempt_path),
            "theorem_review_manifest": input_record(theorem_review_path),
        },
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "readiness_status": (
            STATUS_READY if theorem_closure_assessment_ready else STATUS_BLOCKED
        ),
        "theorem_closure_assessment_ready": theorem_closure_assessment_ready,
        "checks": checks,
        "ready_checks": ready_checks,
        "blocker_groups": blocker_groups,
        "unresolved_promotion_requirements": unresolved,
        "inputs": digest_material["inputs"],
        "readiness_digest_sha256": sha256_text(canonical_json(digest_material)),
        **false_claim_flags(),
        "assessment_boundary": (
            "This preflight only decides whether enough reviewed inputs exist to "
            "start theorem-closure assessment. It requires Criterion 2 proof review, "
            "requires rejection-distribution preservation proof review, and does not "
            "claim selected-backend proof closure."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    """Render a concise theorem-closure readiness summary."""
    lines = [
        "# Theorem Closure Assessment Readiness",
        "",
        "This artifact is a fail-closed preflight for starting theorem-closure "
        "assessment. It is pending theorem-closure review.",
        "",
        f"- Status: `{manifest['readiness_status']}`",
        "- Theorem-closure assessment ready: "
        f"`{str(manifest['theorem_closure_assessment_ready']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Readiness digest SHA-256: `{manifest['readiness_digest_sha256']}`",
        "",
        "Checks:",
    ]
    for name, passed in manifest["checks"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")

    lines.extend(["", "Blocker Groups:"])
    for group, blockers in manifest["blocker_groups"].items():
        lines.append(f"- `{group}`: `{len(blockers)}` blocker(s)")
        for blocker in blockers:
            lines.append(f"  - {blocker}")

    lines.extend(
        [
            "",
            "This preflight keeps all closure claim flags false. A ready result "
            "would only mean the repository has enough reviewed input material "
            "to begin theorem-closure assessment.",
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
    """Write theorem-closure readiness artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Assess theorem-closure assessment readiness"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--criterion2-manifest", default=None)
    parser.add_argument("--hypothesis-assessment", default=None)
    parser.add_argument("--closure-candidate", default=None)
    parser.add_argument("--external-attempt", default=None)
    parser.add_argument("--theorem-review", default=None)
    parser.add_argument(
        "--out",
        default="artifacts/theorem-closure-readiness/latest",
        help="theorem-closure readiness artifact output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero until theorem-closure assessment readiness is true",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(
        Path(args.root),
        criterion2_manifest_path=args.criterion2_manifest,
        hypothesis_assessment_path=args.hypothesis_assessment,
        closure_candidate_path=args.closure_candidate,
        external_attempt_path=args.external_attempt,
        theorem_review_path=args.theorem_review,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote theorem-closure readiness artifacts to {args.out}")
    if args.strict and not report["manifest"]["theorem_closure_assessment_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
