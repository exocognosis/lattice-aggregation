#!/usr/bin/env python3
"""Run the internal theorem-closure attempt pipeline, fail closed.

This orchestrates the three closure inputs that matter now:

* a real 24-case n=10000, t=6667 distributed aggregation campaign capture;
* five passing substantive criterion proof manifests;
* a clean-provenance internal bundle with two internal reviewer signatures.

The script does not manufacture any of those inputs.  It refreshes the
repo-owned request/validation/bundle/assessment artifacts and writes a compact
attempt manifest that records which required inputs are present and which
blockers remain.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import sys
import time
from pathlib import Path


ATTEMPT_SCHEMA = "lattice-aggregation:internal-theorem-closure-attempt:v1"
NAME = "internal-theorem-closure-attempt-v1"
DEFAULT_CAMPAIGN_ID = "theorem-closure-internal-001"
DEFAULT_OUT = "artifacts/internal-theorem-closure-attempt/latest"
STATUS_READY = "internally_closed_pending_independent_review"
STATUS_BLOCKED = "blocked_before_internal_closure"
CLAIM_BOUNDARY = (
    "closure attempt only; theorem closure requires real campaign evidence, "
    "five substantive proof manifests, clean internal review, and independent "
    "cryptographic review"
)
CRITERIA = (
    "aggregate_mask_distribution",
    "aggregate_rejection_equivalence",
    "abort_retry_bias",
    "partial_contribution_soundness",
    "unauthorized_aggregate_reduction",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_path(path):
    path = Path(path)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_digest(value):
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def load_script(script_name):
    path = Path(__file__).with_name(script_name)
    spec = importlib.util.spec_from_file_location(script_name.removesuffix(".py"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"script unavailable: {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_campaign_dir(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest"


def default_criterion_dir(root):
    return Path(root) / "artifacts/internal-theorem-closure-evidence/latest"


def default_bundle_dir(root):
    return Path(root) / "artifacts/internal-theorem-closure-bundle/latest"


def default_assessment_dir(root):
    return Path(root) / "artifacts/internal-theorem-closure/latest"


def default_attempt_dir(root):
    return Path(root) / DEFAULT_OUT


def file_record(path):
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "sha256": sha256_path(path),
    }


def load_json(path):
    path = Path(path)
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def unique(messages):
    seen = set()
    result = []
    for message in messages:
        if isinstance(message, str) and message and message not in seen:
            seen.add(message)
            result.append(message)
    return result


def flatten_blockers(groups):
    if not isinstance(groups, dict):
        return []
    blockers = []
    for group, messages in groups.items():
        if not isinstance(messages, list):
            continue
        blockers.extend(f"{group}: {message}" for message in messages)
    return unique(blockers)


def valid_reviewer_signature(record):
    if not isinstance(record, dict):
        return False
    identity = record.get("reviewer_identity_sha256")
    signature_digest = record.get("signature_sha256") or record.get(
        "review_signature_sha256"
    )
    signed_payload = record.get("signed_payload_sha256") or record.get(
        "reviewed_payload_sha256"
    )
    verdict = record.get("verdict")
    return (
        is_digest(identity)
        and is_digest(signature_digest)
        and is_digest(signed_payload)
        and verdict in ("accepted", "approved", "passed")
    )


def collect_reviewer_signatures(bundle, criterion_documents):
    """Return valid reviewer signature records from bundle/criterion manifests.

    The current fail-closed criterion schema records a reviewer identity digest,
    not a cryptographic signature.  This helper deliberately requires explicit
    signature records so identity-only placeholders cannot satisfy the target.
    """
    candidates = []
    if isinstance(bundle, dict):
        internal_review = bundle.get("internal_review")
        if isinstance(internal_review, dict):
            signatures = internal_review.get("reviewer_signatures")
            if isinstance(signatures, list):
                candidates.extend(signatures)
    for document in criterion_documents:
        if not isinstance(document, dict):
            continue
        internal_review = document.get("internal_review")
        if not isinstance(internal_review, dict):
            continue
        signatures = internal_review.get("reviewer_signatures")
        if isinstance(signatures, list):
            candidates.extend(signatures)
    valid = [record for record in candidates if valid_reviewer_signature(record)]
    identities = sorted({record["reviewer_identity_sha256"] for record in valid})
    return {
        "valid_signature_count": len(valid),
        "distinct_reviewer_count": len(identities),
        "reviewer_identity_sha256": identities,
        "records": valid,
    }


def campaign_target(request, capture, validation):
    authorization = (
        validation.get("authorization_verification")
        if isinstance(validation, dict)
        else None
    )
    topology = request.get("topology") if isinstance(request, dict) else None
    core = capture.get("cryptographic_core") if isinstance(capture, dict) else None
    checks = {
        "request_present": isinstance(request, dict),
        "capture_present": isinstance(capture, dict),
        "validation_present": isinstance(validation, dict),
        "n_10000": isinstance(topology, dict)
        and topology.get("validator_count") == 10_000,
        "t_6667": isinstance(topology, dict) and topology.get("threshold") == 6_667,
        "exact_24_case_matrix": isinstance(validation, dict)
        and validation.get("preregistered_case_count") == 24
        and validation.get("validated_execution_count") == 24,
        "real_distributed_evidence_class": isinstance(capture, dict)
        and capture.get("evidence_class")
        == "actual_distributed_threshold_mldsa_campaign",
        "actual_distributed_execution_mode": isinstance(capture, dict)
        and capture.get("execution_mode") == "actual_distributed_threshold_backend",
        "strong_threshold_core": isinstance(core, dict)
        and all(
            core.get(key) is True
            for key in (
                "exact_distributed_keygen",
                "per_receiver_private_share_custody",
                "exact_expand_mask_mpc",
                "partial_signing_over_secret_shares",
                "partial_z_i_hint_aggregation",
                "fips204_rejection_loop_over_threshold_partials",
                "no_secret_or_seed_reconstruction",
                "committee_authorization_bound",
            )
        ),
        "authorization_signatures_verified": isinstance(authorization, dict)
        and authorization.get("required") is True
        and authorization.get("verified") is True
        and isinstance(authorization.get("verifier_id"), str)
        and bool(authorization.get("verifier_id"))
        and is_digest(authorization.get("verifier_implementation_sha256")),
        "campaign_validation_ready": isinstance(validation, dict)
        and validation.get("internal_campaign_evidence_ready") is True
        and validation.get("campaign_status") == "internal_campaign_evidence_ready"
        and validation.get("blockers") == [],
    }
    blockers = []
    if isinstance(validation, dict):
        blockers.extend(validation.get("blockers", []))
    if not checks["capture_present"]:
        blockers.append("real distributed campaign capture.json is absent")
    if not checks["authorization_signatures_verified"]:
        blockers.append(
            "campaign authorization signatures are not verified by a bound reviewed verifier"
        )
    failed = [key for key, passed in checks.items() if not passed]
    blockers.extend(f"campaign check failed: {key}" for key in failed)
    ready = all(checks.values())
    return {
        "id": "real_24_case_n10000_t6667_distributed_campaign_capture",
        "required": True,
        "status": "passed" if ready else "blocked",
        "ready": ready,
        "checks": checks,
        "blockers": unique(blockers),
    }


def criteria_target(criterion_documents, assessment):
    checks_by_criterion = (
        assessment.get("checks", {}).get("criteria", {})
        if isinstance(assessment, dict)
        else {}
    )
    blocker_groups = (
        assessment.get("blocker_groups", {}) if isinstance(assessment, dict) else {}
    )
    criteria = {}
    for criterion_id in CRITERIA:
        document = criterion_documents.get(criterion_id)
        checks = checks_by_criterion.get(criterion_id, {})
        ready = isinstance(checks, dict) and bool(checks) and all(
            value is True for value in checks.values()
        )
        blockers = []
        group_blockers = blocker_groups.get(criterion_id)
        if isinstance(group_blockers, list):
            blockers.extend(group_blockers)
        if not isinstance(document, dict):
            blockers.append("criterion manifest is missing or invalid JSON")
        elif document.get("evidence_status") != "internally_closed_candidate":
            blockers.append(
                f"criterion evidence_status is {document.get('evidence_status')!r}"
            )
        criteria[criterion_id] = {
            "status": "passed" if ready else "blocked",
            "ready": ready,
            "evidence_status": (
                document.get("evidence_status") if isinstance(document, dict) else None
            ),
            "assessment_status": (
                document.get("assessment_status") if isinstance(document, dict) else None
            ),
            "checks": checks if isinstance(checks, dict) else {},
            "blockers": unique(blockers),
        }
    ready_count = sum(1 for item in criteria.values() if item["ready"])
    ready = ready_count == len(CRITERIA)
    blockers = []
    if ready_count != len(CRITERIA):
        blockers.append(
            "passing substantive proof manifests for all five criteria are absent or incomplete"
        )
    blockers.extend(flatten_blockers(blocker_groups))
    return {
        "id": "passing_substantive_proof_manifests_for_all_five_criteria",
        "required": True,
        "status": "passed" if ready else "blocked",
        "ready": ready,
        "ready_count": ready_count,
        "required_count": len(CRITERIA),
        "criteria": criteria,
        "blockers": unique(blockers),
    }


def bundle_target(bundle, assessment, reviewer_signatures):
    bundle_checks = bundle.get("checks") if isinstance(bundle, dict) else {}
    assessment_closed = (
        isinstance(assessment, dict)
        and assessment.get("internally_closed_pending_independent_review") is True
        and assessment.get("assessment_status") == STATUS_READY
    )
    clean_provenance = (
        isinstance(bundle, dict)
        and isinstance(bundle_checks, dict)
        and bundle_checks.get("clean_git_provenance") is True
        and bundle.get("provenance", {}).get("worktree_clean") is True
    )
    two_reviewers = (
        reviewer_signatures["valid_signature_count"] >= 2
        and reviewer_signatures["distinct_reviewer_count"] >= 2
    )
    checks = {
        "bundle_present": isinstance(bundle, dict),
        "bundle_internal_closure_candidate": isinstance(bundle, dict)
        and bundle.get("internal_closure_candidate") is True
        and bundle.get("bundle_status") == STATUS_READY,
        "clean_git_provenance": clean_provenance,
        "two_internal_reviewer_signatures": two_reviewers,
        "assessment_confirms_internal_candidate": assessment_closed,
    }
    blockers = []
    if isinstance(bundle, dict):
        blockers.extend(bundle.get("global_blockers", []))
    if isinstance(assessment, dict):
        closure_blockers = assessment.get("blocker_groups", {}).get("closure_bundle")
        if isinstance(closure_blockers, list):
            blockers.extend(f"closure bundle: {item}" for item in closure_blockers)
    if not two_reviewers:
        blockers.append(
            "two distinct internal reviewer signature records are missing or invalid"
        )
    blockers.extend(f"bundle check failed: {key}" for key, passed in checks.items() if not passed)
    ready = all(checks.values())
    return {
        "id": "internal_closure_bundle_clean_provenance_two_internal_reviewers",
        "required": True,
        "status": "passed" if ready else "blocked",
        "ready": ready,
        "checks": checks,
        "reviewer_signatures": reviewer_signatures,
        "blockers": unique(blockers),
    }


def refresh_artifacts(args):
    root = Path(args.root)
    campaign_dir = Path(args.campaign_out or default_campaign_dir(root))
    criterion_dir = Path(args.criterion_evidence_dir or default_criterion_dir(root))
    bundle_dir = Path(args.bundle_out or default_bundle_dir(root))
    assessment_dir = Path(args.assessment_out or default_assessment_dir(root))
    campaign_request_path = Path(args.campaign_request or (campaign_dir / "request.json"))
    campaign_capture_path = Path(args.campaign_capture or (campaign_dir / "capture.json"))
    campaign_validation_path = Path(
        args.campaign_validation or (campaign_dir / "manifest.json")
    )

    campaign_builder = load_script("build_internal_aggregation_campaign_request.py")
    campaign_validator = load_script("validate_internal_aggregation_campaign_capture.py")
    criterion_builder = load_script("build_internal_theorem_closure_criterion_inputs.py")
    bundle_builder = load_script("build_internal_theorem_closure_bundle.py")
    assessor = load_script("assess_internal_theorem_closure.py")

    if not args.skip_campaign_request:
        request_report = campaign_builder.build_request(args.campaign_id)
        campaign_builder.write_artifacts(request_report, campaign_dir)
        campaign_request_path = campaign_dir / "request.json"

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
        io.StringIO()
    ):
        campaign_validator.main(
            [
                "--request",
                str(campaign_request_path),
                "--capture",
                str(campaign_capture_path),
                "--out",
                str(campaign_validation_path.parent),
            ]
        )

    if not args.skip_criterion_inputs:
        criterion_report = criterion_builder.build_report(root)
        criterion_builder.write_artifacts(criterion_report, criterion_dir)

    bundle_report = bundle_builder.build_report(
        root,
        campaign_request_path=campaign_request_path,
        campaign_capture_path=campaign_capture_path,
        campaign_validation_path=campaign_validation_path,
        evidence_dir=criterion_dir,
    )
    bundle_builder.write_artifacts(bundle_report, bundle_dir)

    assessment_report = assessor.build_report(
        root,
        campaign_request_path=campaign_request_path,
        campaign_capture_path=campaign_capture_path,
        campaign_validation_path=campaign_validation_path,
        bundle_path=bundle_dir / "manifest.json",
        criterion_paths={
            criterion_id: criterion_dir / f"{criterion_id}.json"
            for criterion_id in CRITERIA
        },
    )
    assessor.write_artifacts(assessment_report, assessment_dir)

    return {
        "campaign_request": campaign_request_path,
        "campaign_capture": campaign_capture_path,
        "campaign_validation": campaign_validation_path,
        "criterion_dir": criterion_dir,
        "bundle": bundle_dir / "manifest.json",
        "assessment": assessment_dir / "manifest.json",
    }


def build_attempt(root, paths, generated_at=None):
    root = Path(root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    request = load_json(paths["campaign_request"])
    capture = load_json(paths["campaign_capture"])
    campaign_validation = load_json(paths["campaign_validation"])
    criterion_documents = {
        criterion_id: load_json(Path(paths["criterion_dir"]) / f"{criterion_id}.json")
        for criterion_id in CRITERIA
    }
    bundle = load_json(paths["bundle"])
    assessment = load_json(paths["assessment"])

    campaign = campaign_target(request, capture, campaign_validation)
    criteria = criteria_target(criterion_documents, assessment)
    reviewer_signatures = collect_reviewer_signatures(
        bundle, criterion_documents.values()
    )
    bundle_item = bundle_target(bundle, assessment, reviewer_signatures)
    requested_items = [campaign, criteria, bundle_item]
    closed = all(item["ready"] for item in requested_items)
    blockers = []
    for item in requested_items:
        blockers.extend(f"{item['id']}: {blocker}" for blocker in item["blockers"])
    blockers = unique(blockers)
    manifest = {
        "schema": ATTEMPT_SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "attempt_status": STATUS_READY if closed else STATUS_BLOCKED,
        "internally_closed_pending_independent_review": closed,
        "requested_items": requested_items,
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
            "claims_internal_theorem_closure": closed,
            "claims_independent_review_complete": False,
            "claims_external_validation_complete": False,
        },
        "inputs": {
            "campaign_request": file_record(paths["campaign_request"]),
            "campaign_capture": file_record(paths["campaign_capture"]),
            "campaign_validation": file_record(paths["campaign_validation"]),
            "criterion_evidence_dir": str(paths["criterion_dir"]),
            "closure_bundle": file_record(paths["bundle"]),
            "internal_assessment": file_record(paths["assessment"]),
        },
        "blockers": blockers,
        "next_required_artifacts": [
            "admissible real 24-case n=10000/t=6667 distributed campaign capture",
            "five internally closed substantive criterion manifests",
            "clean-provenance internal closure bundle with two distinct internal reviewer signatures",
            "independent cryptographic review after internal closure",
        ],
    }
    digest_material = dict(manifest)
    manifest["attempt_digest_sha256"] = sha256_text(canonical_json(digest_material))
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    lines = [
        "# Internal Theorem-Closure Attempt",
        "",
        f"- Attempt status: `{manifest['attempt_status']}`",
        f"- Internal closure candidate: `{str(manifest['internally_closed_pending_independent_review']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Attempt digest SHA-256: `{manifest['attempt_digest_sha256']}`",
        "",
        "## Requested Items",
        "",
    ]
    for item in manifest["requested_items"]:
        lines.append(f"- `{item['id']}`: `{item['status']}`")
    lines.extend(["", "## Blockers", ""])
    if manifest["blockers"]:
        lines.extend(f"- {blocker}" for blocker in manifest["blockers"])
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "This attempt remains non-promotional unless every requested item is present",
            "and the independent cryptographic review boundary is preserved.",
            "",
        ]
    )
    return "\n".join(lines)


def write_artifacts(report, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }
    contents["SHA256SUMS"] = "".join(
        f"{sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run an internal theorem-closure attempt and fail closed"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--campaign-out", default=None)
    parser.add_argument("--campaign-request", default=None)
    parser.add_argument("--campaign-capture", default=None)
    parser.add_argument("--campaign-validation", default=None)
    parser.add_argument("--criterion-evidence-dir", default=None)
    parser.add_argument("--bundle-out", default=None)
    parser.add_argument("--assessment-out", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--skip-campaign-request",
        action="store_true",
        help="do not rebuild the preregistered campaign request",
    )
    parser.add_argument(
        "--skip-criterion-inputs",
        action="store_true",
        help="do not rebuild fail-closed criterion input manifests",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 unless the internal closure attempt passes",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    paths = refresh_artifacts(args)
    report = build_attempt(root, paths)
    out = Path(args.out) if args.out else default_attempt_dir(root)
    write_artifacts(report, out)
    manifest = report["manifest"]
    print(f"attempt_status={manifest['attempt_status']}")
    print(f"blockers={len(manifest['blockers'])}")
    if args.strict and not manifest["internally_closed_pending_independent_review"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
