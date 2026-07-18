#!/usr/bin/env python3
"""Fail-closed assessment for an internal theorem-closure candidate.

This assessor intentionally does not consume theorem-closure *readiness*
artifacts as closure evidence.  It requires five substantive criterion
manifests plus separate reproducibility and provenance manifests.  A passing
result means only ``internally_closed_pending_independent_review``; independent
cryptographic review remains required and incomplete by definition.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path


ASSESSMENT_SCHEMA = "lattice-aggregation:internal-theorem-closure-assessment:v1"
CRITERION_SCHEMA = (
    "lattice-aggregation:internal-theorem-closure-criterion-evidence:v1"
)
BUNDLE_SCHEMA = "lattice-aggregation:internal-theorem-closure-bundle:v1"
CAMPAIGN_VALIDATION_SCHEMA = (
    "lattice-aggregation:internal-aggregation-campaign-validation:v1"
)

STATUS_CLOSED = "internally_closed_pending_independent_review"
STATUS_BLOCKED = "blocked_before_internal_theorem_closure"
EVIDENCE_CLASS = "substantive_proof_and_execution_evidence"
SAFE_SOURCE_CLASS = "production_real_distributed_threshold"
PENDING_REVIEW_STATUS = "pending_independent_cryptographic_review"
CAMPAIGN_READY_STATUS = "internal_campaign_evidence_ready"
BUNDLE_CLAIM_BOUNDARY = (
    "internal theorem-closure candidate only; pending independent cryptographic review"
)
CRITERION_READY_STATUS = "internally_closed_candidate"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_SOURCE_MARKERS = ("hazmat", "simulat", "quarantin")

CRITERIA = {
    "aggregate_mask_distribution": (
        "selected_mask_construction_proven",
        "centralized_distribution_reference_bound",
        "aggregate_distribution_bound",
        "distribution_distance_bound_nonvacuous",
    ),
    "aggregate_rejection_equivalence": (
        "real_threshold_recomputation_verified",
        "standard_verifier_accepts",
        "rejection_predicates_equivalent",
        "mutation_cases_rejected",
    ),
    "abort_retry_bias": (
        "retry_domain_separation_proven",
        "abort_leakage_bound_proven",
        "accepted_output_distribution_proven",
        "adversarial_abort_corpus_passed",
    ),
    "partial_contribution_soundness": (
        "vss_dkg_binding_hiding_proven",
        "partial_context_binding_proven",
        "malicious_partials_rejected",
        "local_accept_leakage_reviewed",
    ),
    "unauthorized_aggregate_reduction": (
        "euf_cma_reduction_complete",
        "base_theorem_dependency_bound",
        "simulator_complete",
        "hybrid_bound_nonvacuous",
        "subthreshold_forgery_reduction_complete",
    ),
}

PROTOCOL_PROFILE = {
    "profile_id": "native-threshold-mldsa65-mpc-no-reconstruction-v1",
    "parameter_set": "ML-DSA-65",
    "validator_count": 10_000,
    "threshold": 6_667,
    "maximum_committee_size": 64,
    "standard_wire_signature_bytes": 3_309,
    "no_secret_or_seed_reconstruction": True,
    "exact_distributed_keygen": True,
    "per_receiver_private_share_custody": True,
    "exact_expand_mask_mpc": True,
    "committee_authorization_bound_to_validator_threshold": True,
}

BUNDLE_CHECKS = (
    "five_criteria_present",
    "all_criteria_internally_closed",
    "source_claim_boundary_preserved",
    "source_inventory_present",
    "artifact_inventory_present",
    "toolchain_identified",
    "clean_git_provenance",
    "campaign_binding_ready",
)

BUNDLE_PUBLIC_CLAIMS = (
    "claims_theorem_closure",
    "claims_criterion_met",
    "claims_internal_theorem_closure",
    "claims_selected_backend_proof_closure",
    "claims_mask_distribution_proven",
    "claims_rejection_distribution_preservation",
    "claims_standard_verifier_compatibility_complete",
    "claims_production_threshold_mldsa_security",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)

CRITERION_DIGESTS = (
    "protocol_spec_digest",
    "proof_digest",
    "implementation_digest",
    "test_evidence_digest",
)

ALLOWED_FALSE_CLAIMS = {
    "claims_independent_review_complete",
    "claims_external_validation_complete",
}


def canonical_json(value):
    """Return stable, pretty JSON with a trailing newline."""
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_path(path):
    path = Path(path)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_local_script(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"local script is unavailable: {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_campaign_validator():
    return load_local_script(
        "internal_aggregation_campaign_validator_for_assessor",
        "validate_internal_aggregation_campaign_capture.py",
    )


def load_bundle_builder():
    return load_local_script(
        "internal_theorem_closure_bundle_builder_for_assessor",
        "build_internal_theorem_closure_bundle.py",
    )


def run_git(root, arguments):
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def current_provenance(root):
    commit = run_git(root, ["rev-parse", "HEAD"])
    status = run_git(root, ["status", "--porcelain", "--untracked-files=all"])
    return {
        "repository_available": commit is not None and status is not None,
        "commit": commit,
        "worktree_clean": commit is not None and status == "",
        "changed_paths": (
            sorted(line[3:] for line in status.splitlines() if len(line) > 3)
            if status
            else []
        ),
    }


def verify_inventory(inventory, root):
    """Re-hash every recorded file and recompute the canonical tree digest."""
    if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
        return False
    records = inventory["files"]
    observed = []
    root = Path(root).resolve()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            return False
        path = Path(record["path"])
        path = path if path.is_absolute() else root / path
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            return False
        if not resolved.is_file():
            return False
        size = resolved.stat().st_size
        digest = sha256_path(resolved)
        if (
            record.get("present") is not True
            or record.get("size_bytes") != size
            or record.get("sha256") != digest
        ):
            return False
        observed.append(
            {"path": record["path"], "size_bytes": size, "sha256": digest}
        )
    return (
        inventory.get("file_count") == len(records)
        and len(records) > 0
        and inventory.get("tree_sha256") == sha256_text(canonical_json(observed))
    )


def input_record(path):
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def add_blocker(groups, group, message):
    if message not in groups[group]:
        groups[group].append(message)


def load_json_fail_closed(path):
    path = Path(path)
    if not path.is_file():
        return None, "manifest is missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"manifest is unreadable or invalid JSON: {error}"
    if not isinstance(value, dict):
        return None, "manifest root must be a JSON object"
    return value, None


def review_semantics_valid(document):
    review = document.get("independent_review") if isinstance(document, dict) else None
    return (
        isinstance(review, dict)
        and review.get("required") is True
        and review.get("completed") is False
        and review.get("status") == PENDING_REVIEW_STATUS
    )


def digest_map_checks(digests, required, groups, group):
    valid = True
    if not isinstance(digests, dict):
        add_blocker(groups, group, "digest map is missing")
        return False
    for key in required:
        value = digests.get(key)
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            add_blocker(groups, group, f"missing or invalid SHA-256 digest: {key}")
            valid = False
    return valid


def claim_flags_valid(document, required_true, groups, group):
    flags = document.get("claim_flags") if isinstance(document, dict) else None
    if not isinstance(flags, dict):
        add_blocker(groups, group, "claim_flags object is missing")
        return False

    valid = True
    for key in required_true:
        if flags.get(key) is not True:
            add_blocker(groups, group, f"required substantive claim is not true: {key}")
            valid = False

    for key, value in flags.items():
        if not isinstance(key, str) or not key.startswith("claims_"):
            add_blocker(groups, group, f"invalid claim flag name: {key}")
            valid = False
        elif value is False and key not in ALLOWED_FALSE_CLAIMS:
            add_blocker(groups, group, f"closure input retains a false claim flag: {key}")
            valid = False
        elif not isinstance(value, bool):
            add_blocker(groups, group, f"claim flag must be boolean: {key}")
            valid = False

    for key in ALLOWED_FALSE_CLAIMS:
        if flags.get(key) is not False:
            add_blocker(groups, group, f"pending-review claim must be explicitly false: {key}")
            valid = False
    return valid


def unsafe_source_references(document, input_path):
    """Return unsafe source markers from the path and provenance-like fields."""
    findings = []

    def inspect(value, key=""):
        key_lower = key.lower()
        source_field = any(
            token in key_lower
            for token in ("source", "runner", "generator", "capture_path")
        )
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                inspect(child_value, str(child_key))
        elif isinstance(value, list) and source_field:
            for child in value:
                inspect(child, key)
        elif isinstance(value, str) and source_field:
            lowered = value.lower()
            for marker in UNSAFE_SOURCE_MARKERS:
                if marker in lowered:
                    findings.append(f"{key}={value}")
                    break

    lowered_path = str(input_path).lower()
    if any(marker in lowered_path for marker in UNSAFE_SOURCE_MARKERS):
        findings.append(f"input_path={input_path}")
    inspect(document)
    return sorted(set(findings))


def criterion_checks(criterion_id, document, path, groups):
    group = criterion_id
    checks = {
        "present_and_valid_json": isinstance(document, dict),
        "schema_valid": False,
        "schema_version_valid": False,
        "criterion_id_valid": False,
        "candidate_boundary_valid": False,
        "protocol_profile_valid": False,
        "substantive_evidence_class": False,
        "status_met": False,
        "readiness_only_false": False,
        "substantive_checks_pass": False,
        "digests_complete": False,
        "claim_flags_valid": False,
        "reproducibility_commands_pass": False,
        "internal_review_complete": False,
        "provenance_safe": False,
        "independent_review_pending": False,
    }
    if not isinstance(document, dict):
        return checks

    checks["schema_valid"] = document.get("schema") == CRITERION_SCHEMA
    checks["schema_version_valid"] = document.get("schema_version") == 1
    checks["criterion_id_valid"] = document.get("criterion_id") == criterion_id
    checks["candidate_boundary_valid"] = (
        document.get("claim_boundary") == BUNDLE_CLAIM_BOUNDARY
        and document.get("evidence_status") == CRITERION_READY_STATUS
        and document.get("blockers") == []
    )
    checks["protocol_profile_valid"] = document.get("protocol_profile") == PROTOCOL_PROFILE
    checks["substantive_evidence_class"] = document.get("evidence_class") == EVIDENCE_CLASS
    checks["status_met"] = document.get("assessment_status") == "met"
    checks["readiness_only_false"] = document.get("readiness_only") is False

    expected = CRITERIA[criterion_id]
    substantive = document.get("substantive_checks")
    checks["substantive_checks_pass"] = isinstance(substantive, dict) and all(
        substantive.get(key) is True for key in expected
    )
    checks["digests_complete"] = digest_map_checks(
        document.get("evidence_digests"), CRITERION_DIGESTS, groups, group
    )
    checks["claim_flags_valid"] = claim_flags_valid(
        document,
        ("claims_criterion_met", "claims_substantive_proof_complete"),
        groups,
        group,
    )

    reproducibility = document.get("reproducibility")
    commands = reproducibility.get("commands") if isinstance(reproducibility, dict) else None
    checks["reproducibility_commands_pass"] = (
        isinstance(commands, list)
        and len(commands) > 0
        and all(
            isinstance(command, dict)
            and isinstance(command.get("command"), list)
            and len(command["command"]) > 0
            and command.get("exit_code") == 0
            and command.get("passed") is True
            and isinstance(command.get("output_sha256"), str)
            and SHA256_RE.fullmatch(command["output_sha256"]) is not None
            for command in commands
        )
    )
    internal_review = document.get("internal_review")
    checks["internal_review_complete"] = (
        isinstance(internal_review, dict)
        and internal_review.get("completed") is True
        and isinstance(internal_review.get("reviewed_at"), str)
        and bool(internal_review["reviewed_at"])
        and isinstance(internal_review.get("reviewer_identity_sha256"), str)
        and SHA256_RE.fullmatch(internal_review["reviewer_identity_sha256"]) is not None
        and isinstance(internal_review.get("review_digest_sha256"), str)
        and SHA256_RE.fullmatch(internal_review["review_digest_sha256"]) is not None
        and internal_review.get("independent_review_completed") is False
    )

    provenance = document.get("provenance")
    checks["provenance_safe"] = (
        isinstance(provenance, dict)
        and provenance.get("source_class") == SAFE_SOURCE_CLASS
        and provenance.get("real_distributed_threshold_core_verified") is True
        and provenance.get("simulation") is False
        and provenance.get("hazmat") is False
        and provenance.get("quarantined") is False
        and provenance.get("worktree_clean") is True
        and isinstance(provenance.get("git_commit"), str)
        and GIT_COMMIT_RE.fullmatch(provenance["git_commit"]) is not None
        and not unsafe_source_references(document, path)
    )
    checks["independent_review_pending"] = review_semantics_valid(document)

    messages = {
        "schema_valid": "criterion manifest schema is not the substantive closure schema",
        "schema_version_valid": "criterion manifest schema_version is not 1",
        "criterion_id_valid": "criterion manifest ID does not match its input slot",
        "candidate_boundary_valid": "criterion is not a blocker-free internal closure candidate",
        "protocol_profile_valid": "criterion does not bind the selected no-reconstruction protocol profile",
        "substantive_evidence_class": "criterion evidence is readiness-only or not substantive",
        "status_met": "criterion assessment_status is not met",
        "readiness_only_false": "criterion is marked as readiness-only or omits readiness_only=false",
        "substantive_checks_pass": "one or more criterion-specific substantive checks are not true",
        "claim_flags_valid": "criterion closure claim flags are invalid",
        "reproducibility_commands_pass": "criterion reproducibility commands are absent or did not pass",
        "internal_review_complete": "criterion internal review is incomplete or invalid",
        "provenance_safe": "criterion provenance is not a real, non-hazmat, non-simulated production source",
        "independent_review_pending": "independent review must be explicitly required, incomplete, and pending",
    }
    for check, message in messages.items():
        if not checks[check]:
            add_blocker(groups, group, message)
    return checks


def campaign_validation_checks(document, expected_document, groups):
    """Require the upstream validator's exact 24-case real-campaign result."""
    group = "campaign_validation"
    checks = {
        "present_and_valid_json": isinstance(document, dict),
        "schema_valid": False,
        "campaign_evidence_ready": False,
        "campaign_status_ready": False,
        "all_preregistered_cases_validated": False,
        "request_digest_present": False,
        "capture_digest_present": False,
        "evidence_bundle_binding_digest_present": False,
        "evidence_bindings_present": False,
        "no_campaign_blockers": False,
        "campaign_preserves_nonclosure_boundary": False,
        "deterministic_revalidation_matches": False,
        "authorization_signatures_verified": False,
    }
    if not isinstance(document, dict):
        return checks
    checks["schema_valid"] = document.get("schema") == CAMPAIGN_VALIDATION_SCHEMA
    checks["campaign_evidence_ready"] = (
        document.get("internal_campaign_evidence_ready") is True
    )
    checks["campaign_status_ready"] = (
        document.get("campaign_status") == CAMPAIGN_READY_STATUS
    )
    checks["all_preregistered_cases_validated"] = (
        document.get("preregistered_case_count") == 24
        and document.get("validated_execution_count") == 24
    )
    checks["request_digest_present"] = (
        isinstance(document.get("request_sha256"), str)
        and SHA256_RE.fullmatch(document["request_sha256"]) is not None
    )
    checks["capture_digest_present"] = (
        isinstance(document.get("capture_sha256"), str)
        and SHA256_RE.fullmatch(document["capture_sha256"]) is not None
    )
    checks["evidence_bundle_binding_digest_present"] = (
        isinstance(document.get("evidence_bundle_binding_sha256"), str)
        and SHA256_RE.fullmatch(document["evidence_bundle_binding_sha256"])
        is not None
    )
    evidence_bindings = document.get("evidence_bindings")
    checks["evidence_bindings_present"] = (
        isinstance(evidence_bindings, dict)
        and len(evidence_bindings) > 0
        and all(
            isinstance(value, str) and SHA256_RE.fullmatch(value) is not None
            for value in evidence_bindings.values()
        )
    )
    checks["no_campaign_blockers"] = document.get("blockers") == []
    checks["campaign_preserves_nonclosure_boundary"] = (
        document.get("theorem_status") == "unclosed_pending_proof_and_independent_review"
        and document.get("claims_theorem_closure") is False
        and document.get("claims_fips_validation") is False
    )
    checks["deterministic_revalidation_matches"] = (
        isinstance(expected_document, dict)
        and canonical_json(document) == canonical_json(expected_document)
    )
    authorization = document.get("authorization_verification")
    checks["authorization_signatures_verified"] = (
        isinstance(authorization, dict)
        and authorization.get("required") is True
        and authorization.get("verified") is True
        and isinstance(authorization.get("verifier_id"), str)
        and bool(authorization["verifier_id"])
        and isinstance(authorization.get("verifier_implementation_sha256"), str)
        and SHA256_RE.fullmatch(
            authorization["verifier_implementation_sha256"]
        )
        is not None
    )

    for check, message in {
        "schema_valid": "campaign validation manifest schema is invalid",
        "campaign_evidence_ready": "real distributed campaign evidence is not ready",
        "campaign_status_ready": "campaign validation status is not ready",
        "all_preregistered_cases_validated": "campaign does not validate exactly all 24 preregistered cases",
        "request_digest_present": "campaign request digest is missing or invalid",
        "capture_digest_present": "campaign capture digest is missing or invalid",
        "evidence_bundle_binding_digest_present": "campaign evidence-bundle binding digest is missing or invalid",
        "evidence_bindings_present": "campaign evidence file bindings are absent or invalid",
        "no_campaign_blockers": "campaign validation retains blockers",
        "campaign_preserves_nonclosure_boundary": "campaign validation does not preserve its nonclosure claim boundary",
        "deterministic_revalidation_matches": "campaign validation was not reproduced from the exact request and capture bytes",
        "authorization_signatures_verified": "campaign authorization signatures lack a bound reviewed verifier result",
    }.items():
        if not checks[check]:
            add_blocker(groups, group, message)
    return checks


def bundle_checks(
    document,
    bundle_path,
    criterion_paths,
    campaign_document,
    campaign_path,
    root,
    groups,
):
    """Validate the content-addressed bundle and its embedded criterion records."""
    group = "closure_bundle"
    checks = {
        "present_and_valid_json": isinstance(document, dict),
        "schema_valid": False,
        "bundle_candidate_ready": False,
        "claim_boundary_valid": False,
        "protocol_profile_valid": False,
        "review_semantics_valid": False,
        "public_claims_preserved_false": False,
        "bundle_digest_valid": False,
        "all_bundle_checks_pass": False,
        "all_five_criterion_records_pass": False,
        "clean_provenance": False,
        "campaign_binding_matches": False,
        "source_and_artifact_inventories_bound": False,
        "current_git_provenance_matches": False,
    }
    if not isinstance(document, dict):
        return checks

    checks["schema_valid"] = (
        document.get("schema") == BUNDLE_SCHEMA and document.get("schema_version") == 1
    )
    checks["bundle_candidate_ready"] = (
        document.get("bundle_status") == STATUS_CLOSED
        and document.get("internal_closure_candidate") is True
        and document.get("global_blockers") == []
    )
    checks["claim_boundary_valid"] = (
        document.get("claim_boundary") == BUNDLE_CLAIM_BOUNDARY
    )
    checks["protocol_profile_valid"] = document.get("protocol_profile") == PROTOCOL_PROFILE
    internal_review = document.get("internal_review")
    independent_review = document.get("independent_review")
    checks["review_semantics_valid"] = (
        isinstance(internal_review, dict)
        and internal_review.get("required") is True
        and internal_review.get("completed") is True
        and internal_review.get("status") == "complete"
        and isinstance(independent_review, dict)
        and independent_review.get("required") is True
        and independent_review.get("completed") is False
        and independent_review.get("status") == PENDING_REVIEW_STATUS
    )
    flags = document.get("claim_flags")
    checks["public_claims_preserved_false"] = (
        isinstance(flags, dict)
        and all(flags.get(key) is False for key in BUNDLE_PUBLIC_CLAIMS)
        and not any(value is True for value in flags.values())
    )
    bundle_digest = document.get("bundle_digest_sha256")
    try:
        builder = load_bundle_builder()
        expected_bundle_digest = sha256_text(
            canonical_json(builder.bundle_digest_material(document))
        )
    except Exception:
        expected_bundle_digest = None
    checks["bundle_digest_valid"] = (
        isinstance(bundle_digest, str)
        and SHA256_RE.fullmatch(bundle_digest) is not None
        and bundle_digest != "0" * 64
        and bundle_digest == expected_bundle_digest
    )
    bundle_check_map = document.get("checks")
    checks["all_bundle_checks_pass"] = (
        isinstance(bundle_check_map, dict)
        and all(bundle_check_map.get(key) is True for key in BUNDLE_CHECKS)
    )

    criteria = document.get("criteria")
    criteria_by_id = (
        {
            item.get("criterion_id"): item
            for item in criteria
            if isinstance(item, dict) and isinstance(item.get("criterion_id"), str)
        }
        if isinstance(criteria, list)
        else {}
    )
    expected_ids = set(CRITERIA)
    criterion_records_valid = (
        isinstance(criteria, list)
        and len(criteria) == len(expected_ids)
        and set(criteria_by_id) == expected_ids
    )
    if criterion_records_valid:
        for criterion_id in CRITERIA:
            record = criteria_by_id[criterion_id]
            record_checks = record.get("checks")
            review = record.get("internal_review")
            evidence_input = record.get("evidence_input")
            criterion_records_valid = criterion_records_valid and (
                record.get("assessment_status") == "met"
                and record.get("declared_evidence_status") == CRITERION_READY_STATUS
                and record.get("bundle_evidence_status") == CRITERION_READY_STATUS
                and record.get("internal_closure_ready") is True
                and record.get("blockers") == []
                and isinstance(record_checks, dict)
                and bool(record_checks)
                and all(value is True for value in record_checks.values())
                and isinstance(review, dict)
                and review.get("valid") is True
                and isinstance(review.get("record"), dict)
                and review["record"].get("completed") is True
                and review["record"].get("independent_review_completed") is False
                and isinstance(evidence_input, dict)
                and evidence_input.get("present") is True
                and isinstance(evidence_input.get("sha256"), str)
                and SHA256_RE.fullmatch(evidence_input["sha256"]) is not None
                and evidence_input["sha256"] == sha256_path(criterion_paths[criterion_id])
            )
    checks["all_five_criterion_records_pass"] = criterion_records_valid

    provenance = document.get("provenance")
    checks["clean_provenance"] = (
        isinstance(provenance, dict)
        and provenance.get("repository_available") is True
        and provenance.get("worktree_clean") is True
        and isinstance(provenance.get("commit"), str)
        and GIT_COMMIT_RE.fullmatch(provenance["commit"]) is not None
        and provenance.get("changed_paths") == []
    )
    observed_provenance = current_provenance(root)
    checks["current_git_provenance_matches"] = (
        checks["clean_provenance"]
        and observed_provenance["repository_available"] is True
        and observed_provenance["worktree_clean"] is True
        and provenance.get("commit") == observed_provenance["commit"]
        and provenance.get("changed_paths") == observed_provenance["changed_paths"]
    )

    campaign = document.get("campaign")
    bundle_inputs = document.get("inputs")
    campaign_input = (
        bundle_inputs.get("campaign_validation")
        if isinstance(bundle_inputs, dict)
        else None
    )
    campaign_file_digest = sha256_path(campaign_path)
    checks["campaign_binding_matches"] = (
        isinstance(campaign_document, dict)
        and isinstance(campaign, dict)
        and campaign.get("ready") is True
        and campaign.get("blockers") == []
        and campaign.get("request_sha256") == campaign_document.get("request_sha256")
        and campaign.get("capture_sha256") == campaign_document.get("capture_sha256")
        and campaign.get("evidence_bundle_binding_sha256")
        == campaign_document.get("evidence_bundle_binding_sha256")
        and isinstance(campaign_input, dict)
        and campaign_input.get("present") is True
        and campaign_input.get("sha256") == campaign_file_digest
    )

    source_inventory = document.get("source_inventory")
    artifact_inventory = document.get("artifact_inventory")
    checks["source_and_artifact_inventories_bound"] = verify_inventory(
        source_inventory, root
    ) and verify_inventory(artifact_inventory, root)

    for check, message in {
        "schema_valid": "closure bundle schema or version is invalid",
        "bundle_candidate_ready": "closure bundle is blocked or not an internal closure candidate",
        "claim_boundary_valid": "closure bundle claim boundary is invalid",
        "protocol_profile_valid": "closure bundle does not bind the selected no-reconstruction protocol profile",
        "review_semantics_valid": "bundle must complete internal review while keeping independent review explicitly pending",
        "public_claims_preserved_false": "closure bundle crosses a public/security claim boundary",
        "bundle_digest_valid": "closure bundle digest is missing, invalid, or does not authenticate its canonical fields",
        "all_bundle_checks_pass": "one or more closure bundle checks are not true",
        "all_five_criterion_records_pass": "bundle does not contain five passing content-addressed criterion records",
        "clean_provenance": "bundle provenance is dirty, unpinned, or unavailable",
        "campaign_binding_matches": "bundle does not bind the exact validated campaign manifest",
        "source_and_artifact_inventories_bound": "bundle source/artifact inventories are empty or lack tree digests",
        "current_git_provenance_matches": "bundle provenance does not match the current clean Git commit and worktree",
    }.items():
        if not checks[check]:
            add_blocker(groups, group, message)
    return checks


def default_criterion_path(root, criterion_id):
    return (
        Path(root)
        / "artifacts"
        / "internal-theorem-closure-evidence"
        / "latest"
        / f"{criterion_id}.json"
    )


def default_campaign_validation_path(root):
    return (
        Path(root)
        / "artifacts/internal-aggregation-campaign/latest/manifest.json"
    )


def default_campaign_request_path(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest/request.json"


def default_campaign_capture_path(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest/capture.json"


def default_bundle_path(root):
    return Path(root) / "artifacts/internal-theorem-closure-bundle/latest/manifest.json"


def build_report(
    root,
    criterion_paths=None,
    campaign_request_path=None,
    campaign_capture_path=None,
    campaign_validation_path=None,
    bundle_path=None,
    authorization_verifier=None,
):
    root = Path(root)
    criterion_paths = criterion_paths or {}
    resolved_criteria = {
        criterion_id: Path(
            criterion_paths.get(criterion_id) or default_criterion_path(root, criterion_id)
        )
        for criterion_id in CRITERIA
    }
    campaign_validation_path = Path(
        campaign_validation_path or default_campaign_validation_path(root)
    )
    campaign_request_path = Path(
        campaign_request_path or default_campaign_request_path(root)
    )
    campaign_capture_path = Path(
        campaign_capture_path or default_campaign_capture_path(root)
    )
    bundle_path = Path(bundle_path or default_bundle_path(root))

    groups = {criterion_id: [] for criterion_id in CRITERIA}
    groups.update({"campaign_validation": [], "closure_bundle": []})
    inputs = {}
    checks = {"criteria": {}}

    for criterion_id, path in resolved_criteria.items():
        document, error = load_json_fail_closed(path)
        inputs[criterion_id] = input_record(path)
        if error:
            add_blocker(groups, criterion_id, error)
        checks["criteria"][criterion_id] = criterion_checks(
            criterion_id, document, path, groups
        )

    campaign_request, request_error = load_json_fail_closed(campaign_request_path)
    campaign_capture, capture_error = load_json_fail_closed(campaign_capture_path)
    inputs["campaign_request"] = input_record(campaign_request_path)
    inputs["campaign_capture"] = input_record(campaign_capture_path)
    expected_campaign = None
    if request_error is None and capture_error is None:
        try:
            validator = load_campaign_validator()
            expected_campaign = validator.validate_campaign(
                campaign_request,
                campaign_capture,
                campaign_capture_path.parent,
                authorization_verifier=authorization_verifier,
            )
        except Exception as error:
            add_blocker(
                groups,
                "campaign_validation",
                f"deterministic campaign revalidation failed: {type(error).__name__}",
            )
    else:
        if request_error:
            add_blocker(groups, "campaign_validation", f"campaign request {request_error}")
        if capture_error:
            add_blocker(groups, "campaign_validation", f"campaign capture {capture_error}")

    campaign, error = load_json_fail_closed(campaign_validation_path)
    inputs["campaign_validation"] = input_record(campaign_validation_path)
    if error:
        add_blocker(groups, "campaign_validation", error)
    checks["campaign_validation"] = campaign_validation_checks(
        campaign, expected_campaign, groups
    )

    bundle, error = load_json_fail_closed(bundle_path)
    inputs["closure_bundle"] = input_record(bundle_path)
    if error:
        add_blocker(groups, "closure_bundle", error)
    checks["closure_bundle"] = bundle_checks(
        bundle,
        bundle_path,
        resolved_criteria,
        campaign,
        campaign_validation_path,
        root,
        groups,
    )

    blockers = [message for messages in groups.values() for message in messages]
    closed = not blockers and all(
        all(value is True for value in criterion.values())
        for criterion in checks["criteria"].values()
    ) and all(value is True for value in checks["campaign_validation"].values()) and all(
        value is True for value in checks["closure_bundle"].values()
    )

    manifest = {
        "schema": ASSESSMENT_SCHEMA,
        "assessment_status": STATUS_CLOSED if closed else STATUS_BLOCKED,
        "internally_closed_pending_independent_review": closed,
        "independent_review": {
            "required": True,
            "completed": False,
            "status": PENDING_REVIEW_STATUS,
        },
        "claim_flags": {
            "claims_internal_theorem_closure": closed,
            "claims_independent_review_complete": False,
            "claims_external_validation_complete": False,
        },
        "criteria_required": list(CRITERIA),
        "checks": checks,
        "blocker_groups": groups,
        "blockers": blockers,
        "inputs": inputs,
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    lines = [
        "# Internal Theorem-Closure Assessment",
        "",
        f"- Status: `{manifest['assessment_status']}`",
        "- Independent cryptographic review required: `true`",
        "- Independent cryptographic review completed: `false`",
        "",
    ]
    if manifest["blockers"]:
        lines.extend(["## Blockers", ""])
        for group, messages in manifest["blocker_groups"].items():
            for message in messages:
                lines.append(f"- `{group}`: {message}")
        lines.append("")
    else:
        lines.extend(
            [
                "All five substantive criteria, reproducibility checks, and provenance checks pass.",
                "",
            ]
        )
    lines.extend(
        [
            "This status is an internal closure candidate only. It does not claim that independent",
            "cryptographic review, external validation, CAVP/ACVTS validation, or FIPS validation",
            "has completed.",
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
        description="Assess an internal theorem-closure candidate, fail closed"
    )
    parser.add_argument("--root", default=".", help="repository root")
    for criterion_id in CRITERIA:
        parser.add_argument(f"--{criterion_id.replace('_', '-')}", default=None)
    parser.add_argument("--campaign-request", default=None)
    parser.add_argument("--campaign-capture", default=None)
    parser.add_argument("--campaign-validation", default=None)
    parser.add_argument("--closure-bundle", default=None)
    parser.add_argument(
        "--out",
        default="artifacts/internal-theorem-closure/latest",
        help="assessment artifact output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 unless the internal closure candidate passes",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    criterion_paths = {
        criterion_id: getattr(args, criterion_id)
        for criterion_id in CRITERIA
        if getattr(args, criterion_id) is not None
    }
    report = build_report(
        Path(args.root),
        criterion_paths=criterion_paths,
        campaign_request_path=args.campaign_request,
        campaign_capture_path=args.campaign_capture,
        campaign_validation_path=args.campaign_validation,
        bundle_path=args.closure_bundle,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote internal theorem-closure assessment to {args.out}")
    if args.strict and not report["manifest"][
        "internally_closed_pending_independent_review"
    ]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
