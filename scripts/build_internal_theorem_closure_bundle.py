#!/usr/bin/env python3
"""Build a fail-closed internal theorem-closure evidence bundle.

This builder packages evidence; it does not itself prove a criterion. A
criterion can become an internal closure candidate only when its substantive,
content-addressed evidence manifest satisfies the checks below. Legacy
hypothesis/readiness/review manifests are retained as informational context,
not promotion prerequisites. All public theorem/security claim flags remain
false because independent cryptographic review is outside this bundle's
authority.
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path


BUNDLE_SCHEMA = "lattice-aggregation:internal-theorem-closure-bundle:v1"
CRITERION_EVIDENCE_SCHEMA = (
    "lattice-aggregation:internal-theorem-closure-criterion-evidence:v1"
)
NAME = "internal-theorem-closure-bundle-v1"
CLAIM_BOUNDARY = (
    "internal theorem-closure candidate only; pending independent cryptographic review"
)
READY_STATUS = "internally_closed_pending_independent_review"
BLOCKED_STATUS = "blocked_incomplete"
CRITERION_READY_STATUS = "internally_closed_candidate"
CRITERION_BLOCKED_STATUS = "unproven"

CRITERIA = (
    (
        "aggregate_mask_distribution",
        "Aggregate masks match or closely approximate centralized ML-DSA masks.",
    ),
    (
        "aggregate_rejection_equivalence",
        "Aggregate rejection checks match centralized ML-DSA rejection checks.",
    ),
    (
        "abort_retry_bias",
        "Selective aborts and retries do not bias accepted signatures.",
    ),
    (
        "partial_contribution_soundness",
        "Accepted partial contributions are sound, context-bound, and hiding.",
    ),
    (
        "unauthorized_aggregate_reduction",
        "Unauthorized accepting outputs reduce to a named cryptographic failure.",
    ),
)

CLAIM_FLAG_KEYS = (
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

REQUIRED_ARTIFACT_GROUPS = (
    "protocol_spec_artifacts",
    "proof_artifacts",
    "implementation_artifacts",
    "test_artifacts",
)

ARTIFACT_GROUP_DIGEST_KEYS = {
    "protocol_spec_artifacts": "protocol_spec_digest",
    "proof_artifacts": "proof_digest",
    "implementation_artifacts": "implementation_digest",
    "test_artifacts": "test_evidence_digest",
}

CRITERION_SUBSTANTIVE_CHECKS = {
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

CAMPAIGN_REQUEST_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-request:v1"
CAMPAIGN_CAPTURE_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-capture:v1"
CAMPAIGN_VALIDATION_SCHEMA = (
    "lattice-aggregation:internal-aggregation-campaign-validation:v1"
)


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_text(value):
    return sha256_bytes(value.encode("utf-8"))


def sha256_path(path):
    path = Path(path)
    if not path.is_file():
        return None
    return sha256_bytes(path.read_bytes())


def is_digest(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return raw != bytes(32)


def load_campaign_validator():
    """Load the repository validator used for deterministic campaign revalidation."""
    path = Path(__file__).with_name("validate_internal_aggregation_campaign_capture.py")
    spec = importlib.util.spec_from_file_location(
        "internal_aggregation_campaign_validator_for_bundle", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("campaign validator module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bundle_digest_material(document):
    """Return the exact canonical fields authenticated by bundle_digest_sha256."""
    keys = (
        "schema",
        "name",
        "claim_boundary",
        "checks",
        "criteria",
        "source_inventory",
        "artifact_inventory",
        "toolchain",
        "provenance",
        "campaign",
        "global_blockers",
        "legacy_context",
    )
    return {key: document.get(key) for key in keys}


def safe_relative(path, root):
    path = Path(path)
    root = Path(root)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def false_claim_flags():
    return {key: False for key in CLAIM_FLAG_KEYS}


def load_json_if_present(path):
    path = Path(path)
    if not path.is_file():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, str(error)


def file_record(path, root):
    """Hash one file using a clone-stable relative path where possible."""
    path = Path(path)
    present = path.is_file()
    return {
        "path": safe_relative(path, root),
        "present": present,
        "size_bytes": path.stat().st_size if present else None,
        "sha256": sha256_path(path),
    }


def expand_files(paths):
    """Expand declared files/directories into a stable file list."""
    expanded = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file():
            expanded.append(path)
        elif path.is_dir():
            expanded.extend(
                item
                for item in path.rglob("*")
                if item.is_file()
                and "__pycache__" not in item.parts
                and ".git" not in item.parts
            )
    return sorted(set(expanded), key=lambda item: str(item))


def build_inventory(paths, root):
    """Return per-file hashes plus a deterministic tree digest."""
    records = [file_record(path, root) for path in expand_files(paths)]
    digest_material = [
        {
            "path": record["path"],
            "size_bytes": record["size_bytes"],
            "sha256": record["sha256"],
        }
        for record in records
    ]
    return {
        "file_count": len(records),
        "files": records,
        "tree_sha256": sha256_text(canonical_json(digest_material)),
    }


def command_record(command, cwd):
    """Capture a toolchain identity command without invoking a shell."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        return {
            "command": command,
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output_sha256": sha256_text(stdout + "\n" + stderr),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "command": command,
            "exit_code": None,
            "stdout": "",
            "stderr": str(error),
            "output_sha256": sha256_text(str(error)),
        }


def collect_toolchain(root):
    records = [
        command_record(["python3", "--version"], root),
        command_record(["rustc", "--version", "--verbose"], root),
        command_record(["cargo", "--version", "--verbose"], root),
    ]
    return {
        "commands": records,
        "all_identified": all(record["exit_code"] == 0 for record in records),
        "lockfiles": [
            file_record(Path(root) / "Cargo.toml", root),
            file_record(Path(root) / "Cargo.lock", root),
        ],
    }


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
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def collect_provenance(root):
    commit = run_git(root, ["rev-parse", "HEAD"])
    branch = run_git(root, ["branch", "--show-current"])
    status = run_git(root, ["status", "--porcelain", "--untracked-files=all"])
    available = commit is not None and status is not None
    changed_paths = []
    if status:
        changed_paths = sorted(line[3:] for line in status.splitlines() if len(line) > 3)
    return {
        "version_control": "git",
        "repository_available": available,
        "commit": commit,
        "branch": branch,
        "worktree_clean": available and status == "",
        "changed_paths": changed_paths,
        "status_sha256": sha256_text(status or ""),
    }


def default_source_paths(root):
    root = Path(root)
    return [
        root / "Cargo.toml",
        root / "Cargo.lock",
        root / "src",
        root / "scripts",
        root / "docs/cryptography",
    ]


def default_artifact_paths(root):
    root = Path(root)
    return [
        root / "artifacts/hypothesis/latest/assessment.json",
        root / "artifacts/theorem-closure-readiness/latest/manifest.json",
        root / "artifacts/theorem-closure-review/latest/manifest.json",
        root / "artifacts/backend-emission-capture/latest/manifest.json",
        root / "artifacts/backend-emission-capture/latest/capture.json",
        root / "artifacts/p1-rejection-equivalence-batch/latest/batch.json",
        root / "artifacts/internal-aggregation-campaign/latest/request.json",
        root / "artifacts/internal-aggregation-campaign/latest/capture.json",
        root / "artifacts/internal-aggregation-campaign/latest/manifest.json",
        root / "artifacts/internal-aggregation-campaign/latest/request-manifest.json",
    ]


def default_assessment(root):
    return Path(root) / "artifacts/hypothesis/latest/assessment.json"


def default_readiness(root):
    return Path(root) / "artifacts/theorem-closure-readiness/latest/manifest.json"


def default_theorem_review(root):
    return Path(root) / "artifacts/theorem-closure-review/latest/manifest.json"


def default_evidence_dir(root):
    return Path(root) / "artifacts/internal-theorem-closure-evidence/latest"


def default_campaign_request(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest/request.json"


def default_campaign_capture(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest/capture.json"


def default_campaign_validation(root):
    return Path(root) / "artifacts/internal-aggregation-campaign/latest/manifest.json"


def default_out(root):
    return Path(root) / "artifacts/internal-theorem-closure-bundle/latest"


def add_blocker(blockers, message):
    if message not in blockers:
        blockers.append(message)


def assessment_criterion(assessment, criterion_id):
    if not isinstance(assessment, dict):
        return None
    for criterion in assessment.get("criteria", []):
        if isinstance(criterion, dict) and criterion.get("id") == criterion_id:
            return criterion
    return None


def verify_declared_artifact(record, root):
    """Verify a criterion evidence reference against the current filesystem."""
    if not isinstance(record, dict):
        return {
            "path": None,
            "present": False,
            "declared_sha256": None,
            "observed_sha256": None,
            "digest_matches": False,
        }
    declared_path = record.get("path")
    path = Path(declared_path) if isinstance(declared_path, str) else Path("")
    if isinstance(declared_path, str) and not path.is_absolute():
        path = Path(root) / path
    observed = sha256_path(path) if isinstance(declared_path, str) else None
    declared = record.get("sha256")
    return {
        "path": safe_relative(path, root) if isinstance(declared_path, str) else None,
        "present": observed is not None,
        "declared_sha256": declared,
        "observed_sha256": observed,
        "digest_matches": is_digest(declared) and declared == observed,
    }


def criterion_claim_flags_valid(document):
    """Allow internal proof claims while pinning external claims false."""
    if not isinstance(document, dict):
        return False
    flags = document.get("claim_flags")
    return (
        isinstance(flags, dict)
        and flags.get("claims_criterion_met") is True
        and flags.get("claims_substantive_proof_complete") is True
        and flags.get("claims_independent_review_complete") is False
        and flags.get("claims_external_validation_complete") is False
        and all(isinstance(key, str) and key.startswith("claims_") for key in flags)
        and all(isinstance(value, bool) for value in flags.values())
        and not any(
            value is True
            for key, value in flags.items()
            if key not in ("claims_criterion_met", "claims_substantive_proof_complete")
        )
    )


def verify_reproducibility(evidence):
    section = evidence.get("reproducibility", {}) if isinstance(evidence, dict) else {}
    commands = section.get("commands", []) if isinstance(section, dict) else []
    valid = (
        isinstance(commands, list)
        and len(commands) > 0
        and all(
            isinstance(item, dict)
            and isinstance(item.get("command"), list)
            and len(item["command"]) > 0
            and all(isinstance(part, str) and part for part in item["command"])
            and item.get("exit_code") == 0
            and item.get("passed") is True
            and is_digest(item.get("output_sha256"))
            for item in commands
        )
    )
    return {"commands": commands if isinstance(commands, list) else [], "valid": valid}


def verify_internal_review(evidence):
    review = evidence.get("internal_review", {}) if isinstance(evidence, dict) else {}
    valid = (
        isinstance(review, dict)
        and review.get("completed") is True
        and isinstance(review.get("reviewed_at"), str)
        and len(review["reviewed_at"]) > 0
        and is_digest(review.get("reviewer_identity_sha256"))
        and is_digest(review.get("review_digest_sha256"))
        and review.get("independent_review_completed") is False
    )
    return {"record": review if isinstance(review, dict) else {}, "valid": valid}


def build_criterion_record(
    *,
    root,
    criterion_id,
    statement,
    assessment,
    evidence_path,
    source_tree_sha256,
    provenance,
):
    blockers = []
    assessed = assessment_criterion(assessment, criterion_id)
    assessment_status = assessed.get("status") if isinstance(assessed, dict) else None
    # The legacy hypothesis assessor is informational here.  It is not wired to
    # these new substantive manifests and therefore cannot be a prerequisite
    # without creating a circular/unreachable promotion path.

    evidence, parse_error = load_json_if_present(evidence_path)
    if parse_error:
        add_blocker(blockers, f"criterion evidence manifest is invalid JSON: {parse_error}")
    elif evidence is None:
        add_blocker(blockers, "criterion evidence manifest is missing")

    schema_valid = (
        isinstance(evidence, dict)
        and evidence.get("schema") == CRITERION_EVIDENCE_SCHEMA
        and evidence.get("schema_version") == 1
        and evidence.get("criterion_id") == criterion_id
    )
    if evidence is not None and not schema_valid:
        add_blocker(blockers, "criterion evidence schema or criterion_id is invalid")

    boundary_valid = (
        isinstance(evidence, dict)
        and evidence.get("claim_boundary") == CLAIM_BOUNDARY
        and evidence.get("evidence_status") == CRITERION_READY_STATUS
    )
    if evidence is not None and not boundary_valid:
        add_blocker(blockers, "criterion evidence is not an internal closure candidate")

    criterion_claims_valid = criterion_claim_flags_valid(evidence)
    if evidence is not None and not criterion_claims_valid:
        add_blocker(
            blockers,
            "criterion internal claims or pending-independent-review flags are invalid",
        )

    declared_blockers = evidence.get("blockers", []) if isinstance(evidence, dict) else []
    no_declared_blockers = isinstance(declared_blockers, list) and declared_blockers == []
    if evidence is not None and not no_declared_blockers:
        add_blocker(blockers, "criterion evidence declares unresolved blockers")

    artifact_groups = {}
    declared_evidence_digests = (
        evidence.get("evidence_digests", {}) if isinstance(evidence, dict) else {}
    )
    evidence_digests_valid = isinstance(declared_evidence_digests, dict)
    for group in REQUIRED_ARTIFACT_GROUPS:
        declared = evidence.get(group, []) if isinstance(evidence, dict) else []
        verified = (
            [verify_declared_artifact(item, root) for item in declared]
            if isinstance(declared, list)
            else []
        )
        group_digest = sha256_text(
            canonical_json(
                [
                    {"path": item["path"], "sha256": item["observed_sha256"]}
                    for item in verified
                ]
            )
        )
        artifact_groups[group] = {
            "files": verified,
            "group_sha256": group_digest,
        }
        if evidence is not None and (
            len(verified) == 0
            or not all(item["present"] and item["digest_matches"] for item in verified)
        ):
            add_blocker(blockers, f"{group} are missing or fail digest verification")
        digest_key = ARTIFACT_GROUP_DIGEST_KEYS[group]
        if (
            not isinstance(declared_evidence_digests, dict)
            or declared_evidence_digests.get(digest_key) != group_digest
        ):
            evidence_digests_valid = False
            if evidence is not None:
                add_blocker(blockers, f"{digest_key} does not bind the verified artifact group")

    reproducibility = verify_reproducibility(evidence)
    if evidence is not None and not reproducibility["valid"]:
        add_blocker(blockers, "reproducibility commands are incomplete or not recorded passing")

    internal_review = verify_internal_review(evidence)
    if evidence is not None and not internal_review["valid"]:
        add_blocker(blockers, "internal review record is incomplete or crosses the claim boundary")

    evidence_provenance = evidence.get("provenance", {}) if isinstance(evidence, dict) else {}
    provenance_valid = (
        isinstance(evidence_provenance, dict)
        and evidence_provenance.get("source_class")
        == "production_real_distributed_threshold"
        and evidence_provenance.get("real_distributed_threshold_core_verified") is True
        and evidence_provenance.get("simulation") is False
        and evidence_provenance.get("hazmat") is False
        and evidence_provenance.get("quarantined") is False
        and evidence_provenance.get("git_commit") == provenance.get("commit")
        and evidence_provenance.get("worktree_clean") is True
        and provenance.get("worktree_clean") is True
        and evidence_provenance.get("source_tree_sha256") == source_tree_sha256
    )
    if evidence is not None and not provenance_valid:
        add_blocker(
            blockers,
            "criterion provenance does not bind the current clean commit and source tree",
        )

    substantive_checks = (
        evidence.get("substantive_checks", {}) if isinstance(evidence, dict) else {}
    )
    substantive_checks_valid = isinstance(substantive_checks, dict) and all(
        substantive_checks.get(key) is True
        for key in CRITERION_SUBSTANTIVE_CHECKS[criterion_id]
    )
    input_semantics_valid = (
        isinstance(evidence, dict)
        and evidence.get("evidence_class") == "substantive_proof_and_execution_evidence"
        and evidence.get("assessment_status") == "met"
        and evidence.get("readiness_only") is False
        and evidence.get("protocol_profile") == PROTOCOL_PROFILE
        and isinstance(evidence.get("independent_review"), dict)
        and evidence["independent_review"].get("required") is True
        and evidence["independent_review"].get("completed") is False
        and evidence["independent_review"].get("status")
        == "pending_independent_cryptographic_review"
    )
    if evidence is not None and not input_semantics_valid:
        add_blocker(blockers, "criterion substantive/profile/review semantics are invalid")
    if evidence is not None and not substantive_checks_valid:
        add_blocker(blockers, "criterion-specific substantive checks are incomplete")

    checks = {
        "assessment_status_met": isinstance(evidence, dict)
        and evidence.get("assessment_status") == "met",
        "schema_valid": schema_valid,
        "claim_boundary_valid": boundary_valid,
        "criterion_claim_flags_valid": criterion_claims_valid,
        "input_semantics_valid": input_semantics_valid,
        "substantive_checks_valid": substantive_checks_valid,
        "no_declared_blockers": no_declared_blockers,
        "artifact_groups_complete": all(
            len(artifact_groups[group]["files"]) > 0
            and all(
                item["digest_matches"] for item in artifact_groups[group]["files"]
            )
            for group in REQUIRED_ARTIFACT_GROUPS
        ),
        "evidence_digests_bind_artifact_groups": evidence_digests_valid,
        "reproducibility_valid": reproducibility["valid"],
        "internal_review_valid": internal_review["valid"],
        "provenance_valid": provenance_valid,
    }
    ready = all(checks.values()) and blockers == []
    return {
        "criterion_id": criterion_id,
        "statement": statement,
        "assessment_status": (
            evidence.get("assessment_status")
            if isinstance(evidence, dict)
            else assessment_status or "unproven"
        ),
        "legacy_assessment_status": assessment_status or "unproven",
        "declared_evidence_status": (
            evidence.get("evidence_status")
            if isinstance(evidence, dict)
            else CRITERION_BLOCKED_STATUS
        ),
        "bundle_evidence_status": (
            CRITERION_READY_STATUS if ready else CRITERION_BLOCKED_STATUS
        ),
        "internal_closure_ready": ready,
        "claim_boundary": CLAIM_BOUNDARY,
        "protocol_profile": PROTOCOL_PROFILE,
        "claim_flags": false_claim_flags(),
        "evidence_input": file_record(evidence_path, root),
        "checks": checks,
        "artifact_groups": artifact_groups,
        "reproducibility": reproducibility,
        "internal_review": internal_review,
        "blockers": blockers,
    }


def source_claim_boundary_preserved(*documents):
    """Reject true claim flags without mistaking meta-checks such as claims_false."""
    for document in documents:
        if not isinstance(document, dict):
            return False
        stack = [(document, None)]
        while stack:
            value, parent_key = stack.pop()
            if isinstance(value, dict):
                for key, child in value.items():
                    is_claim_flag = (
                        parent_key == "claim_flags"
                        or key in CLAIM_FLAG_KEYS
                        or key
                        in (
                            "claims_external_validation_complete",
                            "claims_independent_review_complete",
                        )
                    )
                    if is_claim_flag and child is True:
                        return False
                    if isinstance(child, (dict, list)):
                        stack.append((child, key))
            elif isinstance(value, list):
                stack.extend(
                    (item, parent_key)
                    for item in value
                    if isinstance(item, (dict, list))
                )
    return True


def validate_campaign_binding(
    request_path,
    capture_path,
    validation_path,
    root,
    authorization_verifier=None,
):
    """Bind the exact preregistered campaign and its fail-closed validator output."""
    request, request_error = load_json_if_present(request_path)
    capture, capture_error = load_json_if_present(capture_path)
    validation, validation_error = load_json_if_present(validation_path)
    request_digest = (
        sha256_text(canonical_json(request)) if isinstance(request, dict) else None
    )
    capture_digest = (
        sha256_text(canonical_json(capture)) if isinstance(capture, dict) else None
    )
    requirements = request.get("capture_requirements", {}) if isinstance(request, dict) else {}
    core = capture.get("cryptographic_core", {}) if isinstance(capture, dict) else {}
    required_strong_flags = (
        "exact_distributed_keygen",
        "per_receiver_private_share_custody",
        "exact_expand_mask_mpc",
        "committee_authorization_bound",
    )
    strong_request = isinstance(requirements, dict) and all(
        requirements.get(key) is True for key in required_strong_flags
    )
    strong_capture = isinstance(core, dict) and all(
        core.get(key) is True for key in required_strong_flags
    )
    expected_validation = None
    if request_error is None and capture_error is None:
        try:
            validator = load_campaign_validator()
            expected_validation = validator.validate_campaign(
                request,
                capture,
                Path(capture_path).parent,
                authorization_verifier=authorization_verifier,
            )
        except Exception:
            expected_validation = None
    deterministic_revalidation = (
        isinstance(validation, dict)
        and isinstance(expected_validation, dict)
        and canonical_json(validation) == canonical_json(expected_validation)
    )
    authorization_verification = (
        expected_validation.get("authorization_verification")
        if isinstance(expected_validation, dict)
        else None
    )
    authorization_valid = (
        isinstance(authorization_verification, dict)
        and authorization_verification.get("required") is True
        and authorization_verification.get("verified") is True
        and isinstance(authorization_verification.get("verifier_id"), str)
        and bool(authorization_verification["verifier_id"])
        and is_digest(
            authorization_verification.get("verifier_implementation_sha256")
        )
    )
    evidence_bindings = validation.get("evidence_bindings") if isinstance(validation, dict) else None
    expected_bundle_binding = None
    if (
        request_digest is not None
        and capture_digest is not None
        and isinstance(evidence_bindings, dict)
    ):
        expected_bundle_binding = sha256_text(
            canonical_json(
                {
                    "request_sha256": request_digest,
                    "capture_sha256": capture_digest,
                    "evidence_bindings": evidence_bindings,
                }
            )
        )
    checks = {
        "request_present_and_valid": request_error is None and isinstance(request, dict),
        "capture_present_and_valid": capture_error is None and isinstance(capture, dict),
        "validation_present_and_valid": validation_error is None
        and isinstance(validation, dict),
        "request_schema_valid": isinstance(request, dict)
        and request.get("schema") == CAMPAIGN_REQUEST_SCHEMA,
        "capture_schema_valid": isinstance(capture, dict)
        and capture.get("schema") == CAMPAIGN_CAPTURE_SCHEMA,
        "validation_schema_valid": isinstance(validation, dict)
        and validation.get("schema") == CAMPAIGN_VALIDATION_SCHEMA,
        "validation_ready": isinstance(validation, dict)
        and validation.get("campaign_status") == "internal_campaign_evidence_ready"
        and validation.get("internal_campaign_evidence_ready") is True
        and validation.get("blockers") == [],
        "exact_24_case_campaign": isinstance(request, dict)
        and isinstance(request.get("cases"), list)
        and len(request["cases"]) == 24
        and isinstance(capture, dict)
        and isinstance(capture.get("executions"), list)
        and len(capture["executions"]) == 24
        and isinstance(validation, dict)
        and validation.get("preregistered_case_count") == 24
        and validation.get("validated_execution_count") == 24,
        "request_digest_bound": isinstance(validation, dict)
        and validation.get("request_sha256") == request_digest,
        "capture_digest_bound": isinstance(validation, dict)
        and validation.get("capture_sha256") == capture_digest,
        "evidence_bundle_bound": isinstance(validation, dict)
        and validation.get("evidence_bundle_binding_sha256") == expected_bundle_binding
        and isinstance(evidence_bindings, dict)
        and len(evidence_bindings) > 0
        and all(is_digest(value) for value in evidence_bindings.values()),
        "strong_profile_preregistered": strong_request,
        "strong_profile_executed": strong_capture,
        "threshold_authorization_verified": authorization_valid,
        "deterministic_validator_revalidation": deterministic_revalidation,
        "nonclosure_boundary_preserved": isinstance(validation, dict)
        and validation.get("theorem_status")
        == "unclosed_pending_proof_and_independent_review"
        and validation.get("claims_theorem_closure") is False
        and validation.get("claims_fips_validation") is False,
    }
    blockers = [name for name, passed in checks.items() if not passed]
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "blockers": blockers,
        "inputs": {
            "request": file_record(request_path, root),
            "capture": file_record(capture_path, root),
            "validation": file_record(validation_path, root),
        },
        "request_sha256": request_digest,
        "capture_sha256": capture_digest,
        "evidence_bundle_binding_sha256": (
            validation.get("evidence_bundle_binding_sha256")
            if isinstance(validation, dict)
            else None
        ),
        "authorization_verification": authorization_verification,
    }


def build_report(
    root,
    *,
    assessment_path=None,
    readiness_path=None,
    theorem_review_path=None,
    campaign_request_path=None,
    campaign_capture_path=None,
    campaign_validation_path=None,
    evidence_dir=None,
    source_paths=None,
    artifact_paths=None,
    provenance_record=None,
    toolchain_record=None,
    authorization_verifier=None,
    generated_at=None,
):
    root = Path(root)
    assessment_path = Path(assessment_path or default_assessment(root))
    readiness_path = Path(readiness_path or default_readiness(root))
    theorem_review_path = Path(theorem_review_path or default_theorem_review(root))
    campaign_request_path = Path(
        campaign_request_path or default_campaign_request(root)
    )
    campaign_capture_path = Path(
        campaign_capture_path or default_campaign_capture(root)
    )
    campaign_validation_path = Path(
        campaign_validation_path or default_campaign_validation(root)
    )
    evidence_dir = Path(evidence_dir or default_evidence_dir(root))
    source_paths = list(source_paths or default_source_paths(root))
    artifact_paths = list(artifact_paths or default_artifact_paths(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    assessment, assessment_error = load_json_if_present(assessment_path)
    readiness, readiness_error = load_json_if_present(readiness_path)
    theorem_review, theorem_review_error = load_json_if_present(theorem_review_path)
    source_inventory = build_inventory(source_paths, root)
    artifact_inventory = build_inventory(artifact_paths, root)
    provenance = provenance_record or collect_provenance(root)
    toolchain = toolchain_record or collect_toolchain(root)
    campaign = validate_campaign_binding(
        campaign_request_path,
        campaign_capture_path,
        campaign_validation_path,
        root,
        authorization_verifier=authorization_verifier,
    )

    criteria = [
        build_criterion_record(
            root=root,
            criterion_id=criterion_id,
            statement=statement,
            assessment=assessment,
            evidence_path=evidence_dir / f"{criterion_id}.json",
            source_tree_sha256=source_inventory["tree_sha256"],
            provenance=provenance,
        )
        for criterion_id, statement in CRITERIA
    ]

    global_blockers = []
    if assessment_error or not isinstance(assessment, dict):
        add_blocker(global_blockers, "hypothesis assessment is missing or invalid")
    if readiness_error or not isinstance(readiness, dict):
        add_blocker(global_blockers, "theorem-closure readiness manifest is missing or invalid")
    if theorem_review_error or not isinstance(theorem_review, dict):
        add_blocker(global_blockers, "theorem-closure review manifest is missing or invalid")
    if source_inventory["file_count"] == 0:
        add_blocker(global_blockers, "source inventory is empty")
    if not all(Path(path).is_file() for path in artifact_paths):
        add_blocker(global_blockers, "artifact inventory is incomplete")
    if not provenance.get("repository_available"):
        add_blocker(global_blockers, "Git provenance is unavailable")
    if provenance.get("worktree_clean") is not True:
        add_blocker(global_blockers, "Git worktree is not clean")
    if toolchain.get("all_identified") is not True:
        add_blocker(global_blockers, "toolchain identity is incomplete")

    readiness_ready = (
        isinstance(readiness, dict)
        and readiness.get("theorem_closure_assessment_ready") is True
    )
    review_ready = (
        isinstance(theorem_review, dict)
        and theorem_review.get("review_status") == "theorem_closure_review_ready"
    )
    assessment_complete = (
        isinstance(assessment, dict)
        and assessment.get("overall_verdict") == "completely_proven"
    )
    source_boundary = source_claim_boundary_preserved(
        assessment, readiness, theorem_review
    )
    if not source_boundary:
        add_blocker(global_blockers, "a source manifest crosses the false-claim boundary")
    if not campaign["ready"]:
        add_blocker(
            global_blockers,
            "real 24-case strong-profile aggregation campaign is missing or invalid",
        )

    checks = {
        "five_criteria_present": [item["criterion_id"] for item in criteria]
        == [item[0] for item in CRITERIA],
        "all_criteria_internally_closed": all(
            item["internal_closure_ready"] for item in criteria
        ),
        "source_claim_boundary_preserved": source_boundary,
        "source_inventory_present": source_inventory["file_count"] > 0,
        "artifact_inventory_present": artifact_inventory["file_count"] > 0,
        "toolchain_identified": toolchain.get("all_identified") is True,
        "clean_git_provenance": provenance.get("worktree_clean") is True,
        "campaign_binding_ready": campaign["ready"],
    }
    ready = all(checks.values()) and global_blockers == []

    digest_document = {
        "schema": BUNDLE_SCHEMA,
        "name": NAME,
        "claim_boundary": CLAIM_BOUNDARY,
        "checks": checks,
        "criteria": criteria,
        "source_inventory": source_inventory,
        "artifact_inventory": artifact_inventory,
        "toolchain": toolchain,
        "provenance": provenance,
        "campaign": campaign,
        "global_blockers": global_blockers,
        "legacy_context": {
            "hypothesis_completely_proven": assessment_complete,
            "theorem_closure_readiness_ready": readiness_ready,
            "theorem_closure_review_ready": review_ready,
            "promotion_authority": False,
        },
    }
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "bundle_status": READY_STATUS if ready else BLOCKED_STATUS,
        "internal_closure_candidate": ready,
        "claim_boundary": CLAIM_BOUNDARY,
        "protocol_profile": PROTOCOL_PROFILE,
        "claim_flags": false_claim_flags(),
        "internal_review": {
            "required": True,
            "completed": ready,
            "status": "complete" if ready else "blocked_incomplete",
        },
        "independent_review": {
            "required": True,
            "completed": False,
            "status": "pending_independent_cryptographic_review",
        },
        "criteria": criteria,
        "checks": checks,
        "global_blockers": global_blockers,
        "legacy_context": {
            "hypothesis_completely_proven": assessment_complete,
            "theorem_closure_readiness_ready": readiness_ready,
            "theorem_closure_review_ready": review_ready,
            "promotion_authority": False,
        },
        "inputs": {
            "hypothesis_assessment": file_record(assessment_path, root),
            "theorem_closure_readiness": file_record(readiness_path, root),
            "theorem_closure_review": file_record(theorem_review_path, root),
            "campaign_request": campaign["inputs"]["request"],
            "campaign_capture": campaign["inputs"]["capture"],
            "campaign_validation": campaign["inputs"]["validation"],
        },
        "source_inventory": source_inventory,
        "artifact_inventory": artifact_inventory,
        "toolchain": toolchain,
        "provenance": provenance,
        "campaign": campaign,
        "reproducibility": {
            "builder_command": [
                "python3",
                "scripts/build_internal_theorem_closure_bundle.py",
                "--root",
                ".",
            ],
            "criterion_commands_embedded": True,
            "content_addressed": True,
        },
        "bundle_digest_sha256": sha256_text(
            canonical_json(bundle_digest_material(digest_document))
        ),
        "assessment_boundary": (
            "This bundle may record an internally closed candidate only after all five "
            "criteria and their content-addressed evidence pass. It never asserts public "
            "theorem closure, production security, FIPS validation, or completion of "
            "independent cryptographic review."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    lines = [
        "# Internal Theorem-Closure Bundle",
        "",
        f"- Bundle status: `{manifest['bundle_status']}`",
        f"- Internal closure candidate: `{str(manifest['internal_closure_candidate']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Bundle digest SHA-256: `{manifest['bundle_digest_sha256']}`",
        "",
        "## Criteria",
        "",
    ]
    for criterion in manifest["criteria"]:
        lines.append(
            f"- `{criterion['criterion_id']}`: "
            f"`{criterion['bundle_evidence_status']}` "
            f"({len(criterion['blockers'])} blocker(s))"
        )
    lines.extend(["", "## Global blockers", ""])
    if manifest["global_blockers"]:
        lines.extend(f"- {blocker}" for blocker in manifest["global_blockers"])
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "Independent cryptographic review remains outside this bundle's claim authority.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }


def render_checksums(contents):
    return "\n".join(
        f"{sha256_text(contents[name])}  {name}" for name in sorted(contents)
    ) + "\n"


def write_artifacts(report, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build a fail-closed internal theorem-closure evidence bundle"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--assessment", default=None)
    parser.add_argument("--readiness", default=None)
    parser.add_argument("--theorem-review", default=None)
    parser.add_argument("--campaign-request", default=None)
    parser.add_argument("--campaign-capture", default=None)
    parser.add_argument("--campaign-validation", default=None)
    parser.add_argument("--criterion-evidence-dir", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--require-internal-closure",
        action="store_true",
        help="exit 2 unless the bundle is an internal closure candidate",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        assessment_path=args.assessment,
        readiness_path=args.readiness,
        theorem_review_path=args.theorem_review,
        campaign_request_path=args.campaign_request,
        campaign_capture_path=args.campaign_capture,
        campaign_validation_path=args.campaign_validation,
        evidence_dir=args.criterion_evidence_dir,
    )
    out = Path(args.out) if args.out else default_out(root)
    write_artifacts(report, out)
    print(f"wrote internal theorem-closure bundle to {out}")
    if args.require_internal_closure and not report["manifest"]["internal_closure_candidate"]:
        print("internal theorem closure remains blocked", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
