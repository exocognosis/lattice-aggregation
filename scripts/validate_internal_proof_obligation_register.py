#!/usr/bin/env python3
"""Validate the internal theorem proof-obligation register and its claim gates."""

import argparse
import json
import sys
from pathlib import Path


DEFAULT_REGISTER = (
    "docs/cryptography/internal-proof-obligation-register.json"
)
SCHEMA = "lattice-aggregation.internal-proof-obligation-register.v1"
INTERNAL_MILESTONE = "internally_closed_pending_independent_review"

EXPECTED_CRITERIA = {
    "aggregate_mask_distribution": [
        "selected-backend mask-generation",
        "Renyi divergence",
        "distribution comparison",
    ],
    "aggregate_rejection_equivalence": [
        "real threshold aggregate recomputation",
        "standard-verifier compatibility",
        "rejection-distribution review",
    ],
    "abort_retry_bias": [
        "retry transcript domain separation",
        "selective-abort leakage",
        "accepted-signature distribution",
    ],
    "partial_contribution_soundness": [
        "production LocalAccept",
        "VSS/DKG binding and hiding",
        "context-binding and leakage review",
    ],
    "unauthorized_aggregate_reduction": [
        "threshold unforgeability reduction",
        "base ML-DSA theorem dependency",
        "simulator and hybrid-bound",
    ],
}

REQUIRED_OBLIGATIONS = {
    "FST-T1",
    "FST-T2",
    "FST-T3",
    "FST-T4",
    *(f"FST-L{number}" for number in range(1, 10)),
}

SUBSTANTIVE_STATUSES = {
    "open",
    "proof_sketch_only",
    "engineering_guard_only",
    "external_dependency_open",
    "discharged",
}
INTERNAL_REVIEW_STATUSES = {
    "not_ready",
    "ready_for_internal_review",
    "accepted",
    "rejected",
}
INDEPENDENT_VALIDATION_STATUSES = {
    "not_requested",
    "in_progress",
    "validated",
    "rejected",
}
ASSESSOR_STATUSES = {"blocked", "partially_met", "met", "failed"}

OPEN_KEYGEN_CAPABILITIES = {
    "fips204_exact_joint_expand_s_secret_sampling",
    "joint_unbiasable_rho_generation",
    "ceremony_context_construction_and_authentication",
    "distributed_secret_k_generation",
    "fips204_retained_t0_signing_state",
    "production_pq_private_share_transport",
    "process_isolated_private_share_custody",
    "persistent_receiver_replay_state",
    "malicious_secure_dkg_proof",
    "secret_share_vss_and_shortness_proof",
    "public_secret_relation_proof",
    "authenticated_complaint_and_recovery",
    "fips204_shared_signing_state",
    "fips204_exact_distributed_key_generation",
}


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load {path}: {error}") from error


def require_status(errors, subject, status, allowed):
    if status not in allowed:
        errors.append(
            f"{subject} has invalid status {status!r}; "
            f"expected one of {sorted(allowed)}"
        )


def validate_criterion(errors, criterion):
    criterion_id = criterion.get("id")
    if criterion_id not in EXPECTED_CRITERIA:
        errors.append(f"unexpected criterion id {criterion_id!r}")
        return

    required_promotion = criterion.get("promotion_requires", [])
    for anchor in EXPECTED_CRITERIA[criterion_id]:
        if anchor not in required_promotion:
            errors.append(
                f"criterion {criterion_id} is missing promotion anchor {anchor!r}"
            )

    assessor_status = criterion.get("assessor_status")
    proof = criterion.get("substantive_proof", {})
    review = criterion.get("internal_review", {})
    validation = criterion.get("independent_validation", {})
    proof_status = proof.get("status")
    review_status = review.get("status")
    validation_status = validation.get("status")

    require_status(
        errors,
        f"criterion {criterion_id} assessor",
        assessor_status,
        ASSESSOR_STATUSES,
    )
    require_status(
        errors,
        f"criterion {criterion_id} proof",
        proof_status,
        SUBSTANTIVE_STATUSES,
    )
    require_status(
        errors,
        f"criterion {criterion_id} internal review",
        review_status,
        INTERNAL_REVIEW_STATUSES,
    )
    require_status(
        errors,
        f"criterion {criterion_id} independent validation",
        validation_status,
        INDEPENDENT_VALIDATION_STATUSES,
    )

    if not proof.get("required_artifacts"):
        errors.append(f"criterion {criterion_id} has no required artifacts")
    if proof_status != "discharged" and not proof.get("blockers"):
        errors.append(f"criterion {criterion_id} is open without explicit blockers")
    if assessor_status == "met" and (
        proof_status != "discharged" or review_status != "accepted"
    ):
        errors.append(
            f"criterion {criterion_id} is marked met without a discharged proof "
            "and accepted internal review"
        )
    if assessor_status != "met" and proof_status == "discharged":
        errors.append(
            f"criterion {criterion_id} has a discharged proof but assessor status "
            f"is {assessor_status!r}"
        )
    if review_status == "accepted" and proof_status != "discharged":
        errors.append(
            f"criterion {criterion_id} has accepted internal review before proof discharge"
        )
    if validation_status == "validated" and (
        proof_status != "discharged" or review_status != "accepted"
    ):
        errors.append(
            f"criterion {criterion_id} has independent validation without internal closure"
        )


def validate_obligation(errors, obligation):
    obligation_id = obligation.get("id", "<missing>")
    proof_status = obligation.get("substantive_proof_status")
    review_status = obligation.get("internal_review_status")
    validation_status = obligation.get("independent_validation_status")

    require_status(
        errors,
        f"obligation {obligation_id} proof",
        proof_status,
        SUBSTANTIVE_STATUSES,
    )
    require_status(
        errors,
        f"obligation {obligation_id} internal review",
        review_status,
        INTERNAL_REVIEW_STATUSES,
    )
    require_status(
        errors,
        f"obligation {obligation_id} independent validation",
        validation_status,
        INDEPENDENT_VALIDATION_STATUSES,
    )

    if proof_status != "discharged" and not obligation.get("blocker"):
        errors.append(f"obligation {obligation_id} is open without an explicit blocker")
    if review_status == "accepted" and proof_status != "discharged":
        errors.append(
            f"obligation {obligation_id} has accepted review before proof discharge"
        )
    if validation_status == "validated" and (
        proof_status != "discharged" or review_status != "accepted"
    ):
        errors.append(
            f"obligation {obligation_id} has independent validation without internal closure"
        )


def validate_claims(errors, register, criteria, obligations_by_id):
    claims = register.get("claim_boundary", {})
    internal_claim = claims.get("claims_internal_theorem_closure") is True
    independent_claim = claims.get("claims_independent_validation") is True
    theorem_claim = claims.get("claims_theorem_closure") is True

    internal_criteria_closed = all(
        criterion.get("substantive_proof", {}).get("status") == "discharged"
        and criterion.get("internal_review", {}).get("status") == "accepted"
        for criterion in criteria
    )
    gate_ids = register.get("closure_gates", {}).get(
        "internal_candidate", {}
    ).get("required_obligations", [])
    internal_obligations_closed = bool(gate_ids) and all(
        obligations_by_id.get(obligation_id, {}).get("substantive_proof_status")
        == "discharged"
        and obligations_by_id.get(obligation_id, {}).get("internal_review_status")
        == "accepted"
        for obligation_id in gate_ids
    )
    if internal_claim and not (
        internal_criteria_closed and internal_obligations_closed
    ):
        errors.append(
            "internal theorem closure is claimed before all required proofs and "
            "internal reviews are complete"
        )

    independent_criteria_validated = all(
        criterion.get("independent_validation", {}).get("status") == "validated"
        for criterion in criteria
    )
    independent_theorems_validated = all(
        obligations_by_id.get(obligation_id, {}).get(
            "independent_validation_status"
        )
        == "validated"
        for obligation_id in ("FST-T1", "FST-T2")
    )
    if independent_claim and not (
        internal_claim
        and independent_criteria_validated
        and independent_theorems_validated
    ):
        errors.append(
            "independent validation is claimed without internal closure and "
            "validated criteria/theorems"
        )
    if theorem_claim and not independent_claim:
        errors.append(
            "final theorem closure is claimed without independent validation"
        )


def validate_keygen_capability_boundary(errors, register, criteria, root):
    boundary = register.get("implementation_capability_boundary")
    if not isinstance(boundary, dict):
        errors.append("implementation capability boundary must be an object")
        return

    public_key = boundary.get("fips204_exact_public_key_from_supplied_shares", {})
    if public_key.get("status") != "engineering_guard_only":
        errors.append(
            "exact public-key derivation must remain an engineering guard"
        )
    if public_key.get("implemented") is not True:
        errors.append(
            "exact public-key derivation from supplied shares is not recorded as implemented"
        )
    if public_key.get("reveals_combined_t_and_t0") is not True:
        errors.append(
            "public-key derivation must record that combined t and t0 are revealed"
        )
    if public_key.get("model_permits_public_t_and_t0") is not True:
        errors.append(
            "public-key derivation must record the selected model's t/t0 declassification"
        )
    if public_key.get("establishes_exact_joint_secret_distribution") is not False:
        errors.append(
            "public-key derivation must not claim an exact joint secret distribution"
        )
    public_key_evidence = public_key.get("evidence", {})
    for path_key in ("implementation_path", "test_path", "type_surface_test_path"):
        relative = public_key_evidence.get(path_key)
        if not relative:
            errors.append(f"public-key derivation has no {path_key}")
        elif not (root / relative).is_file():
            errors.append(f"public-key derivation evidence is missing: {relative}")
    if not public_key_evidence.get("verified_properties"):
        errors.append("public-key derivation has no verified properties")

    custody = boundary.get("encrypted_receiver_custody_seam", {})
    if custody.get("status") != "engineering_guard_only":
        errors.append("encrypted receiver-custody seam must remain an engineering guard")
    if custody.get("implemented") is not True:
        errors.append("encrypted receiver-custody seam is not recorded as implemented")
    if custody.get("establishes_process_isolation") is not False:
        errors.append("encrypted custody seam must not claim process isolation")
    if custody.get("establishes_pq_key_exchange_or_production_aead") is not False:
        errors.append("encrypted custody seam must not claim production transport")
    custody_evidence = custody.get("evidence", {})
    for path_key in (
        "implementation_path",
        "clear_share_consume_path",
        "test_path",
        "adversarial_test_path",
        "capability_test_path",
    ):
        relative = custody_evidence.get(path_key)
        if not relative:
            errors.append(f"encrypted custody seam has no {path_key}")
        elif not (root / relative).is_file():
            errors.append(f"encrypted custody evidence is missing: {relative}")

    for capability_id in sorted(OPEN_KEYGEN_CAPABILITIES):
        capability = boundary.get(capability_id)
        if not isinstance(capability, dict):
            errors.append(f"missing keygen capability {capability_id}")
            continue
        if capability.get("status") != "open":
            errors.append(f"keygen capability {capability_id} must remain open")
        if capability.get("implemented") is not False:
            errors.append(
                f"keygen capability {capability_id} must remain unimplemented"
            )
        if not capability.get("blocker"):
            errors.append(f"keygen capability {capability_id} has no blocker")

    promotion = boundary.get("criterion_promotion", {})
    if promotion.get("promoted_by_this_batch") is not False:
        errors.append("public-key derivation batch must not promote a criterion")
    recorded_statuses = promotion.get("criteria_status", {})
    live_statuses = {
        criterion.get("id"): criterion.get("assessor_status")
        for criterion in criteria
    }
    if recorded_statuses != live_statuses:
        errors.append(
            "keygen capability criterion statuses have drifted from the register"
        )


def validate_current_evidence(errors, register, root):
    evidence = register.get("current_evidence", {})
    loaded = {}
    for evidence_id, snapshot in evidence.items():
        relative = snapshot.get("path")
        if not relative:
            errors.append(f"current evidence {evidence_id} has no path")
            continue
        path = root / relative
        if not path.is_file():
            errors.append(f"current evidence {evidence_id} is missing: {relative}")
            continue
        try:
            loaded[evidence_id] = load_json(path)
        except ValueError as error:
            errors.append(str(error))

    hypothesis = loaded.get("hypothesis_assessment", {})
    hypothesis_snapshot = evidence.get("hypothesis_assessment", {})
    if hypothesis and hypothesis.get("overall_verdict") != hypothesis_snapshot.get(
        "overall_verdict"
    ):
        errors.append("hypothesis-assessment verdict has drifted from the register")
    if hypothesis:
        statuses = {
            criterion.get("status") for criterion in hypothesis.get("criteria", [])
        }
        expected_status = hypothesis_snapshot.get("all_five_criteria_status")
        if statuses != {expected_status}:
            errors.append(
                "hypothesis-assessment criterion statuses have drifted from the register"
            )

    readiness = loaded.get("theorem_closure_readiness", {})
    readiness_snapshot = evidence.get("theorem_closure_readiness", {})
    if readiness and readiness.get("readiness_status") != readiness_snapshot.get(
        "status"
    ):
        errors.append("theorem-closure readiness has drifted from the register")

    review = loaded.get("theorem_closure_review", {})
    review_snapshot = evidence.get("theorem_closure_review", {})
    if review and review.get("review_status") != review_snapshot.get("status"):
        errors.append("theorem-closure review status has drifted from the register")

    capture = loaded.get("backend_emission_capture", {})
    capture_snapshot = evidence.get("backend_emission_capture", {})
    if capture:
        captured_values = {
            "validator_count": capture.get("validator_count"),
            "threshold": capture.get("threshold"),
            "signature_bytes": capture.get("aggregate_signature_len"),
            "dirty": capture.get("metadata", {}).get("dirty"),
            "real_distributed_threshold_core_verified": capture.get(
                "external_capture_review", {}
            )
            .get("checks", {})
            .get("real_distributed_threshold_core_verified"),
        }
        for key, value in captured_values.items():
            if value != capture_snapshot.get(key):
                errors.append(
                    f"backend-emission capture field {key} has drifted from the register"
                )


def validate(register, root):
    errors = []
    if register.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")
    if register.get("scope", {}).get("internal_milestone") != INTERNAL_MILESTONE:
        errors.append(f"internal milestone must be {INTERNAL_MILESTONE!r}")

    criteria = register.get("criteria")
    if not isinstance(criteria, list):
        errors.append("criteria must be an array")
        criteria = []
    criterion_ids = [criterion.get("id") for criterion in criteria]
    if set(criterion_ids) != set(EXPECTED_CRITERIA):
        errors.append(
            "criteria must contain exactly the five assessor criterion ids"
        )
    if len(criterion_ids) != len(set(criterion_ids)):
        errors.append("criterion ids must be unique")
    for criterion in criteria:
        validate_criterion(errors, criterion)

    obligations = register.get("obligations")
    if not isinstance(obligations, list):
        errors.append("obligations must be an array")
        obligations = []
    obligations_by_id = {
        obligation.get("id"): obligation for obligation in obligations
    }
    if len(obligations_by_id) != len(obligations):
        errors.append("obligation ids must be unique")
    missing_obligations = REQUIRED_OBLIGATIONS - set(obligations_by_id)
    if missing_obligations:
        errors.append(
            "missing required obligations: " + ", ".join(sorted(missing_obligations))
        )
    for obligation in obligations:
        validate_obligation(errors, obligation)

    required_source_documents = register.get("scope", {}).get(
        "source_documents", []
    )
    for relative in required_source_documents:
        if not (root / relative).is_file():
            errors.append(f"missing source document {relative}")

    validate_current_evidence(errors, register, root)
    validate_keygen_capability_boundary(errors, register, criteria, root)
    validate_claims(errors, register, criteria, obligations_by_id)
    return errors


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--register",
        default=DEFAULT_REGISTER,
        help="register path relative to --root",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable validation result",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    root = Path(args.root).resolve()
    register_path = root / args.register
    try:
        register = load_json(register_path)
        errors = validate(register, root)
    except ValueError as error:
        errors = [str(error)]
        register = {}

    result = {
        "schema": "lattice-aggregation.internal-proof-obligation-validation.v1",
        "register": str(register_path),
        "valid": not errors,
        "errors": errors,
        "claims": register.get("claim_boundary", {}),
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    else:
        print(f"valid proof-obligation register: {register_path}")
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
