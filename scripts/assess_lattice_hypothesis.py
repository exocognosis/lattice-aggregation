#!/usr/bin/env python3
"""Assess lattice aggregation hypothesis evidence for the current checkout."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


REQUIRED_DOCUMENTS = [
    "README.md",
    "docs/cryptography/proof-obligations.md",
    "docs/cryptography/noise-rejection-proof-plan.md",
    "docs/cryptography/formal-security-theorem.md",
    "docs/cryptography/ideal-functionality.md",
    "docs/cryptography/proof-implementation-crosswalk.md",
    "docs/cryptography/protocol-code-crosswalk.md",
    "docs/benchmarks/release-readiness-checklist.md",
]

SELECTED_BACKEND_DOCUMENTS = [
    "docs/cryptography/proof-implementation-crosswalk.md",
    "docs/cryptography/protocol-code-crosswalk.md",
]

SELECTED_BACKEND_PROFILE = {
    "direction": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
    "assumption": "TEE/HSM",
    "output": "standard-verifier-compatible output",
    "migration_candidates": ["P2/MPC", "TALUS"],
    "claim_boundary": (
        "selection artifact only; not proof closure or production approval"
    ),
}

SELECTED_BACKEND_REQUIRED_TOKENS = [
    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
    "TEE/HSM coordinator assumption",
    "standard-verifier-compatible output",
    "P2/MPC",
    "TALUS",
    "selection artifact",
    "not proof closure",
    "not production approval",
]

THESIS_OPERATING_PARAMETERS_DOC = (
    "docs/cryptography/thesis-operating-parameters.md"
)
THESIS_OPERATING_PARAMETERS_MANIFEST = (
    "docs/cryptography/thesis-operating-parameters.json"
)
THESIS_OPERATING_PARAMETERS_SCHEMA = (
    "lattice-aggregation.thesis-operating-parameters.v1"
)
THESIS_OPERATING_PARAMETERS_ID = "native-threshold-mldsa65-aggregation-p1"
THESIS_FALSE_CLAIM_KEYS = [
    "claims_production_threshold_mldsa_security",
    "claims_selected_backend_proof_closure",
    "claims_standard_verifier_compatibility_complete",
    "claims_rejection_distribution_preservation",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
]
THESIS_CRITERION_IDS = [
    "aggregate_mask_distribution",
    "aggregate_rejection_equivalence",
    "abort_retry_bias",
    "partial_contribution_soundness",
    "unauthorized_aggregate_reduction",
]
THESIS_OPERATING_PARAMETERS_EXPECTED = {
    "security_parameter": "lambda",
    "validator_count": "n",
    "threshold": "t",
    "validator_set": "V",
    "threshold_range": "1 <= t <= n",
    "static_corruption_bound": "at most t - 1 validators",
    "retry_domain": "session_id + attempt_id + retry_counter",
    "rejection_sampling_domain": (
        "centralized ML-DSA-65 acceptance distribution"
    ),
    "batch4_dependency": (
        "selected-backend proof-closure artifact package gate"
    ),
    "boundary": "conformance/proof-review evidence only",
}
THESIS_CRITERION_ANCHORS = {
    "aggregate_mask_distribution": {
        "promotion_requires": [
            "selected-backend mask-generation",
            "Renyi divergence",
            "distribution comparison",
        ],
        "failure_criteria": ["distinguishable", "selected profile"],
    },
    "aggregate_rejection_equivalence": {
        "promotion_requires": [
            "real threshold aggregate recomputation",
            "standard-verifier compatibility",
            "rejection-distribution review",
        ],
        "failure_criteria": [
            "fail standard ML-DSA-65 verification",
            "centralized ML-DSA-65 predicates",
        ],
    },
    "abort_retry_bias": {
        "promotion_requires": [
            "retry transcript domain separation",
            "selective-abort leakage",
            "accepted-signature distribution",
        ],
        "failure_criteria": ["retry timing", "attempt identifiers"],
    },
    "partial_contribution_soundness": {
        "promotion_requires": [
            "production LocalAccept",
            "VSS/DKG binding and hiding",
            "context-binding and leakage review",
        ],
        "failure_criteria": [
            "cross-context partial contributions",
            "accepted partial evidence leaks",
        ],
    },
    "unauthorized_aggregate_reduction": {
        "promotion_requires": [
            "threshold unforgeability reduction",
            "base ML-DSA theorem dependency",
            "simulator and hybrid-bound",
        ],
        "failure_criteria": [
            "named assumption",
            "validator-set binding",
        ],
    },
}

CRITERION2_PROOF_SUBSTANCE_DOC = (
    "docs/cryptography/criterion-2-proof-substance.md"
)
CRITERION2_PROOF_SUBSTANCE_MANIFEST = (
    "docs/cryptography/criterion-2-proof-substance.json"
)
CRITERION2_PROOF_SUBSTANCE_SCHEMA = (
    "lattice-aggregation.criterion-2-proof-substance.v1"
)
CRITERION2_ID = "aggregate_rejection_equivalence"
CRITERION2_FALSE_CLAIM_KEYS = [
    "claims_criterion_met",
    "claims_selected_backend_proof_closure",
    "claims_standard_verifier_compatibility_complete",
    "claims_rejection_distribution_preservation",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
    "claims_production_threshold_mldsa_security",
]
CRITERION2_REQUIRED_ARTIFACT_SLOTS = [
    "threshold_output_certificate_digest",
    "real_recomputation_evidence_digest",
    "standard_verifier_compatibility_artifact_digest",
    "rejection_distribution_review_digest",
    "theorem_linkage_artifact_digest",
    "full_kat_validation_artifact_digest",
    "norm_bound_artifact_digest",
    "hint_bound_artifact_digest",
    "challenge_bound_artifact_digest",
    "transcript_binding_evidence_digest",
    "external_review_digest",
]
CRITERION2_EVIDENCE_PRESENT_SLOTS = {
    "threshold_output_certificate_digest": (
        "p1_criterion2_threshold_output_certificate_artifact_gate"
    ),
    "real_recomputation_evidence_digest": (
        "p1_criterion2_real_recomputation_evidence_artifact_gate"
    ),
    "standard_verifier_compatibility_artifact_digest": (
        "p1_standard_verifier_compatibility_artifact_gate"
    ),
    "rejection_distribution_review_digest": (
        "p1_criterion2_rejection_distribution_review_artifact_gate"
    ),
    "theorem_linkage_artifact_digest": (
        "p1_criterion2_theorem_linkage_artifact_gate"
    ),
    "full_kat_validation_artifact_digest": (
        "p1_criterion2_full_kat_validation_artifact_gate"
    ),
    "norm_bound_artifact_digest": "p1_criterion2_norm_bound_artifact_gate",
    "hint_bound_artifact_digest": "p1_criterion2_hint_bound_artifact_gate",
    "challenge_bound_artifact_digest": (
        "p1_criterion2_challenge_bound_artifact_gate"
    ),
    "transcript_binding_evidence_digest": (
        "p1_criterion2_transcript_binding_artifact_gate"
    ),
    "external_review_digest": "p1_criterion2_external_review_artifact_gate",
}
CRITERION2_EVIDENCE_PRESENT_PACKAGES = {
    "standard_verifier_compatibility_artifact_digest": (
        "p1_standard_verifier_compatibility_artifact_package"
    ),
    **{
        slot: "p1_criterion2_proof_slot_artifact_package"
        for slot in CRITERION2_EVIDENCE_PRESENT_SLOTS
        if slot != "standard_verifier_compatibility_artifact_digest"
    },
}
CRITERION2_DURABLE_CERTIFICATE_ACCESSORS = {
    "threshold_output_certificate_digest": (
        "threshold_output_certificate_artifact_digest"
    ),
    "real_recomputation_evidence_digest": (
        "real_recomputation_evidence_artifact_digest"
    ),
}
CRITERION2_DURABLE_CERTIFICATE_SURFACE = (
    "p1_selected_backend_proof_closure_artifact_certificate"
)
CRITERION2_DURABLE_CERTIFICATE_EVIDENCE_SURFACE = (
    "P1SelectedBackendProofClosureArtifactCertificate"
)
CRITERION2_ARTIFACT_FIXTURE_REFS = [
    {
        "slot_id": "real_recomputation_evidence_digest",
        "fixture_path": "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-real-recomputation-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence only",
    },
    {
        "slot_id": "standard_verifier_compatibility_artifact_digest",
        "fixture_path": "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence only",
    }
]
CRITERION2_ARTIFACT_SLOT_STATUSES = {
    slot: (
        "evidence_present_unclosed"
        if slot in CRITERION2_EVIDENCE_PRESENT_SLOTS
        else "required_unclosed"
    )
    for slot in CRITERION2_REQUIRED_ARTIFACT_SLOTS
}
CRITERION2_THEOREM_LINKS = [
    "Correctness Lemma 7",
    "Correctness Lemma 8",
    "Noise Lemma D",
    "Noise Lemma F",
    "Noise Lemma H",
    "FST-L5",
    "FST-L7",
]

TESTING_STATEMENT = (
    "If a threshold ML-DSA-65 lattice aggregation protocol emits an accepted "
    "aggregate output, then the output should behave like a centralized "
    "ML-DSA-65 signature under the same public key and message, while "
    "preserving threshold soundness, rejection-sampling distribution, "
    "contribution validity, leakage boundaries, and unforgeability reduction "
    "claims."
)

RUST_COMMENT_OR_STRING_RE = re.compile(
    r"""
    //[^\n]*
    | /\*.*?\*/
    | b?r\#{0,16}".*?"\#{0,16}
    | b?"(?:\\.|[^"\\])*"
    """,
    re.DOTALL | re.VERBOSE,
)

RUST_TEST_FN_RE = re.compile(
    r"(?m)^\s*#\s*\[\s*test\s*\]\s*"
    r"(?:#\s*\[[^\]]+\]\s*)*"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
)


def rust_code_without_comments_or_strings(text):
    """Blank Rust comments and string literals before lightweight regex scans."""

    def blank_match(match):
        return re.sub(r"[^\n]", " ", match.group(0))

    return RUST_COMMENT_OR_STRING_RE.sub(blank_match, text)


def has_public_struct(source, name):
    """Return whether Rust source declares the named public struct."""
    code = rust_code_without_comments_or_strings(source)
    pattern = rf"(?m)^\s*pub\s+struct\s+{re.escape(name)}\b"
    return re.search(pattern, code) is not None


def has_public_enum(source, name):
    """Return whether Rust source declares the named public enum."""
    code = rust_code_without_comments_or_strings(source)
    pattern = rf"(?m)^\s*pub\s+enum\s+{re.escape(name)}\b"
    return re.search(pattern, code) is not None


def has_public_function(source, name):
    """Return whether Rust source declares the named public function."""
    code = rust_code_without_comments_or_strings(source)
    pattern = rf"(?m)^\s*pub\s+(?:const\s+)?fn\s+{re.escape(name)}\b"
    return re.search(pattern, code) is not None


def has_acceptance_test_function(source, *required_terms):
    """Return whether a #[test] function name mentions the required terms."""
    code = rust_code_without_comments_or_strings(source)
    for function_name in RUST_TEST_FN_RE.findall(code):
        lowered = function_name.lower()
        if all(term.lower() in lowered for term in required_terms):
            return True
    return False


def has_rust_tokens(source, *tokens):
    """Return whether Rust source contains all code tokens outside comments/strings."""
    code = rust_code_without_comments_or_strings(source)
    return all(token in code for token in tokens)


def normalize_whitespace(text):
    """Normalize text for phrase scans across Markdown line wrapping."""
    return re.sub(r"\s+", " ", text).strip().lower()


def parse_json_document(text):
    """Parse a JSON document without failing the assessment scan."""
    if not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def entries_contain_terms(entries, terms):
    """Return whether string entries contain all required reviewer-anchor terms."""
    joined = "\n".join(str(entry) for entry in entries).lower()
    return all(term.lower() in joined for term in terms)


def thesis_operating_parameters_status(markdown, manifest_text):
    """Return thesis/parameter formalization status without criterion promotion."""
    normalized = normalize_whitespace(markdown)
    manifest = parse_json_document(manifest_text)
    claim_boundary = manifest.get("claim_boundary", {})
    selected_profile = manifest.get("selected_profile", {})
    operating_parameters = manifest.get("operating_parameters", {})
    fallback = manifest.get("fallback", {})
    criteria = manifest.get("criterion_promotion", [])
    criteria_by_id = {
        criterion.get("id"): criterion
        for criterion in criteria
        if isinstance(criterion, dict)
    }

    expected_markdown_tokens = [
        "# thesis and operating parameters",
        "native-threshold-mldsa65-aggregation-p1",
        "research scaffold only",
        "ml-dsa-65 coordinator-assisted shamir nonce dkg p1",
        "one standard-sized ml-dsa-65 signature if proven",
        "partially_proven",
        "partially_met",
        "not selected-backend proof closure",
        "not production threshold ml-dsa security",
        "not cavp/acvts validation",
        "not fips validation",
        "falcon/labrador-style proof aggregation",
        "evaluate only",
    ]
    missing_evidence = [
        token
        for token in expected_markdown_tokens
        if token not in normalized
    ]
    false_claims_pinned = all(
        claim_boundary.get(key) is False for key in THESIS_FALSE_CLAIM_KEYS
    )
    operating_parameters_pinned = all(
        operating_parameters.get(key) == expected
        for key, expected in THESIS_OPERATING_PARAMETERS_EXPECTED.items()
    )
    criteria_pinned = all(
        (
            criteria_by_id.get(criterion_id, {}).get("current_status")
            == "partially_met"
            and entries_contain_terms(
                criteria_by_id.get(criterion_id, {}).get(
                    "promotion_requires", []
                ),
                THESIS_CRITERION_ANCHORS[criterion_id][
                    "promotion_requires"
                ],
            )
            and entries_contain_terms(
                criteria_by_id.get(criterion_id, {}).get(
                    "failure_criteria", []
                ),
                THESIS_CRITERION_ANCHORS[criterion_id][
                    "failure_criteria"
                ],
            )
        )
        for criterion_id in THESIS_CRITERION_IDS
    )
    manifest_ok = (
        manifest.get("schema") == THESIS_OPERATING_PARAMETERS_SCHEMA
        and manifest.get("thesis_id") == THESIS_OPERATING_PARAMETERS_ID
        and manifest.get("status") == "research_scaffold_partially_proven"
        and claim_boundary.get("scope") == "research scaffold only"
        and selected_profile.get("name")
        == "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
        and selected_profile.get("feature_gate") == "production-mldsa65-coordinator"
        and selected_profile.get("coordinator_assumption") == "TEE/HSM"
        and selected_profile.get("aggregate_output_shape")
        == "one standard-sized ML-DSA-65 signature if proven"
        and false_claims_pinned
        and operating_parameters_pinned
        and criteria_pinned
        and fallback.get("architecture") == "Falcon/LaBRADOR-style proof aggregation"
        and fallback.get("status") == "evaluate_only"
        and fallback.get("claims_selected_backend") is False
    )
    formalized = bool(markdown.strip()) and manifest_ok and not missing_evidence
    if not manifest:
        missing_evidence.append(THESIS_OPERATING_PARAMETERS_MANIFEST)
    if not markdown.strip():
        missing_evidence.append(THESIS_OPERATING_PARAMETERS_DOC)
    if manifest and not operating_parameters_pinned:
        missing_evidence.append("operating_parameters")
    if manifest and not criteria_pinned:
        missing_evidence.append("criterion promotion/failure anchors")

    return {
        "status": (
            "formalized_research_boundary"
            if formalized
            else "missing_or_incomplete"
        ),
        "document_path": THESIS_OPERATING_PARAMETERS_DOC,
        "manifest_path": THESIS_OPERATING_PARAMETERS_MANIFEST,
        "thesis_id": manifest.get("thesis_id", ""),
        "scope": claim_boundary.get("scope", ""),
        "selected_profile": selected_profile.get("name", ""),
        "output_target": selected_profile.get("aggregate_output_shape", ""),
        "operating_parameters": operating_parameters,
        "fallback": {
            "architecture": fallback.get("architecture", ""),
            "status": fallback.get("status", ""),
        },
        "missing_evidence": sorted(set(missing_evidence)),
    }


def criterion2_proof_substance_status(markdown, manifest_text):
    """Return Criterion-2 proof-payload status without criterion promotion."""
    normalized = normalize_whitespace(markdown)
    manifest = parse_json_document(manifest_text)
    claim_boundary = manifest.get("claim_boundary", {})
    selected_profile = manifest.get("selected_profile", {})
    proof_payload = manifest.get("proof_payload", {})
    assessment = manifest.get("assessment", {})
    artifact_slots = proof_payload.get("required_artifact_slots", [])
    slot_by_id = {
        slot.get("id"): slot for slot in artifact_slots if isinstance(slot, dict)
    }
    durable_certificate_evidence = proof_payload.get(
        "durable_certificate_evidence", []
    )
    artifact_fixture_refs = proof_payload.get("artifact_fixture_refs", [])
    durable_certificate_evidence_by_slot = {
        entry.get("slot_id"): entry
        for entry in durable_certificate_evidence
        if isinstance(entry, dict)
    }
    theorem_links = proof_payload.get("theorem_links", [])

    expected_markdown_tokens = [
        "# criterion 2 proof substance",
        "aggregate_rejection_equivalence",
        "formalized_open_proof_payload",
        "criterion2_proof_payload_formalized",
        "mldsa65.verify(pk, m, sigma) = accept",
        "aggregateaccept(...) = true",
        "standard_verifier_compatibility_artifact_digest",
        "evidence_present_unclosed",
        "evidence_present_unclosed only",
        "typed criterion 2 proof-slot artifact packages",
        "p1_criterion2_proof_slot_artifact_package",
        "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
        "checked recomputation fixture",
        "checked standard-verifier compatibility fixture",
        "p1_standard_verifier_compatibility_artifact_gate",
        "p1_criterion2_threshold_output_certificate_artifact_gate",
        "p1_criterion2_real_recomputation_evidence_artifact_gate",
        "rejection_distribution_review_digest",
        "p1_criterion2_rejection_distribution_review_artifact_gate",
        "theorem_linkage_artifact_digest",
        "p1_criterion2_theorem_linkage_artifact_gate",
        "p1_criterion2_full_kat_validation_artifact_gate",
        "p1_criterion2_norm_bound_artifact_gate",
        "p1_criterion2_hint_bound_artifact_gate",
        "p1_criterion2_challenge_bound_artifact_gate",
        "p1_criterion2_transcript_binding_artifact_gate",
        "p1_criterion2_external_review_artifact_gate",
        "conformance/proof-review evidence only",
        "correctness lemma 7",
        "correctness lemma 8",
        "noise lemma d",
        "noise lemma f",
        "noise lemma h",
        "fst-l5",
        "fst-l7",
        "partially_met",
        "partially_proven",
        "not selected-backend proof closure",
        "not production threshold ml-dsa security",
        "not cavp/acvts validation",
        "not fips validation",
        "not rejection-distribution preservation",
        "not a completed standard-verifier compatibility proof",
    ]
    missing_evidence = [
        token
        for token in expected_markdown_tokens
        if token not in normalized
    ]
    false_claims_pinned = all(
        claim_boundary.get(key) is False for key in CRITERION2_FALSE_CLAIM_KEYS
    )
    artifact_slot_statuses = {
        slot_id: slot_by_id.get(slot_id, {}).get("current_status", "")
        for slot_id in CRITERION2_REQUIRED_ARTIFACT_SLOTS
    }
    artifact_slot_sources = {
        slot_id: slot_by_id.get(slot_id, {}).get("evidence_source", "")
        for slot_id in CRITERION2_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("evidence_source")
    }
    artifact_slot_packages = {
        slot_id: slot_by_id.get(slot_id, {}).get("artifact_package", "")
        for slot_id in CRITERION2_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("artifact_package")
    }
    artifact_slot_certificate_accessors = {
        slot_id: slot_by_id.get(slot_id, {}).get("certificate_accessor", "")
        for slot_id in CRITERION2_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("certificate_accessor")
    }
    evidence_present_slots_pinned = all(
        slot_by_id.get(slot_id, {}).get("evidence_source") == evidence_source
        and slot_by_id.get(slot_id, {}).get("artifact_package")
        == CRITERION2_EVIDENCE_PRESENT_PACKAGES[slot_id]
        and slot_by_id.get(slot_id, {}).get("claim_boundary")
        == "conformance/proof-review evidence only"
        for slot_id, evidence_source in CRITERION2_EVIDENCE_PRESENT_SLOTS.items()
    )
    artifact_slots_pinned = (
        artifact_slot_statuses == CRITERION2_ARTIFACT_SLOT_STATUSES
        and artifact_slot_sources == CRITERION2_EVIDENCE_PRESENT_SLOTS
        and artifact_slot_packages == CRITERION2_EVIDENCE_PRESENT_PACKAGES
        and artifact_slot_certificate_accessors
        == CRITERION2_DURABLE_CERTIFICATE_ACCESSORS
        and durable_certificate_evidence_by_slot.keys()
        == CRITERION2_DURABLE_CERTIFICATE_ACCESSORS.keys()
        and all(
            slot_by_id.get(slot_id, {}).get("certificate_surface")
            == CRITERION2_DURABLE_CERTIFICATE_SURFACE
            for slot_id in CRITERION2_DURABLE_CERTIFICATE_ACCESSORS
        )
        and all(
            durable_certificate_evidence_by_slot.get(slot_id, {}).get(
                "certificate_surface"
            )
            == CRITERION2_DURABLE_CERTIFICATE_EVIDENCE_SURFACE
            and durable_certificate_evidence_by_slot.get(slot_id, {}).get(
                "certificate_accessor"
            )
            == accessor
            and durable_certificate_evidence_by_slot.get(slot_id, {}).get(
                "current_status"
            )
            == "evidence_present_unclosed"
            and durable_certificate_evidence_by_slot.get(slot_id, {}).get(
                "claim_boundary"
            )
            == "conformance/proof-review evidence only"
            for slot_id, accessor in CRITERION2_DURABLE_CERTIFICATE_ACCESSORS.items()
        )
        and evidence_present_slots_pinned
    )
    artifact_fixture_refs_pinned = artifact_fixture_refs == CRITERION2_ARTIFACT_FIXTURE_REFS
    theorem_links_pinned = entries_contain_terms(
        theorem_links,
        CRITERION2_THEOREM_LINKS,
    )
    promotion_anchors_pinned = entries_contain_terms(
        manifest.get("promotion_requires", []),
        [
            "threshold-output",
            "full KAT/validation",
            "rejection-distribution preservation",
            "standard-verifier compatibility",
            "theorem-linkage",
        ],
    )
    failure_anchors_pinned = entries_contain_terms(
        manifest.get("failure_conditions", []),
        [
            "fail standard ML-DSA-65 verification",
            "centralized ML-DSA-65 predicates",
        ],
    )
    manifest_ok = (
        manifest.get("schema") == CRITERION2_PROOF_SUBSTANCE_SCHEMA
        and manifest.get("criterion_id") == CRITERION2_ID
        and manifest.get("status") == "formalized_open_proof_payload"
        and claim_boundary.get("scope") == "criterion-2 proof payload only"
        and selected_profile.get("name")
        == "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
        and selected_profile.get("feature_gate") == "production-mldsa65-coordinator"
        and selected_profile.get("output_target")
        == "one standard-sized ML-DSA-65 signature if proven"
        and proof_payload.get("central_verifier_target")
        == "MLDSA65.Verify(pk, m, sigma) = accept"
        and false_claims_pinned
        and artifact_slots_pinned
        and artifact_fixture_refs_pinned
        and theorem_links_pinned
        and promotion_anchors_pinned
        and failure_anchors_pinned
        and assessment.get("criterion_status") == "partially_met"
        and assessment.get("overall_verdict") == "partially_proven"
        and assessment.get("does_not_change_overall_verdict") is True
        and assessment.get("report_status")
        == "criterion2_proof_payload_formalized"
    )
    formalized = bool(markdown.strip()) and manifest_ok and not missing_evidence
    if not manifest:
        missing_evidence.append(CRITERION2_PROOF_SUBSTANCE_MANIFEST)
    if not markdown.strip():
        missing_evidence.append(CRITERION2_PROOF_SUBSTANCE_DOC)
    if manifest and not false_claims_pinned:
        missing_evidence.append("claim_boundary false claims")
    if manifest and not artifact_slots_pinned:
        missing_evidence.append("required_artifact_slots")
    if manifest and not artifact_fixture_refs_pinned:
        missing_evidence.append("artifact_fixture_refs")
    if manifest and not theorem_links_pinned:
        missing_evidence.append("theorem_links")

    return {
        "status": (
            "criterion2_proof_payload_formalized"
            if formalized
            else "missing_or_incomplete"
        ),
        "document_path": CRITERION2_PROOF_SUBSTANCE_DOC,
        "manifest_path": CRITERION2_PROOF_SUBSTANCE_MANIFEST,
        "criterion_id": manifest.get("criterion_id", ""),
        "payload_status": manifest.get("status", ""),
        "scope": claim_boundary.get("scope", ""),
        "selected_profile": selected_profile.get("name", ""),
        "output_target": selected_profile.get("output_target", ""),
        "required_artifact_slots": CRITERION2_REQUIRED_ARTIFACT_SLOTS,
        "artifact_slot_statuses": artifact_slot_statuses,
        "artifact_slot_sources": artifact_slot_sources,
        "artifact_slot_certificate_accessors": artifact_slot_certificate_accessors,
        "artifact_fixture_refs": artifact_fixture_refs,
        "durable_certificate_evidence": durable_certificate_evidence,
        "theorem_links": theorem_links,
        "missing_evidence": sorted(set(missing_evidence)),
    }


def selected_backend_direction(texts):
    """Return selected-backend traceability observed in docs."""
    selected_text = "\n".join(
        texts.get(relative, "") for relative in SELECTED_BACKEND_DOCUMENTS
    )
    normalized = normalize_whitespace(selected_text)
    missing_tokens = [
        token
        for token in SELECTED_BACKEND_REQUIRED_TOKENS
        if token.lower() not in normalized
    ]
    profile = dict(SELECTED_BACKEND_PROFILE)
    profile["status"] = (
        "observed_selection_artifact" if not missing_tokens else "not_observed"
    )
    profile["evidence_documents"] = [
        relative
        for relative in SELECTED_BACKEND_DOCUMENTS
        if texts.get(relative, "").strip()
    ]
    profile["missing_evidence"] = missing_tokens
    return profile


def selected_backend_observed(scan):
    """Return whether the selected backend direction is fully observed."""
    return (
        scan.get("selected_backend_direction", {}).get("status")
        == "observed_selection_artifact"
    )


def selected_backend_observation(selected_backend):
    """Return the criterion evidence sentence for selected backend traceability."""
    candidates = ", ".join(selected_backend["migration_candidates"])
    return (
        "Selected backend direction is documented as "
        f"{selected_backend['direction']} under a "
        f"{selected_backend['assumption']} coordinator assumption with "
        f"{selected_backend['output']}; later migration candidates remain "
        f"{candidates}."
    )


def selected_backend_boundary_blocker():
    """Return the blocker that preserves claim boundaries for backend selection."""
    return (
        "Selected backend direction is a selection artifact only; proof "
        "artifacts, backend implementation evidence, and production approval "
        "remain open."
    )


def default_criteria():
    """Return the five canonical hypothesis success criteria."""
    return [
        {
            "id": "aggregate_mask_distribution",
            "statement": (
                "Aggregate masks match or closely approximate centralized "
                "ML-DSA masks."
            ),
            "required_evidence": [
                "selected threshold ML-DSA construction",
                "Renyi divergence bound for epsilon_mask",
                "mask distribution comparison evidence",
            ],
            "proof_anchors": ["Noise Lemma B", "Noise Lemma H"],
        },
        {
            "id": "aggregate_rejection_equivalence",
            "statement": (
                "Aggregate rejection checks match centralized ML-DSA rejection "
                "checks."
            ),
            "required_evidence": [
                "real aggregate recomputation",
                "standard verifier bridge tests",
                "ML-DSA-65 norm, hint, and challenge bound checks",
            ],
            "proof_anchors": [
                "Noise Lemma D",
                "Noise Lemma F",
                "Correctness Lemma 7",
                "Correctness Lemma 8",
            ],
        },
        {
            "id": "abort_retry_bias",
            "statement": (
                "Selective aborts and retries do not bias accepted signatures."
            ),
            "required_evidence": [
                "abort leakage model",
                "retry transcript domain separation",
                "accepted-signature distribution proof",
            ],
            "proof_anchors": ["Noise Lemma G", "Noise Lemma H", "FST-L7"],
        },
        {
            "id": "partial_contribution_soundness",
            "statement": (
                "Every accepted partial contribution is sound, context-bound, "
                "and hiding enough for the chosen leakage model."
            ),
            "required_evidence": [
                "local partial acceptance predicate",
                "partial-share verification evidence",
                "VSS/DKG hiding and binding proof",
            ],
            "proof_anchors": ["FST-L4", "Noise Lemma E", "VSS hiding"],
        },
        {
            "id": "unauthorized_aggregate_reduction",
            "statement": (
                "Every unauthorized accepting aggregate output reduces to a "
                "base ML-DSA forgery or a named threshold-side assumption "
                "violation."
            ),
            "required_evidence": [
                "threshold unforgeability reduction",
                "base ML-DSA theorem dependency",
                "named threshold-side assumptions",
            ],
            "proof_anchors": ["FST-L6", "FST-T1", "IF-R6"],
        },
    ]


def overall_verdict(criteria):
    """Roll criterion statuses into the requested four-way verdict."""
    statuses = [criterion["status"] for criterion in criteria]
    if statuses and all(status == "met" for status in statuses):
        return "completely_proven"
    if statuses and all(status == "failed" for status in statuses):
        return "completely_disproven"
    if any(status == "failed" for status in statuses):
        return "partially_disproven"
    if any(status in {"met", "partially_met", "blocked"} for status in statuses):
        return "partially_proven"
    return "partially_proven"


def scan_documents(root):
    """Scan source documents for current claim boundaries and proof blockers."""
    root = Path(root)
    texts = {}
    missing = []
    for relative in REQUIRED_DOCUMENTS:
        path = root / relative
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            texts[relative] = ""
            missing.append(relative)

    combined = "\n".join(texts.values()).lower()
    readme = texts["README.md"].lower()

    def read_optional(relative):
        try:
            return (root / relative).read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    acceptance_source_path = root / "src" / "production" / "acceptance.rs"
    production_acceptance_test_path = root / "tests" / "production_acceptance.rs"
    acceptance_source = read_optional("src/production/acceptance.rs")
    production_acceptance_test = read_optional("tests/production_acceptance.rs")
    provider_source = read_optional("src/production/provider.rs")
    provider_test = read_optional("tests/production_provider.rs")
    acvp_mldsa65_sigver_fixture = read_optional(
        "tests/fixtures/acvp_mldsa65_sigver_fips204_sample.json"
    )
    mask_distribution_source = read_optional("src/production/mask_distribution.rs")
    mask_distribution_test = read_optional("tests/production_mask_distribution.rs")
    rejection_equivalence_source = read_optional("src/production/rejection_equivalence.rs")
    rejection_equivalence_test = read_optional("tests/production_rejection_equivalence.rs")
    abort_bias_source = read_optional("src/production/abort_bias.rs")
    abort_bias_test = read_optional("tests/production_abort_bias.rs")
    partial_soundness_source = read_optional("src/production/partial_soundness.rs")
    partial_soundness_test = read_optional("tests/production_partial_soundness.rs")
    reduction_manifest = read_optional(
        "docs/cryptography/unauthorized-aggregate-reduction.md"
    )
    reduction_manifest_test = read_optional(
        "tests/unauthorized_aggregate_reduction_manifest.rs"
    )
    thesis_operating_parameters = thesis_operating_parameters_status(
        read_optional(THESIS_OPERATING_PARAMETERS_DOC),
        read_optional(THESIS_OPERATING_PARAMETERS_MANIFEST),
    )
    criterion2_proof_substance = criterion2_proof_substance_status(
        read_optional(CRITERION2_PROOF_SUBSTANCE_DOC),
        read_optional(CRITERION2_PROOF_SUBSTANCE_MANIFEST),
    )

    acceptance_source_scaffold = all(
        has_public_struct(acceptance_source, token)
        for token in [
            "LocalAccept",
            "AggregateAccept",
            "AcceptedPartialContribution",
            "AggregateAcceptEvidence",
        ]
    )
    local_acceptance_test_scaffold = has_acceptance_test_function(
        production_acceptance_test,
        "local",
        "accept",
    )
    aggregate_acceptance_test_scaffold = has_acceptance_test_function(
        production_acceptance_test,
        "aggregate",
        "accept",
    )
    production_acceptance_tests_scaffold = (
        production_acceptance_test_path.is_file()
        and local_acceptance_test_scaffold
        and aggregate_acceptance_test_scaffold
    )
    local_acceptance_conformance_scaffold = (
        acceptance_source_scaffold
        and production_acceptance_tests_scaffold
        and local_acceptance_test_scaffold
    )
    aggregate_acceptance_conformance_scaffold = (
        acceptance_source_scaffold
        and production_acceptance_tests_scaffold
        and aggregate_acceptance_test_scaffold
    )
    mask_distribution_evidence_gate = (
        has_public_struct(mask_distribution_source, "MaskDistributionEvidence")
        and has_public_struct(
            mask_distribution_source, "AcceptedMaskDistributionCertificate"
        )
        and has_public_function(mask_distribution_source, "assess_mask_distribution")
        and has_acceptance_test_function(
            mask_distribution_test,
            "mask",
            "distribution",
        )
    )
    mask_distribution_closure_framework = (
        has_public_struct(mask_distribution_source, "MaskDistributionClosurePackage")
        and has_public_struct(mask_distribution_source, "MaskDistributionClosureReport")
        and has_acceptance_test_function(
            mask_distribution_test,
            "closure",
            "package",
        )
    )
    rejection_equivalence_bridge_gate = (
        has_public_struct(
            rejection_equivalence_source, "AggregateRejectionEquivalenceGate"
        )
        and has_public_struct(
            rejection_equivalence_source, "AggregateRecomputationTranscript"
        )
        and has_public_enum(
            rejection_equivalence_source, "AggregateRejectionEvidenceStrength"
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "bridge",
            "equivalence",
        )
    )
    rejection_equivalence_closure_framework = (
        has_public_struct(
            rejection_equivalence_source, "AggregateRejectionClosurePackage"
        )
        and has_public_struct(
            rejection_equivalence_source, "AggregateRejectionClosureCertificate"
        )
        and has_public_enum(
            rejection_equivalence_source, "AggregateRejectionClosureStatus"
        )
        and has_public_function(
            rejection_equivalence_source, "assess_rejection_equivalence_closure"
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "closure",
            "package",
        )
    )
    p1_aggregate_recomputation_artifact_gate = (
        rejection_equivalence_closure_framework
        and has_public_enum(rejection_equivalence_source, "AcvpFips204EvidenceSource")
        and has_public_struct(rejection_equivalence_source, "Mldsa65ProviderKatEvidence")
        and has_public_struct(rejection_equivalence_source, "P1RejectionProofArtifacts")
        and has_public_struct(
            rejection_equivalence_source, "P1AggregateRecomputationClosurePackage"
        )
        and has_public_enum(
            rejection_equivalence_source, "P1AggregateRecomputationAssessment"
        )
        and has_public_function(
            rejection_equivalence_source,
            "standard_verifier_bridge_fixture_package_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_aggregate_recomputation_closure",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "p1",
            "recomputation",
            "closure",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "smoke",
            "kat",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "fixture",
            "package",
            "digest",
        )
    )
    p1_selected_backend_aggregate_artifact_gate = (
        p1_aggregate_recomputation_artifact_gate
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendAggregateArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendAggregateArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1SelectedBackendAggregateArtifactAssessment",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_selected_backend_aggregate_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_transcript_binding_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_signer_set_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_attempt_binding_digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "p1",
            "selected",
            "backend",
            "aggregate",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "stale",
            "bridge",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "unreviewed",
            "package",
        )
    )
    p1_selected_backend_real_output_package = (
        p1_selected_backend_aggregate_artifact_gate
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_aggregate_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_real_recomputation_evidence_digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "mldsa",
            "output",
            "package",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "stale",
            "recomputation",
            "output",
        )
    )
    p1_selected_backend_threshold_output_artifact_gate = (
        p1_selected_backend_real_output_package
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendThresholdOutputArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendThresholdOutputArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1SelectedBackendThresholdOutputArtifactAssessment",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_selected_backend_threshold_output_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_threshold_output_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_threshold_output_source_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_threshold_output_source_package_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_aggregate_certificate_digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "p1",
            "selected",
            "backend",
            "threshold",
            "output",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "mldsa",
            "package",
        )
    )
    p1_selected_backend_proof_closure_artifact_gate = (
        p1_selected_backend_threshold_output_artifact_gate
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendProofClosureArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1SelectedBackendProofClosureArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1SelectedBackendProofClosureArtifactAssessment",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1SelectedBackendProofClosureClaimBoundary",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_selected_backend_proof_closure_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_proof_closure_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_selected_backend_threshold_output_certificate_digest",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "full_kat_validation_artifact_digest",
            "rejection_distribution_review_digest",
            "threshold_output_certificate_artifact_digest",
            "real_recomputation_evidence_artifact_digest",
            "standard_verifier_compatibility_artifact_digest",
            "standard_verifier_compatibility_artifact",
            "theorem_linkage_artifact_digest",
            "transcript_binding_evidence_digest",
            "claims_selected_backend_proof_closure",
            "claims_rejection_distribution_preservation",
            "claims_cavp_acvts_validation",
            "claims_fips_validation",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "p1",
            "selected",
            "backend",
            "proof",
            "closure",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "stale",
            "threshold",
            "certificate",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "missing",
            "validation",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "missing",
            "distribution",
            "review",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "stale",
            "proof",
            "transcript",
            "binding",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "missing",
            "standard",
            "verifier",
            "compatibility",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "stale",
            "standard",
            "verifier",
            "compatibility",
            "artifact",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "missing",
            "theorem",
            "linkage",
            "artifact",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "production",
            "claim",
            "boundary",
        )
    )
    p1_criterion2_proof_slot_artifact_gates = (
        p1_selected_backend_proof_closure_artifact_gate
        and has_public_struct(
            rejection_equivalence_source,
            "P1Criterion2ProofSlotArtifact",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1Criterion2ProofSlotArtifacts",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1Criterion2ProofSlotArtifactKind",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_criterion2_proof_slot_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_criterion2_proof_slot_artifacts",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_criterion2_proof_slot_artifact_digest",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "FullKatValidation",
            "RejectionDistributionReview",
            "NormBound",
            "HintBound",
            "ChallengeBound",
            "TranscriptBinding",
            "TheoremLinkage",
            "ExternalReview",
            "ThresholdOutputCertificate",
            "RealRecomputationEvidence",
            "threshold_output_certificate_artifact",
            "real_recomputation_evidence_artifact",
            "threshold_output_certificate_artifact_digest",
            "real_recomputation_evidence_artifact_digest",
            "validate_p1_criterion2_proof_slot_artifact",
            "source_evidence_digest",
            "review_evidence_digest",
            "artifact_digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "typed",
            "slot",
            "kind",
            "drift",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "unreviewed",
            "typed",
            "slot",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "typed",
            "slot",
            "digest",
            "drift",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "threshold",
            "slot",
            "source",
            "tamper",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "threshold",
            "slot",
            "review",
            "tamper",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "recomputation",
            "slot",
            "source",
            "tamper",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "recomputation",
            "slot",
            "review",
            "tamper",
        )
    )
    p1_standard_verifier_compatibility_artifact_gate = (
        p1_selected_backend_threshold_output_artifact_gate
        and has_public_struct(
            rejection_equivalence_source,
            "P1StandardVerifierCompatibilityArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1StandardVerifierCompatibilityArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1StandardVerifierCompatibilityArtifactAssessment",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1StandardVerifierCompatibilityClaimBoundary",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1StandardVerifierCompatibilityResult",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_standard_verifier_compatibility_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_standard_verifier_compatibility_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_standard_verifier_compatibility_artifact_digest",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "artifact_digest",
            "threshold_output_certificate_digest",
            "provider_identity_digest",
            "public_key_digest",
            "message_digest",
            "accepted_signature_digest",
            "standard_verifier_bridge_evidence_digest",
            "real_recomputation_evidence_digest",
            "transcript_binding_digest",
            "P1StandardVerifierCompatibilityResult::Accept",
            "claims_selected_backend_proof_closure",
            "claims_standard_verifier_compatibility",
            "claims_rejection_distribution_preservation",
            "claims_cavp_acvts_validation",
            "claims_fips_validation",
            "claims_completed_cryptographic_proof",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "standard",
            "verifier",
            "compatibility",
            "accepts",
            "bound",
            "verifier",
            "payload",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "compatibility",
            "rejects",
            "failed",
            "standard",
            "verifier",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "compatibility",
            "rejects",
            "threshold",
            "certificate",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "compatibility",
            "rejects",
            "recomputation",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "compatibility",
            "rejects",
            "bridge",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "compatibility",
            "rejects",
            "production",
            "claim",
            "boundary",
        )
    )
    abort_bias_evidence_gate = (
        has_public_struct(abort_bias_source, "AbortBiasEvidence")
        and has_public_struct(abort_bias_source, "RetryBiasEvidenceReport")
        and has_acceptance_test_function(abort_bias_test, "bias")
    )
    abort_bias_closure_framework = (
        has_public_struct(abort_bias_source, "AbortRetryBiasProofPackage")
        and has_public_struct(abort_bias_source, "AbortBiasClosureReport")
        and has_public_enum(abort_bias_source, "AbortBiasClosureStatus")
        and has_acceptance_test_function(abort_bias_test, "closure")
    )
    partial_soundness_evidence_gate = (
        has_public_struct(
            partial_soundness_source, "PartialContributionSoundnessEvidence"
        )
        and has_public_struct(partial_soundness_source, "ProofBackedLocalVerifier")
        and has_acceptance_test_function(
            partial_soundness_test,
            "partial",
            "soundness",
        )
    )
    partial_soundness_closure_framework = (
        has_public_struct(partial_soundness_source, "PartialSoundnessClosurePackage")
        and has_public_enum(partial_soundness_source, "PartialSoundnessClosureStatus")
        and has_acceptance_test_function(
            partial_soundness_test,
            "closure",
            "package",
        )
    )
    unauthorized_reduction_manifest_gate = (
        "unauthorized aggregate reduction manifest" in reduction_manifest.lower()
        and "uar-c0" in reduction_manifest.lower()
        and "uar-c8" in reduction_manifest.lower()
        and "not a completed proof" in reduction_manifest.lower()
        and has_acceptance_test_function(
            reduction_manifest_test,
            "reduction",
            "manifest",
        )
    )
    unauthorized_reduction_closure_framework = (
        unauthorized_reduction_manifest_gate
        and "closure package framework" in reduction_manifest.lower()
        and "protocol event grammar" in reduction_manifest.lower()
        and "deterministic uar classifier" in reduction_manifest.lower()
        and "base ml-dsa theorem" in reduction_manifest.lower()
        and "hybrid bound" in reduction_manifest.lower()
        and "external review signoff" in reduction_manifest.lower()
    )
    hazmat_standard_verifier_bridge = (
        has_public_struct(provider_source, "HazmatMldsa65Provider")
        and "StandardMldsa65Provider" in provider_source
        and has_acceptance_test_function(
            provider_test,
            "hazmat",
            "provider",
            "verifies",
            "mldsa65",
            "signature",
        )
        and has_acceptance_test_function(
            provider_test,
            "hazmat",
            "provider",
            "rejects",
            "mutated",
        )
    )
    acvp_mldsa65_sample_kat = (
        hazmat_standard_verifier_bridge
        and "verify_with_context" in provider_source
        and has_acceptance_test_function(
            provider_test,
            "hazmat",
            "provider",
            "verifies",
            "mldsa65",
            "kats",
        )
        and "requires checked-in ACVP/FIPS ML-DSA-65 vectors" not in provider_test
        and "nist-acvp-server-mldsa65-sigver-fips204-sample"
        in acvp_mldsa65_sigver_fixture
        and "source_prompt_sha256" in acvp_mldsa65_sigver_fixture
        and "source_expected_results_sha256" in acvp_mldsa65_sigver_fixture
        and '"testPassed": true' in acvp_mldsa65_sigver_fixture
        and '"testPassed": false' in acvp_mldsa65_sigver_fixture
    )

    return {
        "documents": texts,
        "missing_documents": missing,
        "selected_backend_direction": selected_backend_direction(texts),
        "thesis_operating_parameters": thesis_operating_parameters,
        "thesis_operating_parameters_formalized": (
            thesis_operating_parameters["status"]
            == "formalized_research_boundary"
        ),
        "criterion2_proof_substance": criterion2_proof_substance,
        "criterion2_proof_substance_formalized": (
            criterion2_proof_substance["status"]
            == "criterion2_proof_payload_formalized"
        ),
        "acceptance_predicate_source_scaffold": acceptance_source_scaffold,
        "production_acceptance_tests_scaffold": production_acceptance_tests_scaffold,
        "local_acceptance_conformance_scaffold": (
            local_acceptance_conformance_scaffold
        ),
        "aggregate_acceptance_conformance_scaffold": (
            aggregate_acceptance_conformance_scaffold
        ),
        "mask_distribution_evidence_gate": mask_distribution_evidence_gate,
        "mask_distribution_closure_framework": mask_distribution_closure_framework,
        "rejection_equivalence_bridge_gate": rejection_equivalence_bridge_gate,
        "hazmat_standard_verifier_bridge": hazmat_standard_verifier_bridge,
        "acvp_mldsa65_sample_kat": acvp_mldsa65_sample_kat,
        "rejection_equivalence_closure_framework": (
            rejection_equivalence_closure_framework
        ),
        "p1_aggregate_recomputation_artifact_gate": (
            p1_aggregate_recomputation_artifact_gate
        ),
        "p1_selected_backend_aggregate_artifact_gate": (
            p1_selected_backend_aggregate_artifact_gate
        ),
        "p1_selected_backend_real_output_package": (
            p1_selected_backend_real_output_package
        ),
        "p1_selected_backend_threshold_output_artifact_gate": (
            p1_selected_backend_threshold_output_artifact_gate
        ),
        "p1_selected_backend_proof_closure_artifact_gate": (
            p1_selected_backend_proof_closure_artifact_gate
        ),
        "p1_criterion2_proof_slot_artifact_gates": (
            p1_criterion2_proof_slot_artifact_gates
        ),
        "p1_standard_verifier_compatibility_artifact_gate": (
            p1_standard_verifier_compatibility_artifact_gate
        ),
        "abort_bias_evidence_gate": abort_bias_evidence_gate,
        "abort_bias_closure_framework": abort_bias_closure_framework,
        "partial_soundness_evidence_gate": partial_soundness_evidence_gate,
        "partial_soundness_closure_framework": partial_soundness_closure_framework,
        "unauthorized_reduction_manifest_gate": unauthorized_reduction_manifest_gate,
        "unauthorized_reduction_closure_framework": (
            unauthorized_reduction_closure_framework
        ),
        "readme_research_boundary": (
            (
                "research status" in readme
                and "deterministic simulation" in readme
                and "if the hypothesis is proven" in readme
            )
            or (
                "current status" in readme
                and "research artifact" in readme
                and "not publishable as production cryptography" in readme
                and "partially_proven" in readme
                and "standard-verifier-compatible aggregate signature scheme"
                in readme
            )
        ),
        "standard_verifier_blocked": (
            "standard-verifier bridge tests" in combined
            or "standard mldsa verification" in combined
            or "standard ml-dsa verification" in combined
            or "does not perform real ml-dsa aggregate rejection checks" in combined
        ),
        "renyi_evidence_blocked": (
            "renyi divergence" in combined and "epsilon_mask" in combined
        ),
        "abort_bias_blocked": (
            "noise lemma g" in combined
            or "abort distribution" in combined
            or "abort compatibility" in combined
        ),
        "partial_soundness_scaffold": (
            "simulatedaggregator checks threshold and validator-universe matching"
            in combined
            or "context-bound" in combined
            or "transcript binding" in combined
            or "canonical collection" in combined
        ),
        "partial_soundness_blocked": (
            "fst-l4 partial-share validity" in combined
            or "localaccept" in combined
            or "real local acceptance" in combined
            or "vss hiding" in combined
        ),
        "unforgeability_reduction_blocked": (
            "fst-l6 no subthreshold signing" in combined
            or "proof status: not proved" in combined
            or "unauthorized aggregate output would imply a forgery" in combined
        ),
    }


def classify_criteria(criteria, scan):
    """Attach observed evidence, blockers, and status to each criterion."""
    classified = []
    missing = scan.get("missing_documents", [])
    missing_blocker = (
        "Missing required assessment documents: " + ", ".join(missing)
        if missing
        else None
    )
    readme_blocker = (
        "README keeps the hypothesis conditional on theorem closure, a reviewed "
        "threshold backend, and standard ML-DSA verification."
    )

    for criterion in criteria:
        item = dict(criterion)
        observed = []
        blockers = []
        status = "blocked"
        partial_progress = False
        selected_backend = scan.get("selected_backend_direction", {})

        if missing_blocker:
            blockers.append(missing_blocker)
        else:
            if selected_backend_observed(scan):
                partial_progress = True
                observed.append(selected_backend_observation(selected_backend))
                blockers.append(selected_backend_boundary_blocker())

        if missing_blocker:
            pass
        elif criterion["id"] == "aggregate_mask_distribution":
            if scan["mask_distribution_evidence_gate"]:
                partial_progress = True
                observed.append(
                    "MaskDistributionEvidence and "
                    "AcceptedMaskDistributionCertificate evidence gates are "
                    "present as scaffold evidence only."
                )
            if scan["mask_distribution_closure_framework"]:
                partial_progress = True
                observed.append(
                    "MaskDistributionClosurePackage and "
                    "MaskDistributionClosureReport framework checks are "
                    "present for proof-artifact completeness."
                )
            if scan["readme_research_boundary"]:
                blockers.append(readme_blocker)
            if scan["renyi_evidence_blocked"]:
                blockers.append(
                    "Renyi-divergence evidence for epsilon_mask is still a "
                    "release-readiness blocker."
                )
        elif criterion["id"] == "aggregate_rejection_equivalence":
            if scan["aggregate_acceptance_conformance_scaffold"]:
                observed.append(
                    "AggregateAccept conformance checks are present as "
                    "scaffold evidence only."
                )
            if scan["rejection_equivalence_bridge_gate"]:
                partial_progress = True
                observed.append(
                    "AggregateRejectionEquivalenceGate and "
                    "AggregateRecomputationTranscript bridge gates are present "
                    "as scaffold evidence only."
                )
            if scan["rejection_equivalence_closure_framework"]:
                partial_progress = True
                observed.append(
                    "AggregateRejectionClosurePackage and "
                    "AggregateRejectionClosureCertificate framework checks are "
                    "present for recomputation, KAT, bound, and review "
                    "artifacts."
                )
            if scan["hazmat_standard_verifier_bridge"]:
                partial_progress = True
                if scan.get("acvp_mldsa65_sample_kat"):
                    observed.append(
                        "HazmatMldsa65Provider standard-verifier bridge is "
                        "present for fixed-seed ML-DSA-65 signatures, mutated "
                        "message/signature rejection, and a bounded "
                        "ACVP/FIPS204 sample-vector KAT under "
                        "hazmat-real-mldsa; full KAT coverage and validation "
                        "remain separately gated."
                    )
                else:
                    observed.append(
                        "HazmatMldsa65Provider standard-verifier smoke bridge "
                        "is present for fixed-seed ML-DSA-65 signatures and "
                        "mutated message/signature rejection; ACVP/FIPS KAT "
                        "promotion remains separately gated."
                    )
            if scan.get("p1_aggregate_recomputation_artifact_gate"):
                partial_progress = True
                observed.append(
                    "P1 aggregate recomputation artifact gate is present for the "
                    "selected ML-DSA-65 coordinator-assisted profile; it binds "
                    "ACVP/FIPS204-backed provider KAT evidence, recomputation "
                    "digests, bound/proof artifacts, negative corpus evidence, "
                    "raw fixture-package digest, and external review digests "
                    "without claiming FIPS validation or production approval."
                )
            if scan.get("p1_selected_backend_aggregate_artifact_gate"):
                partial_progress = True
                observed.append(
                    "Selected-backend aggregate-output artifact gate is present "
                    "for P1; it binds LocalAccept/AggregateAccept evidence, "
                    "signer-set, attempt, transcript, provider KAT, "
                    "recomputation, and standard-verifier bridge digests as "
                    "conformance/proof-review evidence only, "
                    "not selected-backend proof closure, "
                    "not production threshold ML-DSA security, "
                    "not CAVP/ACVTS validation, not FIPS validation, and "
                    "not a completed standard-verifier compatibility proof."
                )
            if scan.get("p1_selected_backend_real_output_package"):
                partial_progress = True
                observed.append(
                    "Real standard-provider selected-backend aggregate-output package "
                    "evidence is present for P1; it is derived from a "
                    "provider-verified ML-DSA-65 candidate signature, "
                    "LocalAccept/AggregateAccept tokens, public recomputation "
                    "transcript, and standard-verifier bridge digest evidence. "
                    "This is stronger than fixture-only bridge confidence, but "
                    "it remains conformance/proof-review evidence only and does "
                    "not claim a real threshold aggregate signer, production "
                    "threshold ML-DSA security, CAVP/ACVTS validation, FIPS "
                    "validation, rejection-distribution preservation, or "
                    "completed standard-verifier compatibility proof."
                )
            if scan.get("p1_selected_backend_threshold_output_artifact_gate"):
                partial_progress = True
                observed.append(
                    "Selected-backend threshold-output artifact gate is present "
                    "for P1; it binds selected-backend threshold-output attempt "
                    "evidence to signer set, attempt, transcript, "
                    "LocalAccept/AggregateAccept, public recomputation, "
                    "standard-verifier bridge digest, and reviewed source package digest. This is stronger than real standard-provider aggregate-output package evidence, but it remains "
                    "conformance/proof-review evidence only and does not claim "
                    "production threshold ML-DSA security, selected-backend proof "
                    "closure, CAVP/ACVTS validation, FIPS validation, "
                    "rejection-distribution preservation, or completed "
                    "standard-verifier compatibility proof."
                )
            if scan.get("p1_selected_backend_proof_closure_artifact_gate"):
                partial_progress = True
                observed.append(
                    "Selected-backend proof-closure artifact package gate is "
                    "present for P1; it binds threshold-output, recomputation, "
                    "bounds, rejection behavior, and standard verification "
                    "evidence to the accepted threshold-output certificate, "
                    "provider KAT digest, reviewed source package digest, "
                    "full KAT/validation artifact slots, "
                    "rejection-distribution review digest, "
                    "standard-verifier compatibility artifact digest, and "
                    "theorem-linkage artifact digest. This is stronger than "
                    "the Batch 3 threshold-output artifact gate, but it remains "
                    "conformance/proof-review evidence only and does not claim "
                    "production threshold ML-DSA security, selected-backend "
                    "proof closure, CAVP/ACVTS validation, FIPS validation, "
                    "rejection-distribution preservation, or completed "
                    "standard-verifier compatibility proof."
                )
            if scan.get("p1_criterion2_proof_slot_artifact_gates"):
                partial_progress = True
                observed.append(
                    "Typed Criterion 2 proof-slot artifact packages are "
                    "present for P1; they domain-separate threshold-output "
                    "certificate, real recomputation, full KAT/validation, "
                    "rejection-distribution review, norm-bound, hint-bound, "
                    "challenge-bound, transcript-binding, theorem-linkage, "
                    "and external-review evidence as evidence_present_unclosed "
                    "only. All Criterion 2 proof slots have typed wrappers, "
                    "and the accepted proof-closure artifact certificate "
                    "carries durable predecessor slot artifact digests, "
                    "but they remain conformance/proof-review evidence only "
                    "and do not change aggregate_rejection_equivalence from "
                    "partially_met, do not change the overall verdict from "
                    "partially_proven, and do not claim selected-backend proof "
                    "closure, production threshold ML-DSA security, "
                    "CAVP/ACVTS validation, FIPS validation, "
                    "rejection-distribution preservation, or theorem closure."
                )
            if scan.get("p1_standard_verifier_compatibility_artifact_gate"):
                partial_progress = True
                observed.append(
                    "P1 standard-verifier compatibility artifact evidence is "
                    "present; it binds `pk`, `m`, and `sigma` through provider "
                    "identity/version, accept result, threshold-output "
                    "certificate digest, recomputation evidence digest, bridge "
                    "digest, and transcript binding. This fills the "
                    "standard_verifier_compatibility_artifact_digest slot as "
                    "evidence_present_unclosed only; it does not claim "
                    "selected-backend proof closure, production threshold "
                    "ML-DSA security, CAVP/ACVTS validation, FIPS validation, "
                    "rejection-distribution preservation, or completed "
                    "standard-verifier compatibility proof."
                )
            if scan["standard_verifier_blocked"]:
                if scan.get("p1_selected_backend_aggregate_artifact_gate"):
                    if scan.get(
                        "p1_selected_backend_proof_closure_artifact_gate"
                    ):
                        blockers.append(
                            "Selected-backend proof-closure artifact package gating "
                            "is present, but production threshold ML-DSA "
                            "security, selected-backend proof closure, full "
                            "ACVP/FIPS KAT coverage, external proof review, "
                            "CAVP/ACVTS validation artifacts, FIPS validation, "
                            "rejection-distribution preservation, and completed "
                            "standard-verifier compatibility remain open; the "
                            "proof-closure artifact package gate, threshold-output "
                            "artifact gate, real standard-provider aggregate-output "
                            "package, P1 recomputation gate, selected-backend "
                            "aggregate-output artifact gate, and bounded "
                            "sample-vector KAT are framework/conformance "
                            "evidence only."
                        )
                    elif scan.get("p1_selected_backend_threshold_output_artifact_gate"):
                        blockers.append(
                            "Selected-backend threshold-output artifact gating "
                            "is present, but production threshold ML-DSA "
                            "security, selected-backend proof closure, full "
                            "ACVP/FIPS KAT coverage, externally reviewed proof "
                            "artifacts, CAVP/ACVTS validation artifacts, FIPS "
                            "validation, rejection-distribution preservation, "
                            "and completed standard-verifier compatibility remain "
                            "open; the threshold-output artifact gate, real "
                            "standard-provider aggregate-output package, P1 "
                            "recomputation gate, selected-backend aggregate-output "
                            "artifact gate, and bounded sample-vector KAT are "
                            "framework/conformance evidence only."
                        )
                    elif scan.get("p1_selected_backend_real_output_package"):
                        blockers.append(
                            "Real threshold selected-backend aggregate outputs, "
                            "selected-backend proof closure, full ACVP/FIPS KAT "
                            "coverage, externally reviewed proof artifacts, and "
                            "CAVP/ACVTS validation artifacts are still not "
                            "checked in; the real standard-provider "
                            "aggregate-output package, P1 recomputation gate, "
                            "selected-backend aggregate-output artifact gate, "
                            "and bounded sample-vector KAT are "
                            "framework/conformance evidence only."
                        )
                    else:
                        blockers.append(
                            "Real selected-backend aggregate outputs, real P1 "
                            "aggregate recomputation artifacts, selected-backend "
                            "proof closure, full ACVP/FIPS KAT coverage, reviewed "
                            "proof artifacts, and CAVP/ACVTS validation artifacts "
                            "are still not checked in; the P1 recomputation gate, "
                            "selected-backend aggregate-output artifact gate, and "
                            "bounded sample-vector KAT are framework/conformance "
                            "evidence only."
                        )
                elif scan.get("p1_aggregate_recomputation_artifact_gate"):
                    blockers.append(
                        "Real P1 aggregate recomputation artifacts, full "
                        "ACVP/FIPS KAT coverage, reviewed proof artifacts, and "
                        "CAVP/ACVTS validation artifacts are still not checked "
                        "in; the P1 gate and bounded sample-vector KAT are "
                        "framework/conformance evidence only."
                    )
                elif scan["hazmat_standard_verifier_bridge"]:
                    blockers.append(
                        "Real aggregate recomputation and aggregate rejection "
                        "checks are not present; the hazmat standard-verifier "
                        "smoke bridge is not threshold aggregate evidence."
                    )
                else:
                    blockers.append(
                        "Standard ML-DSA verifier bridge and real aggregate "
                        "rejection checks are not present."
                    )
        elif criterion["id"] == "abort_retry_bias":
            if scan["abort_bias_evidence_gate"]:
                partial_progress = True
                observed.append(
                    "AbortBiasEvidence retry-domain, leakage, and "
                    "accepted-sample checks are present as scaffold evidence "
                    "only."
                )
            if scan["abort_bias_closure_framework"]:
                partial_progress = True
                observed.append(
                    "AbortRetryBiasProofPackage and AbortBiasClosureReport "
                    "framework checks are present for leakage, distribution, "
                    "threshold, and review artifacts."
                )
            if scan["abort_bias_blocked"]:
                blockers.append(
                    "Abort leakage and retry-bias distribution analysis remain "
                    "open proof obligations."
                )
        elif criterion["id"] == "partial_contribution_soundness":
            if scan["partial_soundness_scaffold"]:
                observed.append(
                    "Scaffold evidence supports transcript binding, validator "
                    "universe checks, or context-bound contribution shape."
                )
            if scan["local_acceptance_conformance_scaffold"]:
                observed.append(
                    "LocalAccept and AcceptedPartialContribution conformance "
                    "tokens are present as scaffold evidence only."
                )
            if scan["partial_soundness_evidence_gate"]:
                partial_progress = True
                observed.append(
                    "PartialContributionSoundnessEvidence and "
                    "ProofBackedLocalVerifier gates are present as scaffold "
                    "evidence only."
                )
            if scan["partial_soundness_closure_framework"]:
                partial_progress = True
                observed.append(
                    "PartialSoundnessClosurePackage framework checks are "
                    "present for proof-backed verifier, VSS/DKG, leakage, "
                    "context, and review artifacts."
                )
            if scan["partial_soundness_blocked"]:
                blockers.append(
                    "Production local acceptance, partial verification, and "
                    "hiding proof evidence are not complete."
                )
            status = "partially_met" if observed and blockers else "blocked"
        elif criterion["id"] == "unauthorized_aggregate_reduction":
            if scan["unauthorized_reduction_manifest_gate"]:
                partial_progress = True
                observed.append(
                    "Unauthorized aggregate reduction manifest names a base "
                    "ML-DSA forgery case and threshold-side violation cases as "
                    "scaffold evidence only."
                )
            if scan["unauthorized_reduction_closure_framework"]:
                partial_progress = True
                observed.append(
                    "Unauthorized aggregate reduction closure package framework "
                    "records protocol grammar, deterministic classifier, base "
                    "theorem, hybrid-bound, simulator, and review slots."
                )
            if scan["unforgeability_reduction_blocked"]:
                blockers.append(
                    "Threshold unforgeability reduction is stated as a target, "
                    "not a completed proof."
                )

        if criterion["id"] != "partial_contribution_soundness":
            status = "partially_met" if partial_progress and blockers else (
                "blocked" if blockers else "met"
            )

        item["observed_evidence"] = observed
        item["blockers"] = blockers
        item["status"] = status
        item["verdict_contribution"] = (
            "supports_scaffold_only" if status == "partially_met" else "not_proven"
        )
        classified.append(item)

    return classified


def default_commands():
    """Return default scaffold commands for the current-checkout assessment."""
    return [
        ["cargo", "test", "--test", "simulated_flow"],
        ["cargo", "test", "--test", "simulation"],
        ["cargo", "test", "--test", "proof_documentation_manifest"],
        ["cargo", "test", "--test", "thesis_operating_parameters_manifest"],
        ["cargo", "test", "--test", "criterion2_proof_substance_manifest"],
        ["cargo", "test", "--test", "unauthorized_aggregate_reduction_manifest"],
        [
            "cargo",
            "test",
            "--features",
            "coordinator-assisted",
            "--test",
            "production_epsilon",
            "--test",
            "production_prefilter",
            "--test",
            "production_hints",
            "--test",
            "production_wire",
            "--test",
            "production_transcript",
            "--test",
            "production_coordinator",
            "--test",
            "production_acceptance",
            "--test",
            "production_mask_distribution",
            "--test",
            "production_rejection_equivalence",
            "--test",
            "production_abort_bias",
            "--test",
            "production_partial_soundness",
        ],
        ["cargo", "run"],
    ]


def run_command(command, root, env=None):
    """Run one command and capture bounded metadata for the report."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=root,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def git_value(root, args, fallback="unknown"):
    """Return a git metadata value without failing report generation."""
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return fallback
    if completed.returncode != 0:
        return fallback
    value = completed.stdout.strip()
    return value if value else fallback


def command_environment(offline=False, target_dir=None):
    """Build environment overrides for Cargo command execution."""
    env = {}
    if offline:
        env["CARGO_NET_OFFLINE"] = "true"
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    return env


def summarize_commands(command_results):
    """Summarize command outcomes and extract lightweight execution evidence."""
    if not command_results:
        return {"all_passed": None, "passed": 0, "failed": 0}
    passed = sum(1 for result in command_results if result["exit_code"] == 0)
    failed = len(command_results) - passed
    return {"all_passed": failed == 0, "passed": passed, "failed": failed}


def execution_evidence(command_results):
    """Extract high-signal evidence from command output."""
    evidence = []
    if command_results and all(result["exit_code"] == 0 for result in command_results):
        evidence.append("Cargo scaffold checks completed")
    joined = "\n".join(result.get("stdout", "") for result in command_results)
    if "session_id,duration_ms,aborts,bandwidth_bytes" in joined:
        evidence.append("Simulation harness emitted duration, abort, and bandwidth telemetry.")
    if "test result: ok" in joined:
        evidence.append("Rust test output reported passing test suites.")
    return evidence


def build_report(
    root,
    run_commands=True,
    command_runner=run_command,
    commands=None,
    offline=False,
    target_dir=None,
):
    """Build the full assessment report dictionary."""
    root = Path(root)
    scan = scan_documents(root)
    criteria = classify_criteria(default_criteria(), scan)
    env = command_environment(offline=offline, target_dir=target_dir)
    selected_commands = commands if commands is not None else default_commands()
    command_results = []
    if run_commands:
        for command in selected_commands:
            command_results.append(command_runner(command, root, env))

    summary = summarize_commands(command_results)
    evidence = execution_evidence(command_results)
    if summary["failed"]:
        criteria = mark_command_failures(criteria, command_results)

    return {
        "testing_statement": TESTING_STATEMENT,
        "commit": git_value(root, ["rev-parse", "HEAD"]),
        "branch": git_value(root, ["branch", "--show-current"]),
        "claim_boundary": "research scaffold only",
        "selected_backend": scan["selected_backend_direction"],
        "thesis_operating_parameters": scan["thesis_operating_parameters"],
        "criterion2_proof_substance": scan["criterion2_proof_substance"],
        "readme_comparison": readme_comparison(scan),
        "criteria": criteria,
        "commands": command_results,
        "command_summary": summary,
        "execution_evidence": evidence,
        "overall_verdict": overall_verdict(criteria),
    }


def mark_command_failures(criteria, command_results):
    """Attach command failures without turning proof blockers into proof failures."""
    failed_commands = [
        " ".join(result["command"])
        for result in command_results
        if result["exit_code"] != 0
    ]
    if not failed_commands:
        return criteria
    marked = []
    for criterion in criteria:
        item = dict(criterion)
        item["blockers"] = list(item.get("blockers", []))
        item["blockers"].append(
            "Executable scaffold command failed: " + "; ".join(failed_commands)
        )
        if item["status"] == "met":
            item["status"] = "blocked"
        marked.append(item)
    return marked


def readme_comparison(scan):
    """Return claim-boundary comparison points against the top-level README."""
    if scan.get("readme_research_boundary"):
        return [
            "README states the repository is deterministic research scaffolding.",
            "README makes the hypothesis conditional on theorem closure, a reviewed threshold backend, and standard ML-DSA verification.",
            "Missing production proof artifacts are blockers, not contradictions.",
        ]
    return [
        "README research boundary was not detected; claim-drift review is required.",
    ]


def write_reports(report, out_dir):
    """Write JSON and Markdown assessment reports."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "assessment.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "assessment.md").write_text(render_markdown(report), encoding="utf-8")


def render_markdown(report):
    """Render a compact human-readable assessment."""
    lines = [
        "# Lattice Aggregation Hypothesis Assessment",
        "",
        f"Overall verdict: `{report['overall_verdict']}`",
        f"Claim boundary: `{report['claim_boundary']}`",
        f"Branch: `{report['branch']}`",
        f"Commit: `{report['commit']}`",
        "",
        "## Testing Statement",
        "",
        report["testing_statement"],
        "",
        "## README Comparison",
        "",
    ]
    for item in report["readme_comparison"]:
        lines.append(f"- {item}")

    selected_backend = report.get("selected_backend", {})
    lines.extend(["", "## Selected Backend Direction", ""])
    lines.append(f"- Status: `{selected_backend.get('status', 'not_observed')}`")
    if selected_backend.get("status") == "observed_selection_artifact":
        lines.append(f"- Direction: {selected_backend['direction']}")
        lines.append(
            f"- Assumption: {selected_backend['assumption']} coordinator assumption"
        )
        lines.append(f"- Output target: {selected_backend['output']}")
        lines.append(
            "- Later migration candidates: "
            + ", ".join(selected_backend["migration_candidates"])
        )
        lines.append(f"- Boundary: {selected_backend['claim_boundary']}")
    elif selected_backend.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(selected_backend["missing_evidence"])
        )

    thesis = report.get("thesis_operating_parameters", {})
    lines.extend(["", "## Thesis Operating Parameters", ""])
    lines.append(f"- Status: `{thesis.get('status', 'missing_or_incomplete')}`")
    if thesis.get("status") == "formalized_research_boundary":
        lines.append(f"- Thesis: {thesis['thesis_id']}")
        lines.append(f"- Boundary: {thesis['scope']}")
        lines.append(f"- Profile: {thesis['selected_profile']}")
        lines.append(f"- Output target: {thesis['output_target']}")
        fallback = thesis.get("fallback", {})
        lines.append(
            "- Fallback: "
            f"{fallback.get('architecture', '')}; "
            f"{fallback.get('status', '')}"
        )
    elif thesis.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(thesis["missing_evidence"])
        )

    criterion2 = report.get("criterion2_proof_substance", {})
    lines.extend(["", "## Criterion 2 Proof Substance", ""])
    lines.append(
        f"- Status: `{criterion2.get('status', 'missing_or_incomplete')}`"
    )
    if criterion2.get("status") == "criterion2_proof_payload_formalized":
        lines.append(f"- Criterion: {criterion2['criterion_id']}")
        lines.append(f"- Payload status: {criterion2['payload_status']}")
        lines.append(f"- Boundary: {criterion2['scope']}")
        lines.append(f"- Profile: {criterion2['selected_profile']}")
        lines.append(f"- Output target: {criterion2['output_target']}")
        lines.append(
            "- Required artifact slots: "
            + ", ".join(criterion2["required_artifact_slots"])
        )
        artifact_statuses = criterion2.get("artifact_slot_statuses", {})
        if artifact_statuses:
            lines.append(
                "- Artifact slot statuses: "
                + ", ".join(
                    f"{slot}={artifact_statuses[slot]}"
                    for slot in criterion2["required_artifact_slots"]
                    if slot in artifact_statuses
                )
            )
        artifact_sources = criterion2.get("artifact_slot_sources", {})
        if artifact_sources:
            lines.append(
                "- Artifact evidence sources: "
                + ", ".join(
                    f"{slot}={artifact_sources[slot]}"
                    for slot in criterion2["required_artifact_slots"]
                    if slot in artifact_sources
                )
            )
        certificate_accessors = criterion2.get(
            "artifact_slot_certificate_accessors", {}
        )
        if certificate_accessors:
            lines.append(
                "- Durable certificate accessors: "
                + ", ".join(
                    f"{slot}={certificate_accessors[slot]}"
                    for slot in criterion2["required_artifact_slots"]
                    if slot in certificate_accessors
                )
            )
        durable_certificate_evidence = criterion2.get(
            "durable_certificate_evidence", []
        )
        if durable_certificate_evidence:
            lines.append(
                "- Durable certificate evidence: "
                + ", ".join(
                    f"{entry['slot_id']}={entry['certificate_surface']}::{entry['certificate_accessor']}"
                    for entry in durable_certificate_evidence
                    if entry.get("slot_id")
                    and entry.get("certificate_surface")
                    and entry.get("certificate_accessor")
                )
            )
        lines.append(
            "- Theorem links: "
            + ", ".join(criterion2["theorem_links"])
        )
    elif criterion2.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(criterion2["missing_evidence"])
        )

    lines.extend(["", "## Criteria", ""])
    for criterion in report["criteria"]:
        lines.append(f"### {criterion['statement']}")
        lines.append("")
        lines.append(f"- Status: `{criterion['status']}`")
        if criterion.get("observed_evidence"):
            for evidence in criterion["observed_evidence"]:
                lines.append(f"- Evidence: {evidence}")
        if criterion.get("blockers"):
            for blocker in criterion["blockers"]:
                lines.append(f"- Blocker: {blocker}")
        lines.append("")

    lines.extend(["## Command Summary", ""])
    summary = report["command_summary"]
    if summary["all_passed"] is None:
        lines.append("Commands were skipped.")
    else:
        lines.append(
            f"Passed: {summary['passed']}; failed: {summary['failed']}; "
            f"all passed: `{summary['all_passed']}`."
        )
    for evidence in report["execution_evidence"]:
        lines.append(f"- {evidence}")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Assess lattice aggregation hypothesis evidence."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to assess.",
    )
    parser.add_argument(
        "--out",
        default="artifacts/hypothesis/latest",
        help="Output directory for assessment.json and assessment.md.",
    )
    parser.add_argument(
        "--skip-commands",
        action="store_true",
        help="Build the report without running Cargo commands.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Set CARGO_NET_OFFLINE=true for Cargo commands.",
    )
    parser.add_argument(
        "--target-dir",
        help="Set CARGO_TARGET_DIR for Cargo commands.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return 2 unless the verdict is completely_proven.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.root).resolve()
    report = build_report(
        root,
        run_commands=not args.skip_commands,
        offline=args.offline,
        target_dir=args.target_dir,
    )
    write_reports(report, Path(args.out))
    if args.strict and report["overall_verdict"] != "completely_proven":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
