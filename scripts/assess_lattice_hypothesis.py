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
    "claim_boundary": "selected backend direction for closure-run implementation",
}

SELECTED_BACKEND_REQUIRED_TOKENS = [
    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
    "TEE/HSM coordinator assumption",
    "standard-verifier-compatible output",
    "P2/MPC",
    "TALUS",
    "closure-run implementation",
    "implementation evidence",
]

REQUIREMENT_TEXT_ANCHORS = [
    "requires selected-backend proof closure evidence",
    "requires production threshold ML-DSA security evidence",
    "requires CAVP/ACVTS validation evidence",
    "requires FIPS validation evidence",
    "requires a completed standard-verifier compatibility proof",
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
    "boundary": "conformance/proof-review evidence",
}

P1_NONCE_PRODUCER_SELECTION_DOC = (
    "docs/cryptography/p1-nonce-producer-selection.md"
)
P1_NONCE_PRODUCER_SELECTION_MANIFEST = (
    "docs/cryptography/p1-nonce-producer-selection.json"
)
P1_NONCE_PRODUCER_SELECTION_SCHEMA = (
    "lattice-aggregation.p1-nonce-producer-selection.v1"
)
P1_NONCE_PRODUCER_ROUTE = (
    "FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1"
)
P1_NONCE_PRODUCER_PROFILE = "P1 TEE/HSM coordinator"
P1_NONCE_PRODUCER_REPLACEMENT_TARGET = (
    "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key"
)
P1_NONCE_PRODUCER_REQUIRED_SLOT = (
    "distributed_nonce_producer_artifact_digest"
)
P1_NONCE_PRODUCER_REQUIRED_BACKEND_ARTIFACTS = [
    "source_reference_digest",
    "selected_profile_binding_digest",
    "backend_implementation_digest",
    "coordinator_attestation_digest",
    "shamir_nonce_dkg_transcript_digest",
    "active_set_digest",
    "pairwise_mask_seed_commitment_digest",
    "nonce_share_commitment_digest",
    "attempt_binding_digest",
    "abort_accountability_digest",
    "standard_verifier_bridge_digest",
    "external_review_digest",
]
P1_NONCE_PRODUCER_SOURCES = [
    "https://arxiv.org/abs/2601.20917",
    "https://www.usenix.org/conference/usenixsecurity26/presentation/bienstock",
    "https://www.usenix.org/conference/usenixsecurity26/presentation/celi",
    "https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1",
]
P1_NONCE_PRODUCER_FALSE_CLAIM_KEYS = [
    "claims_theorem_closure",
    "claims_selected_backend_proof_closure",
    "claims_production_threshold_mldsa_security",
    "claims_rejection_distribution_preservation",
    "claims_standard_verifier_compatibility_complete",
    "claims_fips_validation",
    "claims_cavp_acvts_validation",
]
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

CRITERION1_PROOF_SUBSTANCE_DOC = (
    "docs/cryptography/criterion-1-proof-substance.md"
)
CRITERION1_PROOF_SUBSTANCE_MANIFEST = (
    "docs/cryptography/criterion-1-proof-substance.json"
)
CRITERION1_PROOF_SUBSTANCE_SCHEMA = (
    "lattice-aggregation.criterion-1-proof-substance.v1"
)
CRITERION1_ID = "aggregate_mask_distribution"
CRITERION1_FALSE_CLAIM_KEYS = [
    "claims_criterion_met",
    "claims_mask_distribution_proven",
    "claims_selected_backend_proof_closure",
    "claims_rejection_distribution_preservation",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
    "claims_production_threshold_mldsa_security",
]
CRITERION1_REQUIRED_ARTIFACT_SLOTS = [
    "selected_mask_construction_digest",
    "centralized_distribution_artifact_digest",
    "aggregate_distribution_artifact_digest",
    "renyi_bound_proof_digest",
    "min_entropy_review_digest",
    "parameter_selection_digest",
    "external_review_digest",
]
CRITERION1_EVIDENCE_SOURCES = {
    "selected_mask_construction_digest": (
        "p1_criterion1_mask_construction_artifact_gate"
    ),
    "centralized_distribution_artifact_digest": (
        "p1_criterion1_centralized_distribution_artifact_gate"
    ),
    "aggregate_distribution_artifact_digest": (
        "p1_criterion1_aggregate_distribution_artifact_gate"
    ),
    "renyi_bound_proof_digest": (
        "p1_criterion1_renyi_bound_proof_artifact_gate"
    ),
    "min_entropy_review_digest": (
        "p1_criterion1_min_entropy_review_artifact_gate"
    ),
    "parameter_selection_digest": (
        "p1_criterion1_parameter_selection_artifact_gate"
    ),
    "external_review_digest": "p1_criterion1_external_review_artifact_gate",
}
CRITERION1_ARTIFACT_PACKAGE = "p1_criterion1_proof_payload_package"
CRITERION1_ARTIFACT_SLOT_STATUSES = {
    slot: "required_unclosed" for slot in CRITERION1_REQUIRED_ARTIFACT_SLOTS
}
CRITERION1_THEOREM_LINKS = [
    "Noise Lemma B",
    "Noise Lemma H",
    "Correctness Lemma 8",
    "FST-L7",
]

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
    "claims_theorem_closure",
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
    "distributed_nonce_producer_artifact_digest",
    "standard_verifier_compatibility_artifact_digest",
    "real_threshold_backend_emission_artifact_digest",
    "external_backend_cryptographic_closure_candidate",
    "external_backend_evidence_attempt",
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
    "distributed_nonce_producer_artifact_digest": (
        "p1_criterion2_distributed_nonce_producer_artifact_gate"
    ),
    "standard_verifier_compatibility_artifact_digest": (
        "p1_standard_verifier_compatibility_artifact_gate"
    ),
    "real_threshold_backend_emission_artifact_digest": (
        "p1_real_threshold_backend_output_gate"
    ),
    "external_backend_cryptographic_closure_candidate": (
        "p1_external_backend_cryptographic_closure_candidate_gate"
    ),
    "external_backend_evidence_attempt": (
        "p1_external_backend_evidence_attempt_gate"
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
CRITERION2_ARTIFACT_SLOT_SOURCES = {
    **CRITERION2_EVIDENCE_PRESENT_SLOTS,
}
CRITERION2_EVIDENCE_PRESENT_PACKAGES = {
    "standard_verifier_compatibility_artifact_digest": (
        "p1_standard_verifier_compatibility_artifact_package"
    ),
    "real_threshold_backend_emission_artifact_digest": (
        "p1_real_threshold_backend_emission_artifact_package"
    ),
    "external_backend_cryptographic_closure_candidate": (
        "p1_external_backend_cryptographic_closure_candidate_package"
    ),
    "external_backend_evidence_attempt": (
        "p1_external_backend_evidence_attempt_artifact"
    ),
    **{
        slot: "p1_criterion2_proof_slot_artifact_package"
        for slot in CRITERION2_ARTIFACT_SLOT_SOURCES
        if slot
        not in {
            "standard_verifier_compatibility_artifact_digest",
            "real_threshold_backend_emission_artifact_digest",
            "external_backend_cryptographic_closure_candidate",
            "external_backend_evidence_attempt",
        }
    },
}
CRITERION2_DURABLE_CERTIFICATE_ACCESSORS = {
    "threshold_output_certificate_digest": (
        "threshold_output_certificate_artifact_digest"
    ),
    "real_recomputation_evidence_digest": (
        "real_recomputation_evidence_artifact_digest"
    ),
    "distributed_nonce_producer_artifact_digest": (
        "distributed_nonce_producer_artifact_digest"
    ),
    "external_backend_cryptographic_closure_candidate": (
        "candidate_artifact_digest"
    ),
}
CRITERION2_DURABLE_CERTIFICATE_SURFACES = {
    "threshold_output_certificate_digest": (
        "p1_selected_backend_proof_closure_artifact_certificate"
    ),
    "real_recomputation_evidence_digest": (
        "p1_selected_backend_proof_closure_artifact_certificate"
    ),
    "distributed_nonce_producer_artifact_digest": (
        "p1_selected_backend_proof_closure_artifact_certificate"
    ),
    "external_backend_cryptographic_closure_candidate": (
        "p1_external_backend_cryptographic_closure_candidate_certificate"
    ),
}
CRITERION2_DURABLE_CERTIFICATE_EVIDENCE_SURFACES = {
    "threshold_output_certificate_digest": (
        "P1SelectedBackendProofClosureArtifactCertificate"
    ),
    "real_recomputation_evidence_digest": (
        "P1SelectedBackendProofClosureArtifactCertificate"
    ),
    "distributed_nonce_producer_artifact_digest": (
        "P1SelectedBackendProofClosureArtifactCertificate"
    ),
    "external_backend_cryptographic_closure_candidate": (
        "P1ExternalBackendCryptographicClosureCandidateCertificate"
    ),
}
CRITERION2_ARTIFACT_FIXTURE_REFS = [
    {
        "slot_id": "threshold_output_certificate_digest",
        "fixture_path": (
            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
        ),
        "schema": "lattice-aggregation:p1-threshold-output-certificate-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "real_recomputation_evidence_digest",
        "fixture_path": "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-real-recomputation-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "standard_verifier_compatibility_artifact_digest",
        "fixture_path": "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "real_threshold_backend_emission_artifact_digest",
        "fixture_path": "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "real_threshold_backend_emission_artifact_digest",
        "fixture_path": (
            "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
        ),
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "current_status": (
            "checked_capture_schema_fixture_blocked_until_actual_backend_evidence"
        ),
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "distributed_nonce_producer_artifact_digest",
        "fixture_path": "artifacts/nonce-producer-handoff/latest/capture/capture.json",
        "schema": "lattice-aggregation:p1-distributed-nonce-producer-capture:v1",
        "current_status": (
            "checked_handoff_replay_importable_until_actual_backend_evidence"
        ),
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "distributed_nonce_producer_artifact_digest",
        "fixture_path": (
            "artifacts/nonce-producer-backend-readiness/latest/manifest.json"
        ),
        "schema": "lattice-aggregation:p1-nonce-producer-backend-readiness:v1",
        "current_status": "backend_candidate_admissible_pending_capture",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "distributed_nonce_producer_artifact_digest",
        "fixture_path": (
            "artifacts/nonce-producer-capture-attempt/latest/manifest.json"
        ),
        "schema": (
            "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
        ),
        "current_status": "capture_promoted",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "distributed_nonce_producer_artifact_digest",
        "fixture_path": (
            "artifacts/nonce-producer-actual-external-gate/latest/manifest.json"
        ),
        "schema": "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
        "current_status": "actual_external_capture_ready",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "external_backend_cryptographic_closure_candidate",
        "fixture_path": (
            "artifacts/p1-external-backend-cryptographic-closure-candidate/"
            "latest/manifest.json"
        ),
        "schema": (
            "lattice-aggregation:p1-external-backend-cryptographic-closure-"
            "candidate:v1"
        ),
        "current_status": "evidence_present_unclosed",
        "close_candidate": True,
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "external_backend_evidence_attempt",
        "fixture_path": (
            "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json"
        ),
        "schema": "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
        "current_status": "external_evidence_close_candidate_ready",
        "close_candidate": True,
        "source_exclusion_passed": True,
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "theorem_closure_review",
        "fixture_path": "artifacts/theorem-closure-review/latest/manifest.json",
        "schema": "lattice-aggregation:theorem-closure-review:v1",
        "current_status": "theorem_closure_review_incomplete",
        "proof_payload_reviewed": True,
        "standard_verifier_compatibility_reviewed": True,
        "rejection_distribution_preservation_reviewed": False,
        "full_kat_validation_reviewed": False,
        "theorem_linkage_reviewed": False,
        "claim_boundary": "readiness preflight only; pending theorem-closure review",
    },
    {
        "slot_id": "rejection_distribution_review_digest",
        "fixture_path": (
            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json"
        ),
        "schema": "lattice-aggregation:p1-rejection-distribution-review-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
    {
        "slot_id": "theorem_linkage_artifact_digest",
        "fixture_path": "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
        "schema": "lattice-aggregation:p1-theorem-linkage-artifact:v1",
        "current_status": "evidence_present_unclosed",
        "claim_boundary": "conformance/proof-review evidence",
    },
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

CRITERION3_PROOF_SUBSTANCE_DOC = (
    "docs/cryptography/criterion-3-proof-substance.md"
)
CRITERION3_PROOF_SUBSTANCE_MANIFEST = (
    "docs/cryptography/criterion-3-proof-substance.json"
)
CRITERION3_PROOF_SUBSTANCE_SCHEMA = (
    "lattice-aggregation.criterion-3-proof-substance.v1"
)
CRITERION3_ID = "abort_retry_bias"
CRITERION3_FALSE_CLAIM_KEYS = [
    "claims_criterion_met",
    "claims_abort_retry_bias_proven",
    "claims_selected_backend_proof_closure",
    "claims_accepted_signature_distribution",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
    "claims_production_threshold_mldsa_security",
]
CRITERION3_REQUIRED_ARTIFACT_SLOTS = [
    "retry_domain_separation_proof_digest",
    "formal_abort_leakage_model_digest",
    "accepted_signature_distribution_proof_digest",
    "adversarial_abort_policy_corpus_digest",
    "sample_size_bucket_rationale_digest",
    "timeout_retry_policy_digest",
    "external_review_digest",
]
CRITERION3_EVIDENCE_SOURCES = {
    "retry_domain_separation_proof_digest": (
        "p1_criterion3_retry_domain_separation_artifact_gate"
    ),
    "formal_abort_leakage_model_digest": (
        "p1_criterion3_abort_leakage_model_artifact_gate"
    ),
    "accepted_signature_distribution_proof_digest": (
        "p1_criterion3_accepted_signature_distribution_artifact_gate"
    ),
    "adversarial_abort_policy_corpus_digest": (
        "p1_criterion3_adversarial_abort_policy_corpus_artifact_gate"
    ),
    "sample_size_bucket_rationale_digest": (
        "p1_criterion3_sample_size_bucket_rationale_artifact_gate"
    ),
    "timeout_retry_policy_digest": (
        "p1_criterion3_timeout_retry_policy_artifact_gate"
    ),
    "external_review_digest": "p1_criterion3_external_review_artifact_gate",
}
CRITERION3_ARTIFACT_PACKAGE = "p1_criterion3_proof_payload_package"
CRITERION3_ARTIFACT_SLOT_STATUSES = {
    slot: "required_unclosed" for slot in CRITERION3_REQUIRED_ARTIFACT_SLOTS
}
CRITERION3_THEOREM_LINKS = [
    "Noise Lemma G",
    "Noise Lemma H",
    "FST-L7",
    "FST-L9",
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
        "research scaffold evidence",
        "ml-dsa-65 coordinator-assisted shamir nonce dkg p1",
        "one standard-sized ml-dsa-65 signature if proven",
        "partially_proven",
        "partially_met",
        "requires selected-backend proof closure evidence",
        "requires production threshold ml-dsa security evidence",
        "requires cavp/acvts validation evidence",
        "requires fips validation evidence",
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
        and claim_boundary.get("scope") == "research scaffold evidence"
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


def p1_nonce_producer_selection_status(markdown, manifest_text):
    """Return source-backed P1 nonce-producer route selection status."""
    normalized = normalize_whitespace(markdown)
    manifest = parse_json_document(manifest_text)
    claim_boundary = manifest.get("claim_boundary", {})
    selected_route = manifest.get("selected_route", {})
    open_target = manifest.get("open_target", {})
    required_backend_artifacts = manifest.get("required_backend_artifacts", [])
    sources = manifest.get("sources", [])

    expected_markdown_tokens = [
        "# p1 nonce producer selection",
        "p1_nonce_producer_route_selected",
        "fips 204-compatible threshold ml-dsa via shamir nonce dkg p1",
        "p1 tee/hsm coordinator",
        "distributed_nonce_producer_artifact_digest",
        "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key",
        "shamir_nonce_dkg_transcript_digest",
        "pairwise_mask_seed_commitment_digest",
        "hazmat prf-output oracle",
        "required_unclosed",
        "pending theorem-closure review",
        "requires selected-backend proof closure evidence",
        "requires production threshold ml-dsa security evidence",
        "requires rejection-distribution preservation proof",
        "https://arxiv.org/abs/2601.20917",
        "https://www.usenix.org/conference/usenixsecurity26/presentation/bienstock",
        "https://www.usenix.org/conference/usenixsecurity26/presentation/celi",
        "https://csrc.nist.gov/projects/threshold-cryptography/tcall-1",
    ]
    missing_evidence = [
        token for token in expected_markdown_tokens if token not in normalized
    ]
    false_claims_pinned = all(
        claim_boundary.get(key) is False
        for key in P1_NONCE_PRODUCER_FALSE_CLAIM_KEYS
    )
    backend_artifacts_pinned = all(
        artifact in required_backend_artifacts
        for artifact in P1_NONCE_PRODUCER_REQUIRED_BACKEND_ARTIFACTS
    )
    sources_pinned = all(source in sources for source in P1_NONCE_PRODUCER_SOURCES)
    manifest_ok = (
        manifest.get("schema") == P1_NONCE_PRODUCER_SELECTION_SCHEMA
        and manifest.get("status") == "p1_nonce_producer_route_selected"
        and selected_route.get("name") == P1_NONCE_PRODUCER_ROUTE
        and selected_route.get("profile") == P1_NONCE_PRODUCER_PROFILE
        and selected_route.get("assumption") == "TEE/HSM coordinator"
        and selected_route.get("output_target")
        == "standard-size ML-DSA-65 signatures accepted by unmodified FIPS 204 verifiers"
        and open_target.get("replacement_target")
        == P1_NONCE_PRODUCER_REPLACEMENT_TARGET
        and open_target.get("required_artifact_slot")
        == P1_NONCE_PRODUCER_REQUIRED_SLOT
        and open_target.get("current_status") == "required_unclosed"
        and false_claims_pinned
        and backend_artifacts_pinned
        and sources_pinned
    )
    selected = bool(markdown.strip()) and manifest_ok and not missing_evidence
    if not manifest:
        missing_evidence.append(P1_NONCE_PRODUCER_SELECTION_MANIFEST)
    if not markdown.strip():
        missing_evidence.append(P1_NONCE_PRODUCER_SELECTION_DOC)
    if manifest and not false_claims_pinned:
        missing_evidence.append("claim_boundary false claims")
    if manifest and not backend_artifacts_pinned:
        missing_evidence.append("required_backend_artifacts")
    if manifest and not sources_pinned:
        missing_evidence.append("sources")

    return {
        "status": (
            "p1_nonce_producer_route_selected"
            if selected
            else "missing_or_incomplete"
        ),
        "document_path": P1_NONCE_PRODUCER_SELECTION_DOC,
        "manifest_path": P1_NONCE_PRODUCER_SELECTION_MANIFEST,
        "selected_route": selected_route.get("name", ""),
        "profile": selected_route.get("profile", ""),
        "replacement_target": open_target.get("replacement_target", ""),
        "required_artifact_slot": open_target.get("required_artifact_slot", ""),
        "claims_theorem_closure": claim_boundary.get("claims_theorem_closure"),
        "required_backend_artifacts": required_backend_artifacts,
        "sources": sources,
        "missing_evidence": sorted(set(missing_evidence)),
    }


def criterion1_proof_substance_status(markdown, manifest_text):
    """Return Criterion-1 proof-payload status without criterion promotion."""
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
    theorem_links = proof_payload.get("theorem_links", [])

    expected_markdown_tokens = [
        "# criterion 1 proof substance",
        "aggregate_mask_distribution",
        "formalized_open_proof_payload",
        "criterion1_proof_payload_formalized",
        "centralized ml-dsa-65 mask distribution",
        "selected profile p1 aggregate mask distribution",
        "renyi divergence bound for epsilon_mask",
        "selected_mask_construction_digest",
        "centralized_distribution_artifact_digest",
        "aggregate_distribution_artifact_digest",
        "renyi_bound_proof_digest",
        "min_entropy_review_digest",
        "parameter_selection_digest",
        "external_review_digest",
        "required_unclosed",
        "p1_criterion1_proof_payload_package",
        "p1_criterion1_renyi_bound_proof_artifact_gate",
        "conformance/proof-review evidence",
        "maskdistributionevidence",
        "acceptedmaskdistributioncertificate",
        "maskdistributionclosurepackage",
        "noise lemma b",
        "noise lemma h",
        "correctness lemma 8",
        "fst-l7",
        "partially_met",
        "partially_proven",
        "requires selected-backend proof closure evidence",
        "requires production threshold ml-dsa security evidence",
        "requires cavp/acvts validation evidence",
        "requires fips validation evidence",
        "requires rejection-distribution preservation proof",
        "requires a completed mask-distribution proof",
    ]
    missing_evidence = [
        token
        for token in expected_markdown_tokens
        if token not in normalized
    ]
    false_claims_pinned = all(
        claim_boundary.get(key) is False for key in CRITERION1_FALSE_CLAIM_KEYS
    )
    artifact_slot_statuses = {
        slot_id: slot_by_id.get(slot_id, {}).get("current_status", "")
        for slot_id in CRITERION1_REQUIRED_ARTIFACT_SLOTS
    }
    artifact_slot_sources = {
        slot_id: slot_by_id.get(slot_id, {}).get("evidence_source", "")
        for slot_id in CRITERION1_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("evidence_source")
    }
    artifact_slot_packages = {
        slot_id: slot_by_id.get(slot_id, {}).get("artifact_package", "")
        for slot_id in CRITERION1_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("artifact_package")
    }
    artifact_slots_pinned = (
        artifact_slot_statuses == CRITERION1_ARTIFACT_SLOT_STATUSES
        and artifact_slot_sources == CRITERION1_EVIDENCE_SOURCES
        and artifact_slot_packages
        == {
            slot: CRITERION1_ARTIFACT_PACKAGE
            for slot in CRITERION1_REQUIRED_ARTIFACT_SLOTS
        }
        and all(
            slot_by_id.get(slot_id, {}).get("claim_boundary")
            == "conformance/proof-review evidence"
            for slot_id in CRITERION1_REQUIRED_ARTIFACT_SLOTS
        )
    )
    theorem_links_pinned = entries_contain_terms(
        theorem_links,
        CRITERION1_THEOREM_LINKS,
    )
    promotion_anchors_pinned = entries_contain_terms(
        manifest.get("promotion_requires", []),
        [
            "selected aggregate-mask construction",
            "centralized ML-DSA-65 reference distribution",
            "selected Profile P1 aggregate-mask distribution",
            "Renyi-divergence proof",
            "min-entropy",
            "external cryptographic review",
        ],
    )
    failure_anchors_pinned = entries_contain_terms(
        manifest.get("failure_conditions", []),
        [
            "distinguishable",
            "epsilon_mask",
            "min-entropy",
        ],
    )
    manifest_ok = (
        manifest.get("schema") == CRITERION1_PROOF_SUBSTANCE_SCHEMA
        and manifest.get("criterion_id") == CRITERION1_ID
        and manifest.get("status") == "formalized_open_proof_payload"
        and claim_boundary.get("scope") == "criterion-1 proof payload only"
        and selected_profile.get("name")
        == "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
        and selected_profile.get("feature_gate") == "production-mldsa65-coordinator"
        and selected_profile.get("output_target")
        == "one standard-sized ML-DSA-65 signature if proven"
        and proof_payload.get("centralized_mask_target")
        == "centralized ML-DSA-65 mask distribution"
        and proof_payload.get("aggregate_mask_target")
        == "selected Profile P1 aggregate mask distribution"
        and proof_payload.get("distance_measure")
        == "Renyi divergence bound for epsilon_mask"
        and false_claims_pinned
        and artifact_slots_pinned
        and theorem_links_pinned
        and promotion_anchors_pinned
        and failure_anchors_pinned
        and assessment.get("criterion_status") == "partially_met"
        and assessment.get("overall_verdict") == "partially_proven"
        and assessment.get("does_not_change_overall_verdict") is True
        and assessment.get("report_status")
        == "criterion1_proof_payload_formalized"
    )
    formalized = bool(markdown.strip()) and manifest_ok and not missing_evidence
    if not manifest:
        missing_evidence.append(CRITERION1_PROOF_SUBSTANCE_MANIFEST)
    if not markdown.strip():
        missing_evidence.append(CRITERION1_PROOF_SUBSTANCE_DOC)
    if manifest and not false_claims_pinned:
        missing_evidence.append("claim_boundary false claims")
    if manifest and not artifact_slots_pinned:
        missing_evidence.append("required_artifact_slots")
    if manifest and not theorem_links_pinned:
        missing_evidence.append("theorem_links")

    return {
        "status": (
            "criterion1_proof_payload_formalized"
            if formalized
            else "missing_or_incomplete"
        ),
        "document_path": CRITERION1_PROOF_SUBSTANCE_DOC,
        "manifest_path": CRITERION1_PROOF_SUBSTANCE_MANIFEST,
        "criterion_id": manifest.get("criterion_id", ""),
        "payload_status": manifest.get("status", ""),
        "scope": claim_boundary.get("scope", ""),
        "selected_profile": selected_profile.get("name", ""),
        "output_target": selected_profile.get("output_target", ""),
        "required_artifact_slots": CRITERION1_REQUIRED_ARTIFACT_SLOTS,
        "artifact_slot_statuses": artifact_slot_statuses,
        "artifact_slot_sources": artifact_slot_sources,
        "theorem_links": theorem_links,
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
        "distributed_nonce_producer_artifact_digest",
        "p1_criterion2_distributed_nonce_producer_artifact_gate",
        "hazmat prf-output oracle",
        "p1 nonce producer selection",
        "standard_verifier_compatibility_artifact_digest",
        "external_backend_cryptographic_closure_candidate",
        "p1_external_backend_cryptographic_closure_candidate_gate",
        "p1_external_backend_cryptographic_closure_candidate_package",
        "p1externalbackendcryptographicclosurecandidatepackage",
        "scripts/build_p1_external_backend_cryptographic_closure_candidate.py",
        "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json",
        "close_candidate = true",
        "actual external nonce capture",
        "external_backend_evidence_attempt",
        "p1_external_backend_evidence_attempt_gate",
        "p1_external_backend_evidence_attempt_artifact",
        "scripts/run_p1_external_backend_evidence_attempt.py",
        "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json",
        "external_evidence_close_candidate_ready",
        "source_exclusion_passed",
        "scripts/build_theorem_closure_review_manifest.py",
        "theorem_closure_review_incomplete",
        "evidence_present_unclosed",
        "evidence_present_unclosed only",
        "typed criterion 2 proof-slot artifact packages",
        "p1_criterion2_proof_slot_artifact_package",
        "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json",
        "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
        "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json",
        "tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json",
        "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json",
        "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
        "artifacts/nonce-producer-handoff/latest/manifest.json",
        "artifacts/nonce-producer-handoff/latest/capture/capture.json",
        "artifacts/nonce-producer-backend-readiness/latest/manifest.json",
        "artifacts/nonce-producer-capture-attempt/latest/manifest.json",
        "docs/cryptography/p1-nonce-producer-backend-cli-contract.md",
        "scripts/run_nonce_producer_handoff_replay.py",
        "scripts/emit_reviewed_nonce_producer_capture.py",
        "scripts/check_nonce_producer_backend_readiness.py",
        "scripts/run_admissible_nonce_producer_capture_attempt.py",
        "scripts/verify_actual_nonce_producer_capture.py",
        "scripts/stage_external_nonce_producer_capture.py",
        "backend_candidate_admissible_pending_capture",
        "capture_promoted",
        "actual_external_capture_ready",
        "outside_repo_capture_file",
        "preexisting_external_capture_file",
        "outside_repo_review_manifest",
        "reviewed_external_capture_ready",
        "capture-attempt runner",
        "distributed nonce-prf interfaces",
        "no detected blockers",
        "repo_reference_cli_capture",
        "admissible_external_backend_capture",
        "reference cli",
        "requires actual backend evidence",
        "checked_nonce_producer_handoff_replay_capture_json_feeds_rust_importer",
        "checked threshold-output certificate fixture",
        "checked recomputation fixture",
        "checked standard-verifier compatibility fixture",
        "checked real-threshold backend emission ingestion fixture harness",
        "actual single-key ml-dsa-65 negative-control emission fixture",
        "reference cli handoff replay only",
        "standardprovidersinglekey",
        "checked rejection-distribution review fixture",
        "checked theorem-linkage fixture",
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
        "conformance/proof-review evidence",
        "correctness lemma 7",
        "correctness lemma 8",
        "noise lemma d",
        "noise lemma f",
        "noise lemma h",
        "fst-l5",
        "fst-l7",
        "partially_met",
        "partially_proven",
        "requires selected-backend proof closure evidence",
        "requires production threshold ml-dsa security evidence",
        "requires cavp/acvts validation evidence",
        "requires fips validation evidence",
        "requires rejection-distribution preservation proof",
        "requires a completed standard-verifier compatibility proof",
        "requires real threshold backend implementation evidence",
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
        == "conformance/proof-review evidence"
        for slot_id, evidence_source in CRITERION2_EVIDENCE_PRESENT_SLOTS.items()
    )
    artifact_slots_pinned = (
        artifact_slot_statuses == CRITERION2_ARTIFACT_SLOT_STATUSES
        and artifact_slot_sources == CRITERION2_ARTIFACT_SLOT_SOURCES
        and artifact_slot_packages == CRITERION2_EVIDENCE_PRESENT_PACKAGES
        and artifact_slot_certificate_accessors
        == CRITERION2_DURABLE_CERTIFICATE_ACCESSORS
        and durable_certificate_evidence_by_slot.keys()
        == CRITERION2_DURABLE_CERTIFICATE_ACCESSORS.keys()
        and all(
            slot_by_id.get(slot_id, {}).get("certificate_surface")
            == CRITERION2_DURABLE_CERTIFICATE_SURFACES[slot_id]
            for slot_id in CRITERION2_DURABLE_CERTIFICATE_ACCESSORS
        )
        and all(
            durable_certificate_evidence_by_slot.get(slot_id, {}).get(
                "certificate_surface"
            )
            == CRITERION2_DURABLE_CERTIFICATE_EVIDENCE_SURFACES[slot_id]
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
            == "conformance/proof-review evidence"
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
        "artifact_slot_packages": artifact_slot_packages,
        "artifact_slot_certificate_accessors": artifact_slot_certificate_accessors,
        "artifact_fixture_refs": artifact_fixture_refs,
        "durable_certificate_evidence": durable_certificate_evidence,
        "theorem_links": theorem_links,
        "missing_evidence": sorted(set(missing_evidence)),
    }


def criterion3_proof_substance_status(markdown, manifest_text):
    """Return Criterion-3 proof-payload status without criterion promotion."""
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
    theorem_links = proof_payload.get("theorem_links", [])

    expected_markdown_tokens = [
        "# criterion 3 proof substance",
        "abort_retry_bias",
        "formalized_open_proof_payload",
        "criterion3_proof_payload_formalized",
        "session_id + attempt_id + retry_counter",
        "accepted threshold signatures remain unbiased under the reviewed abort and retry policy",
        "retry_domain_separation_proof_digest",
        "formal_abort_leakage_model_digest",
        "accepted_signature_distribution_proof_digest",
        "adversarial_abort_policy_corpus_digest",
        "sample_size_bucket_rationale_digest",
        "timeout_retry_policy_digest",
        "external_review_digest",
        "required_unclosed",
        "p1_criterion3_proof_payload_package",
        "p1_criterion3_retry_domain_separation_artifact_gate",
        "p1_criterion3_accepted_signature_distribution_artifact_gate",
        "conformance/proof-review evidence",
        "abortbiasevidence",
        "abortretrybiasproofpackage",
        "abortbiasclosurereport",
        "noise lemma g",
        "noise lemma h",
        "fst-l7",
        "fst-l9",
        "partially_met",
        "partially_proven",
        "requires selected-backend proof closure evidence",
        "requires production threshold ml-dsa security evidence",
        "requires cavp/acvts validation evidence",
        "requires fips validation evidence",
        "requires accepted-signature distribution preservation proof",
        "requires a completed fiat-shamir-with-aborts preservation proof",
        "requires a completed abort/retry-bias proof",
    ]
    missing_evidence = [
        token
        for token in expected_markdown_tokens
        if token not in normalized
    ]
    false_claims_pinned = all(
        claim_boundary.get(key) is False for key in CRITERION3_FALSE_CLAIM_KEYS
    )
    artifact_slot_statuses = {
        slot_id: slot_by_id.get(slot_id, {}).get("current_status", "")
        for slot_id in CRITERION3_REQUIRED_ARTIFACT_SLOTS
    }
    artifact_slot_sources = {
        slot_id: slot_by_id.get(slot_id, {}).get("evidence_source", "")
        for slot_id in CRITERION3_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("evidence_source")
    }
    artifact_slot_packages = {
        slot_id: slot_by_id.get(slot_id, {}).get("artifact_package", "")
        for slot_id in CRITERION3_REQUIRED_ARTIFACT_SLOTS
        if slot_by_id.get(slot_id, {}).get("artifact_package")
    }
    artifact_slots_pinned = (
        artifact_slot_statuses == CRITERION3_ARTIFACT_SLOT_STATUSES
        and artifact_slot_sources == CRITERION3_EVIDENCE_SOURCES
        and artifact_slot_packages
        == {
            slot: CRITERION3_ARTIFACT_PACKAGE
            for slot in CRITERION3_REQUIRED_ARTIFACT_SLOTS
        }
        and all(
            slot_by_id.get(slot_id, {}).get("claim_boundary")
            == "conformance/proof-review evidence"
            for slot_id in CRITERION3_REQUIRED_ARTIFACT_SLOTS
        )
    )
    theorem_links_pinned = entries_contain_terms(
        theorem_links,
        CRITERION3_THEOREM_LINKS,
    )
    promotion_anchors_pinned = entries_contain_terms(
        manifest.get("promotion_requires", []),
        [
            "retry transcript domain separation",
            "formal abort leakage model",
            "accepted-signature distribution proof",
            "adversarial abort-policy corpus",
            "sample-size",
            "timeout and retry policy",
            "external cryptographic review",
        ],
    )
    failure_anchors_pinned = entries_contain_terms(
        manifest.get("failure_conditions", []),
        [
            "retry timing",
            "secret-dependent information",
            "accepted-sample evidence",
        ],
    )
    manifest_ok = (
        manifest.get("schema") == CRITERION3_PROOF_SUBSTANCE_SCHEMA
        and manifest.get("criterion_id") == CRITERION3_ID
        and manifest.get("status") == "formalized_open_proof_payload"
        and claim_boundary.get("scope") == "criterion-3 proof payload only"
        and selected_profile.get("name")
        == "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
        and selected_profile.get("feature_gate") == "production-mldsa65-coordinator"
        and selected_profile.get("output_target")
        == "one standard-sized ML-DSA-65 signature if proven"
        and proof_payload.get("retry_domain")
        == "session_id + attempt_id + retry_counter"
        and proof_payload.get("accepted_signature_target")
        == "accepted threshold signatures remain unbiased under the reviewed abort and retry policy"
        and false_claims_pinned
        and artifact_slots_pinned
        and theorem_links_pinned
        and promotion_anchors_pinned
        and failure_anchors_pinned
        and assessment.get("criterion_status") == "partially_met"
        and assessment.get("overall_verdict") == "partially_proven"
        and assessment.get("does_not_change_overall_verdict") is True
        and assessment.get("report_status")
        == "criterion3_proof_payload_formalized"
    )
    formalized = bool(markdown.strip()) and manifest_ok and not missing_evidence
    if not manifest:
        missing_evidence.append(CRITERION3_PROOF_SUBSTANCE_MANIFEST)
    if not markdown.strip():
        missing_evidence.append(CRITERION3_PROOF_SUBSTANCE_DOC)
    if manifest and not false_claims_pinned:
        missing_evidence.append("claim_boundary false claims")
    if manifest and not artifact_slots_pinned:
        missing_evidence.append("required_artifact_slots")
    if manifest and not theorem_links_pinned:
        missing_evidence.append("theorem_links")

    return {
        "status": (
            "criterion3_proof_payload_formalized"
            if formalized
            else "missing_or_incomplete"
        ),
        "document_path": CRITERION3_PROOF_SUBSTANCE_DOC,
        "manifest_path": CRITERION3_PROOF_SUBSTANCE_MANIFEST,
        "criterion_id": manifest.get("criterion_id", ""),
        "payload_status": manifest.get("status", ""),
        "scope": claim_boundary.get("scope", ""),
        "selected_profile": selected_profile.get("name", ""),
        "output_target": selected_profile.get("output_target", ""),
        "required_artifact_slots": CRITERION3_REQUIRED_ARTIFACT_SLOTS,
        "artifact_slot_statuses": artifact_slot_statuses,
        "artifact_slot_sources": artifact_slot_sources,
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
    """Return the evidence item required for backend selection promotion."""
    return (
        "Selected backend direction requires proof artifacts, backend "
        "implementation evidence, and production approval for release "
        "promotion."
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
    backend_capture_runner = read_optional("scripts/run_backend_emission_capture.py")
    backend_capture_runner_test = read_optional(
        "script_tests/test_run_backend_emission_capture.py"
    )
    backend_emission_request_builder = read_optional(
        "scripts/build_backend_emission_request.py"
    )
    backend_emission_request_builder_test = read_optional(
        "script_tests/test_build_backend_emission_request.py"
    )
    backend_emission_request_manifest = read_optional(
        "artifacts/backend-emission-request/latest/manifest.json"
    )
    backend_emission_request_json = read_optional(
        "artifacts/backend-emission-request/latest/request.json"
    )
    backend_emission_capture_file_intake = read_optional(
        "scripts/stage_external_backend_emission_capture.py"
    )
    backend_emission_capture_file_intake_test = read_optional(
        "script_tests/test_stage_external_backend_emission_capture.py"
    )
    nonce_producer_capture_runner = read_optional(
        "scripts/run_nonce_producer_capture.py"
    )
    nonce_producer_capture_runner_test = read_optional(
        "script_tests/test_run_nonce_producer_capture.py"
    )
    nonce_producer_handoff_replay = read_optional(
        "scripts/run_nonce_producer_handoff_replay.py"
    )
    nonce_producer_handoff_replay_test = read_optional(
        "script_tests/test_run_nonce_producer_handoff_replay.py"
    )
    nonce_producer_backend_readiness = read_optional(
        "scripts/check_nonce_producer_backend_readiness.py"
    )
    nonce_producer_backend_readiness_test = read_optional(
        "script_tests/test_check_nonce_producer_backend_readiness.py"
    )
    nonce_producer_backend_readiness_manifest = read_optional(
        "artifacts/nonce-producer-backend-readiness/latest/manifest.json"
    )
    nonce_producer_capture_attempt = read_optional(
        "scripts/run_admissible_nonce_producer_capture_attempt.py"
    )
    nonce_producer_capture_attempt_test = read_optional(
        "script_tests/test_run_admissible_nonce_producer_capture_attempt.py"
    )
    nonce_producer_capture_attempt_manifest = read_optional(
        "artifacts/nonce-producer-capture-attempt/latest/manifest.json"
    )
    nonce_producer_actual_external_gate = read_optional(
        "scripts/verify_actual_nonce_producer_capture.py"
    )
    nonce_producer_actual_external_gate_test = read_optional(
        "script_tests/test_verify_actual_nonce_producer_capture.py"
    )
    nonce_producer_actual_external_gate_manifest = read_optional(
        "artifacts/nonce-producer-actual-external-gate/latest/manifest.json"
    )
    nonce_producer_external_capture_file_intake = read_optional(
        "scripts/stage_external_nonce_producer_capture.py"
    )
    nonce_producer_external_capture_file_intake_test = read_optional(
        "script_tests/test_stage_external_nonce_producer_capture.py"
    )
    nonce_producer_request_builder = read_optional(
        "scripts/build_nonce_producer_request.py"
    )
    nonce_producer_request_builder_test = read_optional(
        "script_tests/test_build_nonce_producer_request.py"
    )
    hazmat_threshold_backend_capture_adapter = read_optional(
        "scripts/run_hazmat_threshold_backend_capture.py"
    )
    hazmat_threshold_backend_capture_adapter_test = read_optional(
        "script_tests/test_run_hazmat_threshold_backend_capture.py"
    )
    hazmat_rejection_equivalence_batch = read_optional(
        "scripts/run_hazmat_rejection_equivalence_batch.py"
    )
    hazmat_rejection_equivalence_batch_test = read_optional(
        "script_tests/test_run_hazmat_rejection_equivalence_batch.py"
    )
    p1_external_backend_closure_candidate_builder = read_optional(
        "scripts/build_p1_external_backend_cryptographic_closure_candidate.py"
    )
    p1_external_backend_closure_candidate_builder_test = read_optional(
        "script_tests/test_build_p1_external_backend_cryptographic_closure_candidate.py"
    )
    p1_external_backend_closure_candidate_manifest = read_optional(
        "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json"
    )
    p1_external_backend_evidence_attempt_runner = read_optional(
        "scripts/run_p1_external_backend_evidence_attempt.py"
    )
    p1_external_backend_evidence_attempt_test = read_optional(
        "script_tests/test_run_p1_external_backend_evidence_attempt.py"
    )
    p1_external_backend_evidence_attempt_manifest = read_optional(
        "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json"
    )
    real_threshold_backend_capture_schema_fixture = read_optional(
        "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
    )
    validator_10000_gate_doc = read_optional(
        "docs/cryptography/validator-10000-standard-verifier-gate.md"
    )
    validator_10000_gate_test = read_optional(
        "tests/validator_10000_standard_verifier_gate.rs"
    )
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
    p1_nonce_producer_selection = p1_nonce_producer_selection_status(
        read_optional(P1_NONCE_PRODUCER_SELECTION_DOC),
        read_optional(P1_NONCE_PRODUCER_SELECTION_MANIFEST),
    )
    criterion1_proof_substance = criterion1_proof_substance_status(
        read_optional(CRITERION1_PROOF_SUBSTANCE_DOC),
        read_optional(CRITERION1_PROOF_SUBSTANCE_MANIFEST),
    )
    criterion2_proof_substance = criterion2_proof_substance_status(
        read_optional(CRITERION2_PROOF_SUBSTANCE_DOC),
        read_optional(CRITERION2_PROOF_SUBSTANCE_MANIFEST),
    )
    criterion3_proof_substance = criterion3_proof_substance_status(
        read_optional(CRITERION3_PROOF_SUBSTANCE_DOC),
        read_optional(CRITERION3_PROOF_SUBSTANCE_MANIFEST),
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
            "DistributedNonceProducer",
            "threshold_output_certificate_artifact",
            "real_recomputation_evidence_artifact",
            "distributed_nonce_producer_artifact",
            "threshold_output_certificate_artifact_digest",
            "real_recomputation_evidence_artifact_digest",
            "distributed_nonce_producer_artifact_digest",
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
    p1_distributed_nonce_producer_artifact_gate = (
        p1_criterion2_proof_slot_artifact_gates
        and has_public_enum(
            rejection_equivalence_source,
            "P1DistributedNonceProducerEvidence",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1DistributedNonceProducerClaimBoundary",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1DistributedNonceProducerArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "Mldsa65DistributedNonceProducerArtifact",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1DistributedNonceProducerCapture",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1OwnedMldsa65DistributedNonceProducerArtifact",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1DistributedNonceProducerArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1DistributedNonceProducerArtifactAssessment",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_distributed_nonce_producer_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_distributed_nonce_producer_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_distributed_nonce_producer_artifact_package_from_backend_output",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_distributed_nonce_producer_artifact_package_from_capture",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_distributed_nonce_producer_artifact_digest",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SCHEMA",
            "P1_DISTRIBUTED_NONCE_PRODUCER_REQUEST_SCHEMA",
            "P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_EXTERNAL_EVIDENCE",
            "P1DistributedNonceProducerCaptureRequestBinding",
            "P1DistributedNonceProducerCaptureExpectedDigests",
            "request_sha256",
            "HazmatPrfOutputOracle",
            "CentralizedExpandedSecretKeyHelper",
            "FixtureHarness",
            "StandardProviderSingleKey",
            "ReviewedP1ShamirNonceDkgTee",
            "source_reference_digest",
            "backend_implementation_digest",
            "coordinator_attestation_digest",
            "shamir_nonce_dkg_transcript_digest",
            "pairwise_mask_seed_commitment_digest",
            "nonce_share_commitment_digest",
            "abort_accountability_digest",
            "claims_theorem_closure",
            "claims_standard_verifier_compatibility_complete",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "distributed",
            "nonce",
            "producer",
            "accepts",
            "reviewed",
            "shamir",
            "nonce",
            "dkg",
            "tee",
            "evidence",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "distributed",
            "nonce",
            "producer",
            "rejects",
            "hazmat",
            "prf",
            "output",
            "oracle",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "distributed",
            "nonce",
            "producer",
            "rejects",
            "centralized",
            "expanded",
            "secret",
            "key",
            "helper",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "distributed",
            "nonce",
            "producer",
            "rejects",
            "standard",
            "provider",
            "single",
            "key",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "distributed",
            "nonce",
            "producer",
            "capture",
            "json",
            "feeds",
            "artifact",
            "gate",
            "actual",
            "evidence",
        )
    )
    p1_distributed_nonce_producer_request_gate = (
        p1_distributed_nonce_producer_artifact_gate
        and all(
            token in nonce_producer_request_builder
            for token in [
                "REQUEST_SCHEMA",
                "lattice-aggregation:p1-distributed-nonce-producer-request:v1",
                "CAPTURE_SCHEMA",
                "lattice-aggregation:p1-distributed-nonce-producer-capture:v1",
                "EXTERNAL_PRODUCER_EVIDENCE",
                "p1_shamir_nonce_dkg_tee_external_capture",
                "REQUEST_STATUS",
                "evidence_present_unclosed",
                "SELECTED_PROFILE",
                "FORBIDDEN_REQUEST_NAME_TOKENS",
                "build_request",
                "write_artifacts",
                "validate_digest",
                "required_capture",
                "forbidden_capture_sources",
                "shamir_nonce_dkg_transcript",
            ]
        )
        and all(
            token in nonce_producer_request_builder_test
            for token in [
                "test_build_request_manifest_writes_external_nonce_producer_challenge_contract",
                "test_build_request_manifest_rejects_simulation_names_and_bad_digests",
                "lattice-aggregation:p1-distributed-nonce-producer-request:v1",
                "p1_shamir_nonce_dkg_tee_external_capture",
                "evidence_present_unclosed",
            ]
        )
    )
    p1_distributed_nonce_producer_capture_runner_gate = (
        p1_distributed_nonce_producer_request_gate
        and all(
            token in nonce_producer_capture_runner
            for token in [
                "CAPTURE_SCHEMA",
                "REQUEST_SCHEMA",
                "EXTERNAL_PRODUCER_EVIDENCE",
                "RUNNER_STATUS",
                "FORBIDDEN_BACKEND_COMMAND_TOKENS",
                "CAPTURE_SOURCE_PROFILE_EXTERNAL",
                "CAPTURE_SOURCE_PROFILE_QUARANTINED_REPLAY",
                "QUARANTINED_LOCAL_REPLAY_TOKENS",
                "validate_backend_command",
                "validate_capture_source_profile",
                "load_request",
                "validate_request_binding",
                "validate_capture_matches_request",
                "validate_no_unknown_fields",
                "validate_digest_object",
                "validate_capture_bytes",
                "parse_capture_json",
                "build_report",
                "write_artifacts",
                "actual external nonce-producer evidence",
                "request digest mismatch",
                "missing {label} digest",
                "quarantined local replay",
                "hazmat",
                "centralized",
                "localnet",
            ]
        )
        and all(
            token in nonce_producer_capture_runner_test
            for token in [
                "test_build_report_invokes_nonce_producer_capture_runner_and_writes_importable_capture_json",
                "test_build_report_rejects_capture_that_omits_or_stales_request_binding",
                "test_build_report_rejects_hazmat_localnet_or_fixture_sources",
                "test_build_report_rejects_local_replay_emitter_as_external_capture",
                "test_build_report_can_mark_local_replay_emitter_as_quarantined",
                "quarantined_local_schema_replay",
                "test_build_report_rejects_non_importable_capture_shape_before_artifact_write",
                "request_sha256",
                "request digest mismatch",
                "hazmat-centralized-prf",
                "fixture_harness",
            ]
        )
    )
    p1_nonce_producer_external_origin_guard = (
        p1_distributed_nonce_producer_capture_runner_gate
        and all(
            token in nonce_producer_capture_runner
            for token in [
                "COMMAND_ORIGIN_EXTERNAL",
                "COMMAND_ORIGIN_REPO_LOCAL",
                "backend_command_origin",
                "backend_command_path_candidates",
                "repo-local backend command",
                "outside_repo_executable_or_script",
                "repo_local_executable_or_script",
            ]
        )
        and all(
            token in nonce_producer_capture_runner_test
            for token in [
                "test_build_report_rejects_repo_local_wrapper_as_actual_external_backend",
                "test_build_report_records_outside_repo_command_origin_for_external_backend",
                "backend_command_origin",
                "repo-local backend command",
                "outside_repo_executable_or_script",
            ]
        )
    )
    p1_nonce_producer_backend_readiness_gate = (
        p1_distributed_nonce_producer_capture_runner_gate
        and all(
            token in nonce_producer_backend_readiness
            for token in [
                "READINESS_SCHEMA",
                "lattice-aggregation:p1-nonce-producer-backend-readiness:v1",
                "ENV_BACKEND_CRATE",
                "LATTICE_NONCE_PRODUCER_BACKEND_CRATE",
                "detect_capabilities",
                "detected_blockers",
                "quarantine_record",
                "admissible_for_p1_nonce_handoff",
                "backend_detected_not_admissible",
                "backend_candidate_admissible_pending_capture",
                "centralized_nonce_prf_oracle",
                "simulated_default_feature",
                "hazmat_feature",
                "quarantined_sources",
                "safe_replacement_requirements",
                "reviewed_external_capture_contract",
            ]
        )
        and all(
            token in nonce_producer_handoff_replay
            for token in [
                "READINESS_SCHEMA",
                "validate_backend_readiness",
                "backend_readiness",
                "backend_readiness_report",
                "reuse_request",
                "allow_quarantined_replay",
                "handoff_source_profile",
                "requires admissible backend readiness",
                "backend readiness is not admissible",
                "backend_candidate_admissible_pending_capture",
            ]
        )
        and all(
            token in nonce_producer_backend_readiness_test
            for token in [
                "test_readiness_report_blocks_hazmat_backend_but_records_nonce_capabilities",
                "test_readiness_report_marks_clean_reviewed_candidate_as_capture_admissible",
                "test_readiness_report_rejects_missing_backend_crate",
                "backend_detected_not_admissible",
                "centralized nonce PRF oracle",
                "simulated default feature",
                "hazmat feature",
                "quarantined_sources",
            ]
        )
        and all(
            token in nonce_producer_handoff_replay_test
            for token in [
                "test_handoff_replay_requires_readiness_for_explicit_backend_command",
                "test_handoff_replay_rejects_blocked_backend_readiness",
                "test_handoff_replay_accepts_admissible_readiness_bound_to_reused_request",
                "test_handoff_replay_rejects_quarantined_local_replay_as_external_backend",
                "quarantined_local_schema_replay",
                "admissible_external_backend_capture",
                "requires admissible backend readiness",
                "backend readiness is not admissible",
            ]
        )
        and all(
            token in nonce_producer_backend_readiness_manifest
            for token in [
                "lattice-aggregation:p1-nonce-producer-backend-readiness:v1",
                "backend_candidate_admissible_pending_capture",
                "lattice-aggregation",
                "distributed_nonce_prf_output_share_interface",
                "admissible_for_p1_nonce_handoff",
                "\"detected_blockers\": []",
                "\"admissible_for_p1_nonce_handoff\": true",
                "source_tree_sha256",
            ]
        )
    )
    p1_nonce_producer_capture_attempt_gate = (
        p1_nonce_producer_backend_readiness_gate
        and all(
            token in nonce_producer_capture_attempt
            for token in [
                "ATTEMPT_SCHEMA",
                "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1",
                "ATTEMPT_STATUS_BLOCKED",
                "backend_readiness_blocked",
                "ATTEMPT_STATUS_PROMOTED",
                "capture_promoted",
                "ATTEMPT_STATUS_EXECUTION_FAILED",
                "capture_execution_failed",
                "ATTEMPT_STATUS_VALIDATION_FAILED",
                "capture_validation_failed",
                "REQUEST_PLACEHOLDER",
                "{request}",
                "substitute_request_placeholder",
                "backend_command_executed",
                "build_attempt",
                "reuse_request=True",
            ]
        )
        and all(
            token in nonce_producer_capture_attempt_test
            for token in [
                "test_attempt_blocks_hazmat_style_backend_before_capture_command_runs",
                "test_attempt_promotes_capture_only_after_admissible_readiness",
                "test_attempt_requires_request_placeholder_in_backend_command",
                "test_attempt_records_execution_failure_after_admissible_readiness",
                "test_attempt_records_validation_failure_after_admissible_readiness",
                "backend_readiness_blocked",
                "capture_promoted",
                "capture_execution_failed",
                "capture_validation_failed",
                "backend_command_executed",
            ]
        )
        and all(
            token in nonce_producer_capture_attempt_manifest
            for token in [
                "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1",
                "capture_promoted",
                "backend_command_executed",
                "admissible_for_p1_nonce_handoff",
                "\"detected_blockers\": []",
                "repo_reference_cli_capture",
                "\"quarantined\": true",
                "handoff/request/request.json",
                "lattice-aggregation:p1-nonce-producer-backend-readiness:v1",
            ]
        )
    )
    p1_actual_external_nonce_producer_gate = (
        p1_nonce_producer_capture_attempt_gate
        and all(
            token in nonce_producer_actual_external_gate
            for token in [
                "GATE_SCHEMA",
                "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
                "EXPECTED_SOURCE_PROFILE",
                "admissible_external_backend_capture",
                "actual_external_capture_ready",
                "actual_external_capture_missing",
                "repo_reference_cli_capture",
                "source_profile_blockers",
                "build_report",
                "write_artifacts",
                "--strict",
            ]
        )
        and all(
            token in nonce_producer_actual_external_gate_test
            for token in [
                "test_reference_cli_promoted_capture_is_blocked_from_actual_external_slot",
                "test_non_quarantined_external_capture_satisfies_actual_external_slot",
                "test_strict_mode_exits_nonzero_when_actual_external_capture_is_missing",
                "repo_reference_cli_capture",
                "admissible_external_backend_capture",
                "actual_external_capture_missing",
                "actual_external_capture_ready",
            ]
        )
        and all(
            token in nonce_producer_actual_external_gate_manifest
            for token in [
                "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
                "actual_external_capture_missing",
                "\"actual_external_capture_ready\": false",
                "repo_reference_cli_capture",
                "admissible_external_backend_capture",
                "requires actual backend evidence",
            ]
        )
    )
    p1_external_nonce_producer_capture_file_intake = (
        p1_actual_external_nonce_producer_gate
        and all(
            token in nonce_producer_external_capture_file_intake
            for token in [
                "ATTEMPT_SCHEMA",
                "HANDOFF_SCHEMA",
                "CAPTURE_FILE_ORIGIN_EXTERNAL",
                "EXTERNAL_CAPTURE_REVIEW_SCHEMA",
                "REVIEW_FILE_ORIGIN_EXTERNAL",
                "outside_repo_capture_file",
                "repo_local_capture_file",
                "outside_repo_review_manifest",
                "reviewed_external_capture_ready",
                "preexisting_external_capture_file",
                "admissible_external_backend_capture",
                "require_outside_repo_capture_file",
                "require_outside_repo_review_manifest",
                "validate_readiness",
                "validate_external_review_manifest",
                "validate_capture_matches_request",
                "REQUIRED_REVIEW_CHECKS",
                "build_intake",
                "write_artifacts",
                "requires Criterion 2 proof review",
            ]
        )
        and all(
            token in nonce_producer_external_capture_file_intake_test
            for token in [
                "test_outside_repo_capture_file_stages_non_quarantined_attempt_for_actual_gate",
                "test_repo_local_capture_file_is_rejected_before_promotion",
                "test_blocked_or_stale_readiness_is_rejected_before_promotion",
                "test_stale_capture_request_digest_is_rejected_before_promotion",
                "test_missing_review_manifest_is_rejected_before_promotion",
                "test_mismatched_review_manifest_is_rejected_before_promotion",
                "actual_external_capture_ready",
                "outside_repo_capture_file",
                "external review manifest",
                "external review check failed",
                "repo-local capture file",
                "request digest mismatch",
            ]
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
    p1_real_threshold_backend_output_gate = (
        p1_standard_verifier_compatibility_artifact_gate
        and has_public_enum(
            rejection_equivalence_source,
            "P1RealThresholdVerifierClosureBackendEvidence",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1RealThresholdVerifierClosureClaimBoundary",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdBackendEmissionArtifactPackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdBackendEmissionOutput",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdBackendEmissionCapture",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1OwnedRealThresholdBackendEmissionOutput",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdBackendEmissionArtifactCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1RealThresholdBackendEmissionArtifactAssessment",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdVerifierClosurePackage",
        )
        and has_public_struct(
            rejection_equivalence_source,
            "P1RealThresholdVerifierClosureCertificate",
        )
        and has_public_enum(
            rejection_equivalence_source,
            "P1RealThresholdVerifierClosureAssessment",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_real_threshold_backend_emission_artifact",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_real_threshold_backend_emission_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_verified_real_threshold_backend_emission_artifact_package",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_real_threshold_backend_emission_evidence_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_real_threshold_backend_emission_artifact_digest",
        )
        and has_public_function(
            rejection_equivalence_source,
            "assess_p1_real_threshold_verifier_closure_contract",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "SimulatedDeterministic",
            "StandardProviderSingleKey",
            "FixtureHarness",
            "RealThresholdMldsa",
            "validator_count",
            "threshold",
            "aggregate_signature_len",
            "backend_evidence_digest",
            "backend_source_package_digest",
            "backend_implementation_digest",
            "backend_transcript_digest",
            "artifact_digest",
            "backend_source_package",
            "backend_implementation",
            "backend_transcript",
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA",
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE",
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA_FIXTURE_EVIDENCE",
            "decode_json",
            "to_backend_output_material",
            "validate_predecessors",
            "validate_expected_digests",
            "aggregate_signature",
            "mutated_message_rejected",
            "mutated_public_key_rejected",
            "mutated_signature_rejected",
            "to_verifier_closure_package",
            "claims_real_threshold_backend_implemented",
            "mutation_rejection_corpus_complete",
            "claims_production_threshold_mldsa_security",
            "claims_cavp_acvts_validation",
            "claims_fips_validation",
            "claims_completed_cryptographic_proof",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "ingestion",
            "accepts",
            "reviewed",
            "external",
            "threshold",
            "output",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "output",
            "material",
            "derives",
            "artifact",
            "ready",
            "package",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "output",
            "material",
            "rejects",
            "tuple",
            "digest",
            "mismatch",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "verified",
            "real",
            "threshold",
            "backend",
            "output",
            "material",
            "requires",
            "standard",
            "verifier",
            "acceptance",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "schema",
            "fixture",
            "parses",
            "remains",
            "blocked",
            "actual",
            "capture",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "feeds",
            "verified",
            "ingestion",
            "gate",
            "actual",
            "evidence",
            "present",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "requires",
            "standard",
            "verifier",
            "acceptance",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "stale",
            "predecessor",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "expected",
            "artifact",
            "digest",
            "drift",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "missing",
            "predecessor",
            "digests",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "missing",
            "expected",
            "digests",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "malformed",
            "signature",
            "length",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "unsupported",
            "byte",
            "encoding",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "ingestion",
            "blocks",
            "simulated",
            "backend",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "ingestion",
            "rejects",
            "standard",
            "provider",
            "single",
            "key",
            "output",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "ingestion",
            "rejects",
            "stale",
            "threshold",
            "certificate",
            "digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "ingestion",
            "rejects",
            "unreviewed",
            "external",
            "backend",
            "evidence",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "artifact",
            "fixture",
            "parses",
            "remains",
            "blocked",
            "actual",
            "backend",
            "evidence",
            "replaces",
            "it",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "standard",
            "provider",
            "single",
            "key",
            "emission",
            "fixture",
            "verifies",
            "real",
            "mldsa",
            "cannot",
            "replace",
            "threshold",
            "backend",
            "evidence",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "emission",
            "artifact",
            "fixture",
            "package",
            "digest",
            "fails",
            "loudly",
            "drift",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "verifier",
            "closure",
            "contract",
            "blocks",
            "simulated",
            "backend",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "verifier",
            "closure",
            "contract",
            "rejects",
            "standard",
            "provider",
            "single",
            "key",
            "output",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "verifier",
            "closure",
            "contract",
            "accepts",
            "reviewed",
            "verifier",
            "tuple",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "verifier",
            "closure",
            "contract",
            "rejects",
            "missing",
            "mutation",
            "corpus",
        )
        and "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
        in real_threshold_backend_capture_schema_fixture
        and "not actual real threshold backend emission evidence"
        in real_threshold_backend_capture_schema_fixture
        and "real threshold backend emission ingestion artifact"
        in validator_10000_gate_doc
        and "canonical backend-emission capture schema/importer"
        in validator_10000_gate_doc
        and "threshold verifier closure contract" in validator_10000_gate_doc
        and "real threshold ML-DSA acceptance contract" in validator_10000_gate_doc
        and "not ordinary single-key standard-provider output"
        in validator_10000_gate_doc
        and "does not claim production threshold ML-DSA security"
        in validator_10000_gate_doc
    )
    p1_real_threshold_backend_actual_capture_runner_gate = (
        p1_real_threshold_backend_output_gate
        and has_public_function(
            rejection_equivalence_source,
            "derive_p1_verified_real_threshold_backend_emission_capture",
        )
        and has_rust_tokens(
            rejection_equivalence_source,
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_ACTUAL_CAPTURE_RUNNER_GATE",
            "to_canonical_json",
            "is_artifact_ready",
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE",
            "P1RealThresholdBackendEmissionCaptureBytes::hex",
            "package.backend_evidence",
            "derive_p1_real_threshold_backend_source_package_digest",
            "derive_p1_real_threshold_backend_implementation_digest",
            "derive_p1_real_threshold_backend_transcript_digest",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "runner",
            "emits",
            "canonical",
            "importable",
            "capture",
        )
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "runner",
            "rejects",
            "unready",
            "package",
            "before",
            "external",
            "capture",
        )
        and all(
            token in backend_capture_runner
            for token in [
                "CAPTURE_SCHEMA",
                "EXTERNAL_BACKEND_EVIDENCE",
                "SELECTED_PROFILE",
                "RUNNER_STATUS",
                "FORBIDDEN_BACKEND_COMMAND_TOKENS",
                "validate_backend_command",
                "validate_no_unknown_fields",
                "validate_digest_object",
                "validate_hex_field",
                "validate_capture_bytes",
                "localnet",
                "real_threshold_mldsa_external_capture",
                "evidence_present_unclosed",
                "parse_capture_json",
                "build_report",
                "write_artifacts",
                "canonical capture JSON",
                "actual external real-threshold evidence",
                "forbidden backend command",
                "missing {label} digest",
                "public_key_hex",
            ]
        )
        and all(
            token in backend_capture_runner_test
            for token in [
                "test_build_report_invokes_backend_capture_runner_and_writes_importable_capture_json",
                "test_build_report_rejects_deterministic_simulation_or_localnet_capture_source",
                "test_build_report_rejects_forged_external_json_from_localnet_or_simulation_command",
                "test_build_report_rejects_non_importable_capture_shape_before_artifact_write",
                "validator_localnet",
                "run_simulation_benchmarks",
                "real_threshold_mldsa_capture_schema_fixture",
            ]
        )
    )
    p1_real_threshold_backend_emission_request_gate = (
        p1_real_threshold_backend_actual_capture_runner_gate
        and all(
            token in backend_emission_request_builder
            for token in [
                "REQUEST_SCHEMA",
                "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
                "CAPTURE_SCHEMA",
                "EXTERNAL_BACKEND_EVIDENCE",
                "REQUEST_STATUS",
                "evidence_present_unclosed",
                "SELECTED_PROFILE",
                "FORBIDDEN_REQUEST_NAME_TOKENS",
                "build_request",
                "write_artifacts",
                "validate_digest",
                "validate_message_hex",
                "validator_count",
                "threshold",
                "aggregate_signature_len",
                "required_capture",
                "forbidden_capture_sources",
            ]
        )
        and all(
            token in backend_emission_request_builder_test
            for token in [
                "test_build_request_manifest_writes_external_backend_challenge_contract",
                "test_build_request_manifest_rejects_simulation_names_bad_digests_and_bad_message_hex",
                "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
                "real_threshold_mldsa_external_capture",
                "evidence_present_unclosed",
            ]
        )
        and all(
            token in backend_emission_request_manifest
            for token in [
                "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
                "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
                "\"request_status\": \"evidence_present_unclosed\"",
                "\"request_sha256\"",
            ]
        )
        and all(
            token in backend_emission_request_json
            for token in [
                "\"schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\"",
                "\"name\": \"p1-real-threshold-backend-emission-request-001\"",
                "\"validator_count\": 10000",
                "\"threshold\": 6667",
                "\"aggregate_signature_len\": 3309",
                "\"selected_profile_binding_digest_hex\"",
                "\"threshold_output_certificate_digest_hex\"",
                "\"standard_verifier_compatibility_artifact_digest_hex\"",
                "\"backend_evidence\": \"real_threshold_mldsa_external_capture\"",
                "\"mutated_message_rejected\": true",
                "\"mutated_public_key_rejected\": true",
                "\"mutated_signature_rejected\": true",
            ]
        )
    )
    p1_real_threshold_backend_request_capture_binding_gate = (
        p1_real_threshold_backend_emission_request_gate
        and has_rust_tokens(
            rejection_equivalence_source,
            "P1_REAL_THRESHOLD_BACKEND_EMISSION_REQUEST_SCHEMA",
            "P1RealThresholdBackendEmissionCaptureRequestBinding",
            "request_sha256",
            "validate_request_binding",
        )
        and "P1 real-threshold backend emission capture requires request digest binding"
        in rejection_equivalence_source
        and has_acceptance_test_function(
            rejection_equivalence_test,
            "real",
            "threshold",
            "backend",
            "capture",
            "json",
            "rejects",
            "missing",
            "request",
            "binding",
        )
        and all(
            token in backend_capture_runner
            for token in [
                "REQUEST_SCHEMA",
                "load_request",
                "validate_request_binding",
                "validate_capture_matches_request",
                "request digest mismatch",
                "request_sha256",
            ]
        )
        and all(
            token in backend_capture_runner_test
            for token in [
                "test_build_report_rejects_capture_that_omits_or_stales_request_binding",
                "request_sha256",
                "request digest mismatch",
                "request binding",
            ]
        )
        and "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
        in real_threshold_backend_capture_schema_fixture
        and "request_sha256" in real_threshold_backend_capture_schema_fixture
    )
    p1_real_threshold_backend_capture_file_intake_gate = (
        p1_real_threshold_backend_request_capture_binding_gate
        and all(
            token in backend_emission_capture_file_intake
            for token in [
                "CAPTURE_FILE_ORIGIN_EXTERNAL",
                "outside_repo_capture_file",
                "REVIEW_FILE_ORIGIN_EXTERNAL",
                "outside_repo_review_manifest",
                "BACKEND_EXECUTION_MODE",
                "preexisting_external_capture_file",
                "EXTERNAL_CAPTURE_REVIEW_SCHEMA",
                "lattice-aggregation:p1-external-backend-emission-capture-review:v1",
                "EXTERNAL_CAPTURE_REVIEW_STATUS",
                "reviewed_external_backend_emission_capture_ready",
                "validate_external_review_manifest",
                "standard_verifier_acceptance_reviewed",
                "no_single_key_standard_provider_output",
                "repo-local capture file",
                "validate_capture_matches_request",
                "write_artifacts",
                "requires Criterion 2 proof review",
            ]
        )
        and all(
            token in backend_emission_capture_file_intake_test
            for token in [
                "test_outside_repo_capture_file_writes_batch8_consumable_backend_capture",
                "test_repo_local_capture_file_is_rejected_before_artifact_write",
                "test_missing_or_failed_review_manifest_is_rejected_before_artifact_write",
                "test_stale_capture_request_digest_is_rejected_before_artifact_write",
                "lattice-aggregation:p1-external-backend-emission-capture-review:v1",
                "reviewed_external_backend_emission_capture_ready",
                "preexisting_external_capture_file",
                "outside_repo_capture_file",
                "outside_repo_review_manifest",
                "close_candidate",
            ]
        )
    )
    p1_hazmat_threshold_backend_capture_adapter_gate = (
        p1_real_threshold_backend_request_capture_binding_gate
        and all(
            token in hazmat_threshold_backend_capture_adapter
            for token in [
                "RUST_EMITTER_SOURCE",
                "write_emitter_project",
                "run_capture",
                "validate_crate_path",
                "LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE",
                "--backend-crate",
                "dytallix-pq-threshold raw-real-mldsa",
                "backend_external_pure_verifier_accepts",
                "repo_pr69_hazmat_provider_accepts",
                "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
                "real_threshold_mldsa_external_capture",
                "mutated_message_rejected",
                "mutated_public_key_rejected",
                "mutated_signature_rejected",
                "10_000",
                "6_667",
            ]
        )
        and all(
            token in hazmat_threshold_backend_capture_adapter_test
            for token in [
                "test_build_emitter_project_requires_explicit_backend_crate_and_repo_root",
                "test_run_capture_invokes_generated_release_emitter_and_returns_stdout",
                "test_run_capture_rejects_missing_or_invalid_backend_crate",
                "backend_external_pure_verifier_accepts",
                "repo_pr69_hazmat_provider_accepts",
                "Lattice Aggregation Current",
            ]
        )
    )
    p1_hazmat_rejection_predicate_transcript_gate = (
        p1_hazmat_threshold_backend_capture_adapter_gate
        and all(
            token in hazmat_threshold_backend_capture_adapter
            for token in [
                "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met",
                "attempt_count",
                "retry_count",
                "per-attempt-bound-predicates",
                "rejection_predicate_fields_available",
                "attempts",
                "mask_seed_digest_hex",
                "challenge_digest_hex",
                "z_bound_result",
                "r0_bound_result",
                "ct0_bound_result",
                "hint_bound_result",
                "accepted_or_rejected",
            ]
        )
        and all(
            token in hazmat_threshold_backend_capture_adapter_test
            for token in [
                "per-attempt-bound-predicates",
                "rejection_predicate_fields_available",
                "accepted_or_rejected",
            ]
        )
    )
    p1_hazmat_rejection_equivalence_batch_gate = (
        p1_hazmat_rejection_predicate_transcript_gate
        and all(
            token in hazmat_rejection_equivalence_batch
            for token in [
                "derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key",
                "derive_mldsa65_centralized_domain_masking_contribution_from_share",
                "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key",
                "derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share",
                "split_mldsa65_distributed_nonce_prf_output",
                "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met",
                "lattice-aggregation:p1-rejection-equivalence-batch:v1",
                "mldsa65-centralized-vs-threshold-rejection-batch",
                "centralized-rho-double-prime-kappa",
                "distributed-nonce-prf-output-shares",
                "aligned_mask_domain",
                "distributed_nonce_prf_domain",
                "mask_domain",
                "threshold_attempts",
                "centralized_attempts",
                "predicate_mismatches",
                "challenge_digest_matches",
                "accepted_or_rejected_matches",
                "close_candidate",
                "claims_rejection_distribution_preservation",
                "claims_theorem_closure",
            ]
        )
        and all(
            token in hazmat_rejection_equivalence_batch_test
            for token in [
                "test_build_emitter_project_pins_centralized_threshold_comparator_surface",
                "test_run_batch_invokes_generated_release_emitter_and_returns_stdout",
                "mldsa65-centralized-vs-threshold-rejection-batch",
                "centralized-rho-double-prime-kappa",
                "distributed-nonce-prf-output-shares",
                "aligned_mask_domain",
                "distributed_nonce_prf_domain",
                "threshold_attempts",
                "centralized_attempts",
                "predicate_mismatches",
                "close_candidate",
            ]
        )
    )
    p1_external_backend_cryptographic_closure_candidate_gate = (
        p1_actual_external_nonce_producer_gate
        and p1_real_threshold_backend_request_capture_binding_gate
        and p1_hazmat_rejection_equivalence_batch_gate
        and all(
            token in p1_external_backend_closure_candidate_builder
            for token in [
                "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1",
                "p1-external-backend-cryptographic-closure-candidate-v1",
                "actual_external_capture_ready",
                "admissible_external_backend_capture",
                "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
                "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
                "real_threshold_mldsa_external_capture",
                "lattice-aggregation:p1-rejection-equivalence-batch:v1",
                "distributed-nonce-prf-output-shares",
                "predicate_mismatch_count",
                "challenge_digest_matches",
                "accepted_or_rejected_matches",
                "standard_verifier_accepts_threshold_signature",
                "repo_provider_accepts_threshold_signature",
                "close_candidate",
                "claims_theorem_closure",
                "claims_rejection_distribution_preservation",
                "evidence_present_unclosed",
                "pending theorem-closure review",
            ]
        )
        and all(
            token in p1_external_backend_closure_candidate_builder_test
            for token in [
                "test_missing_inputs_build_blocked_nonclosure_candidate",
                "test_complete_evidence_bundle_computes_close_candidate_without_claiming_closure",
                "test_distribution_comparison_must_also_be_close_candidate",
                "actual external nonce capture readiness required",
                "rejection-distribution comparison requires close-candidate evidence",
                "claims_theorem_closure",
                "claims_rejection_distribution_preservation",
            ]
        )
        and all(
            token in p1_external_backend_closure_candidate_manifest
            for token in [
                "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1",
                "p1-external-backend-cryptographic-closure-candidate-v1",
                "\"status\": \"evidence_present_unclosed\"",
                "\"close_candidate\": false",
                "\"claims_theorem_closure\": false",
                "\"claims_rejection_distribution_preservation\": false",
                "\"claims_selected_backend_proof_closure\": false",
                "actual external nonce capture readiness required",
                "real threshold backend emission capture is missing",
            ]
        )
    )
    p1_external_backend_evidence_attempt_gate = (
        p1_external_backend_cryptographic_closure_candidate_gate
        and all(
            token in p1_external_backend_evidence_attempt_runner
            for token in [
                "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
                "p1-external-backend-evidence-attempt-v1",
                "external_evidence_close_candidate_ready",
                "blocked_external_evidence_missing",
                "FORBIDDEN_SOURCE_MARKERS",
                "source_marker_blockers",
                "strict_external_nonce_capture_ready",
                "real_threshold_emission_present",
                "standard_verifier_acceptance_present",
                "mutation_rejection_complete",
                "rejection_distribution_comparison_present",
                "comparison_close_candidate",
                "source_exclusion_passed",
                "claims_theorem_closure",
                "claims_rejection_distribution_preservation",
                "claims_selected_backend_proof_closure",
                "pending theorem-closure review",
            ]
        )
        and all(
            token in p1_external_backend_evidence_attempt_test
            for token in [
                "test_missing_external_inputs_write_blocked_attempt_and_candidate",
                "test_complete_external_bundle_writes_ready_candidate_without_closure_claims",
                "test_rejects_hazmat_or_simulation_source_markers_before_candidate_ready",
                "test_strict_main_returns_two_until_close_candidate_ready",
                "blocked_external_evidence_missing",
                "external_evidence_close_candidate_ready",
                "source_exclusion_passed",
                "claims_theorem_closure",
                "claims_rejection_distribution_preservation",
            ]
        )
        and all(
            token in p1_external_backend_evidence_attempt_manifest
            for token in [
                "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
                "p1-external-backend-evidence-attempt-v1",
                "\"attempt_status\": \"external_evidence_close_candidate_ready\"",
                "\"close_candidate\": true",
                "\"source_exclusion_passed\": true",
                "\"claims_theorem_closure\": false",
                "\"claims_rejection_distribution_preservation\": false",
                "\"claims_selected_backend_proof_closure\": false",
                "\"review_package_binds_inputs\": true",
                "\"review_package_present\": true",
            ]
        )
    )
    p1_external_backend_evidence_package_review_gate = (
        p1_external_backend_evidence_attempt_gate
        and all(
            token in p1_external_backend_evidence_attempt_runner
            for token in [
                "lattice-aggregation:p1-external-backend-evidence-package-review:v1",
                "reviewed_external_backend_evidence_ready",
                "outside_repo_review_manifest",
                "review_package_checks",
                "review_package_expected_input_sha256s",
                "review_package_present",
                "review_package_binds_inputs",
                "review_package_claim_boundary_passed",
                "review_package_source_exclusions_passed",
                "review_package_review_digests_present",
                "--review-package",
            ]
        )
        and all(
            token in p1_external_backend_evidence_attempt_test
            for token in [
                "test_complete_external_bundle_without_review_package_remains_blocked",
                "test_review_package_digest_drift_blocks_close_candidate",
                "reviewed external evidence package is missing",
                "review package input digest mismatch",
                "review_package_binds_inputs",
            ]
        )
        and all(
            token in p1_external_backend_evidence_attempt_manifest
            for token in [
                "p1-external-backend-evidence-package-review",
                "\"review_package_present\": true",
                "\"review_package_binds_inputs\": true",
                "\"review_package_claim_boundary_passed\": true",
                "\"review_package_source_exclusions_passed\": true",
                "\"review_package_review_digests_present\": true",
            ]
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
        and "required proof slots" in reduction_manifest.lower()
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
    validator_10000_standard_verifier_fail_closed_gate = (
        "blocked_fail_closed" in validator_10000_gate_doc
        and "10,000-validator deterministic fan-in telemetry only"
        in validator_10000_gate_doc
        and "requires cryptographic proof" in validator_10000_gate_doc
        and "not standard-verifier equivalence" in validator_10000_gate_doc
        and "not byte-identical to one validator signature"
        in validator_10000_gate_doc
        and (
            "blocked until a real threshold ML-DSA backend emits a verifier-accepted aggregate signature"
            in validator_10000_gate_doc
        )
        and (
            "MLDSA65.Verify(aggregate_public_key, message, aggregate_signature) == accept"
            in validator_10000_gate_doc
        )
        and "const VALIDATOR_COUNT: u16 = 10_000" in validator_10000_gate_test
        and "const THRESHOLD: u16 = 6_667" in validator_10000_gate_test
        and "simulated_10000_validator_aggregate_is_standard_sized_but_verifier_blocked"
        in validator_10000_gate_test
        and "MLDSA65_SIGNATURE_BYTES" in validator_10000_gate_test
        and "SimulatedBackend::verify_standard" in validator_10000_gate_test
        and "BackendUnavailable" in validator_10000_gate_test
        and (
            "simulation backend does not implement standard ML-DSA verification"
            in validator_10000_gate_test
        )
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
        "p1_nonce_producer_selection": p1_nonce_producer_selection,
        "p1_nonce_producer_route_selected": (
            p1_nonce_producer_selection["status"]
            == "p1_nonce_producer_route_selected"
        ),
        "criterion1_proof_substance": criterion1_proof_substance,
        "criterion1_proof_substance_formalized": (
            criterion1_proof_substance["status"]
            == "criterion1_proof_payload_formalized"
        ),
        "criterion2_proof_substance": criterion2_proof_substance,
        "criterion2_proof_substance_formalized": (
            criterion2_proof_substance["status"]
            == "criterion2_proof_payload_formalized"
        ),
        "criterion3_proof_substance": criterion3_proof_substance,
        "criterion3_proof_substance_formalized": (
            criterion3_proof_substance["status"]
            == "criterion3_proof_payload_formalized"
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
        "validator_10000_standard_verifier_fail_closed_gate": (
            validator_10000_standard_verifier_fail_closed_gate
        ),
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
        "p1_distributed_nonce_producer_artifact_gate": (
            p1_distributed_nonce_producer_artifact_gate
        ),
        "p1_distributed_nonce_producer_request_gate": (
            p1_distributed_nonce_producer_request_gate
        ),
        "p1_distributed_nonce_producer_capture_runner_gate": (
            p1_distributed_nonce_producer_capture_runner_gate
        ),
        "p1_nonce_producer_external_origin_guard": (
            p1_nonce_producer_external_origin_guard
        ),
        "p1_nonce_producer_backend_readiness_gate": (
            p1_nonce_producer_backend_readiness_gate
        ),
        "p1_nonce_producer_capture_attempt_gate": (
            p1_nonce_producer_capture_attempt_gate
        ),
        "p1_actual_external_nonce_producer_gate": (
            p1_actual_external_nonce_producer_gate
        ),
        "p1_external_nonce_producer_capture_file_intake": (
            p1_external_nonce_producer_capture_file_intake
        ),
        "p1_standard_verifier_compatibility_artifact_gate": (
            p1_standard_verifier_compatibility_artifact_gate
        ),
        "p1_real_threshold_backend_output_gate": (
            p1_real_threshold_backend_output_gate
        ),
        "p1_real_threshold_backend_actual_capture_runner_gate": (
            p1_real_threshold_backend_actual_capture_runner_gate
        ),
        "p1_real_threshold_backend_emission_request_gate": (
            p1_real_threshold_backend_emission_request_gate
        ),
        "p1_real_threshold_backend_request_capture_binding_gate": (
            p1_real_threshold_backend_request_capture_binding_gate
        ),
        "p1_real_threshold_backend_capture_file_intake_gate": (
            p1_real_threshold_backend_capture_file_intake_gate
        ),
        "p1_hazmat_threshold_backend_capture_adapter_gate": (
            p1_hazmat_threshold_backend_capture_adapter_gate
        ),
        "p1_hazmat_rejection_predicate_transcript_gate": (
            p1_hazmat_rejection_predicate_transcript_gate
        ),
        "p1_hazmat_rejection_equivalence_batch_gate": (
            p1_hazmat_rejection_equivalence_batch_gate
        ),
        "p1_external_backend_cryptographic_closure_candidate_gate": (
            p1_external_backend_cryptographic_closure_candidate_gate
        ),
        "p1_external_backend_evidence_attempt_gate": (
            p1_external_backend_evidence_attempt_gate
        ),
        "p1_external_backend_evidence_package_review_gate": (
            p1_external_backend_evidence_package_review_gate
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
        "README points the run toward reviewed threshold backend artifacts and "
        "standard ML-DSA verification evidence."
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
                    "present as implementation-track evidence."
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
                    "implementation-track evidence."
                )
            if scan["rejection_equivalence_bridge_gate"]:
                partial_progress = True
                observed.append(
                    "AggregateRejectionEquivalenceGate and "
                    "AggregateRecomputationTranscript bridge gates are present "
                    "as implementation-track evidence."
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
                        "raw-real-mldsa; full KAT coverage and validation "
                        "remain separately gated."
                    )
                else:
                    observed.append(
                        "HazmatMldsa65Provider standard-verifier smoke bridge "
                        "is present for fixed-seed ML-DSA-65 signatures and "
                        "mutated message/signature rejection; ACVP/FIPS KAT "
                        "promotion remains separately gated."
                    )
            if scan.get("validator_10000_standard_verifier_fail_closed_gate"):
                partial_progress = True
                observed.append(
                    "10,000-validator standard-verifier fail-closed gate is "
                    "present; it constructs a deterministic 10,000-validator "
                    "topology with threshold 6,667, confirms a standard-size "
                    "3,309-byte simulated aggregate output, and confirms "
                    "SimulatedBackend standard verification returns "
                    "BackendUnavailable. This is deterministic telemetry "
                    "only, requires cryptographic proof, not standard-verifier "
                    "equivalence, and requires production threshold ml-dsa security evidence."
                )
                blockers.append(
                    "10,000-validator standard-verifier equivalence remains "
                    "blocked until a real threshold ML-DSA backend emits a "
                    "verifier-accepted aggregate signature."
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
                    "conformance/proof-review evidence, "
                    "requires selected-backend proof closure evidence, "
                    "requires production threshold ml-dsa security evidence, "
                    "requires cavp/acvts validation evidence, requires fips validation evidence, and "
                    "requires a completed standard-verifier compatibility proof."
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
                    "it remains conformance/proof-review evidence and does "
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
                    "conformance/proof-review evidence and does not claim "
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
                    "conformance/proof-review evidence and does not claim "
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
                    "distributed nonce-producer, rejection-distribution "
                    "review, norm-bound, hint-bound, challenge-bound, "
                    "transcript-binding, theorem-linkage, and "
                    "external-review evidence as evidence_present_unclosed "
                    "only. All Criterion 2 proof slots have typed wrappers, "
                    "and the accepted proof-closure artifact certificate "
                    "carries durable predecessor slot artifact digests, "
                    "but they remain conformance/proof-review evidence "
                    "and do not change aggregate_rejection_equivalence from "
                    "partially_met, do not change the overall verdict from "
                    "partially_proven, and do not claim selected-backend proof "
                    "closure, production threshold ML-DSA security, "
                    "CAVP/ACVTS validation, FIPS validation, "
                    "rejection-distribution preservation, or theorem closure."
                )
            if scan.get("p1_distributed_nonce_producer_artifact_gate"):
                partial_progress = True
                observed.append(
                    "P1 distributed nonce-producer artifact gate is present "
                    "and fail-closed: it accepts only reviewed "
                    "ReviewedP1ShamirNonceDkgTee producer evidence with "
                    "source reference, backend implementation, coordinator "
                    "attestation, Shamir nonce-DKG transcript, active-set, "
                    "pairwise mask seed, nonce-share commitment, "
                    "attempt-binding, abort-accountability, "
                    "standard-verifier bridge, and external-review digests. "
                    "It also has a backend-output adapter that hashes "
                    "submitted nonce-producer material into the gate package, "
                    "plus a canonical capture importer for "
                    "lattice-aggregation:p1-distributed-nonce-producer-capture:v1 "
                    "envelopes with request digest binding, predecessor "
                    "certificate digest binding, and expected package digest "
                    "checks. "
                    "It rejects the hazmat PRF-output oracle, centralized "
                    "expanded-secret-key helper, fixture harnesses, and "
                    "ordinary single-key standard-provider output. This is "
                    "evidence_present_unclosed only and requires theorem-closure review, "
                    "selected-backend proof closure, production threshold "
                    "ML-DSA security, rejection-distribution preservation, "
                    "or completed standard-verifier compatibility."
                )
                blockers.append(
                    "The P1 distributed nonce-producer gate is implemented, "
                    "a backend-output adapter can derive its package from "
                    "submitted nonce-producer material, and a canonical "
                    "capture importer can bind actual backend capture JSON to "
                    "request, predecessor, and expected package digests. "
                    "Externally generated reviewed Shamir nonce-DKG/TEE "
                    "producer material must still replace the hazmat "
                    "PRF-output oracle before Criterion 2 can advance toward "
                    "cryptographic closure."
                )
            if scan.get("p1_distributed_nonce_producer_request_gate"):
                partial_progress = True
                observed.append(
                    "A repo-generated distributed nonce-producer request "
                    "manifest is present for P1; it writes the challenge "
                    "contract that an external Shamir nonce-DKG/TEE producer "
                    "must answer, including predecessor certificate digests, "
                    "required capture schema, required "
                    "p1_shamir_nonce_dkg_tee_external_capture evidence class, "
                    "the nonce-producer material inventory, and forbidden "
                    "hazmat, centralized, fixture, localnet, deterministic, "
                    "and single-key capture sources. This is "
                    "evidence_present_unclosed conformance/proof-review "
                    "evidence, does not change "
                    "aggregate_rejection_equivalence from partially_met, and "
                    "does not change the overall verdict from "
                    "partially_proven."
                )
            if scan.get("p1_distributed_nonce_producer_capture_runner_gate"):
                partial_progress = True
                observed.append(
                    "The distributed nonce-producer capture runner is present "
                    "for P1; it loads request JSON, requires capture schema "
                    "lattice-aggregation:p1-distributed-nonce-producer-capture:v1, "
                    "requires the capture to echo the exact request "
                    "schema/name/SHA-256 binding, rejects stale request "
                    "digests, rejects non-importable capture shapes before "
                    "artifact write, and rejects localnet, deterministic, "
                    "fixture, hazmat, centralized-helper, and single-key "
                    "provider command sources. It now quarantines the local "
                    "checked replay emitter as quarantined_local_schema_replay "
                    "so the schema/importer replay cannot masquerade as an "
                    "admissible_external_backend_capture. This creates the "
                    "executable handoff for actual reviewed nonce-producer "
                    "evidence, but remains evidence_present_unclosed and does "
                    "not claim theorem closure, rejection-distribution "
                    "preservation, or production threshold ML-DSA security."
                )
                blockers.append(
                    "The distributed nonce-producer request and capture "
                    "runner are present, but a reviewed external Shamir "
                    "nonce-DKG/TEE producer must still emit a conforming "
                    "capture whose expected package digests can be imported "
                    "through the Rust gate before the hazmat PRF-output oracle "
                    "is replaced."
                )
            if scan.get("p1_nonce_producer_external_origin_guard"):
                partial_progress = True
                observed.append(
                    "A P1 external command-origin guard is present in the "
                    "nonce-producer capture runner; it records "
                    "backend_command_origin as outside_repo_executable_or_script "
                    "for accepted external commands and rejects an unmarked "
                    "repo-local backend command before it can be classified as "
                    "admissible_external_backend_capture. This hardens the "
                    "actual-backend handoff boundary but remains "
                    "evidence_present_unclosed and does not claim theorem "
                    "closure, rejection-distribution preservation, or "
                    "production threshold ML-DSA security."
                )
                blockers.append(
                    "The external command-origin guard prevents repo-local "
                    "wrappers from satisfying the actual external backend slot, "
                    "but Criterion 2 still needs an independently installed "
                    "backend command outside the repo to emit a reviewed, "
                    "request-bound capture with non-quarantined provenance."
                )
            if scan.get("p1_nonce_producer_backend_readiness_gate"):
                partial_progress = True
                observed.append(
                    "A P1 nonce-producer backend readiness gate is present "
                    "and artifact-backed; it binds the current request "
                    "SHA-256, inspects a candidate backend source tree, "
                    "detects distributed nonce-PRF output-share, splitter, "
                    "and masking-contribution hooks, records source-tree "
                    "checksums, and confirms the checked backend profile is "
                    "backend_candidate_admissible_pending_capture with no "
                    "detected blockers. This means the repo has moved past "
                    "the prior hazmat/simulation/centralized-oracle readiness "
                    "quarantine and is now waiting on an actual reviewed "
                    "external P1 nonce-producer capture. This is "
                    "evidence_present_unclosed boundary evidence and "
                    "requires theorem-closure review, rejection-distribution "
                    "preservation, or production threshold ML-DSA security. "
                    "The handoff replay now requires an admissible readiness "
                    "manifest before explicit external backend commands can "
                    "be promoted, supports request reuse so the readiness "
                    "manifest binds the exact request SHA-256, and records "
                    "accepted readiness metadata in the handoff manifest."
                )
                blockers.append(
                    "The nonce-producer backend readiness gate is now "
                    "admissible, but Criterion 2 still requires an actual "
                    "reviewed external Shamir nonce-DKG/TEE producer capture "
                    "with source, implementation, transcript, attestation, "
                    "nonce-share commitments, abort-accountability, and "
                    "external review evidence."
                )
            if scan.get("p1_nonce_producer_capture_attempt_gate"):
                partial_progress = True
                observed.append(
                    "A P1 admissible nonce-producer capture-attempt runner is "
                    "present and artifact-backed; it generates the exact "
                    "request under the handoff directory, runs backend "
                    "readiness against that request, requires an explicit "
                    "{request}-bound backend command template, and records a "
                    "capture_promoted attempt after the current candidate "
                    "passes readiness and the repo reference CLI command "
                    "successfully emits importable capture JSON. The promoted "
                    "handoff is marked repo_reference_cli_capture and "
                    "quarantined as reference CLI evidence, so it proves the "
                    "executable process/JSON/import contract rather than an "
                    "independently generated threshold backend. "
                    "This is evidence_present_unclosed boundary evidence "
                    "only and requires theorem-closure review, "
                    "rejection-distribution preservation, or production "
                    "threshold ML-DSA security."
                )
                blockers.append(
                    "The P1 admissible capture-attempt runner closes the "
                    "operational gap between readiness preflight and capture "
                    "promotion, and the current artifact now promotes a "
                    "request-bound reference CLI capture through the same "
                    "handoff/import path. That reference CLI is quarantined "
                    "as requires actual backend evidence, so a reviewed external "
                    "backend binary still must be installed or provided and "
                    "emit a conforming request-bound capture before the "
                    "distributed nonce-producer slot can advance beyond "
                    "evidence_present_unclosed."
                )
            if scan.get("p1_actual_external_nonce_producer_gate"):
                partial_progress = True
                observed.append(
                    "A P1 actual external nonce-producer capture gate is "
                    "present and artifact-backed; it requires the promoted "
                    "handoff source profile to be "
                    "admissible_external_backend_capture with quarantine false "
                    "before the distributed nonce-producer slot can be treated "
                    "as actual external backend evidence. The current artifact "
                    "is actual_external_capture_ready with source profile "
                    "admissible_external_backend_capture. This is "
                    "evidence_present_unclosed boundary evidence; Criterion 2 "
                    "now has the external evidence package path populated but "
                    "still requires rejection-distribution preservation review, "
                    "full validation, theorem-linkage review, or production "
                    "threshold ML-DSA security."
                )
                blockers.append(
                    "The actual external nonce-producer gate is now ready with "
                    "admissible_external_backend_capture, but Criterion 2 remains "
                    "blocked on rejection-distribution preservation, full "
                    "validation artifacts, theorem-linkage review, and proof "
                    "closure."
                )
            if scan.get("p1_external_nonce_producer_capture_file_intake"):
                partial_progress = True
                observed.append(
                    "A P1 external nonce-producer capture-file intake path is "
                    "present; it stages a preexisting outside_repo_capture_file "
                    "only after admissible readiness and a matching "
                    "outside_repo_review_manifest with "
                    "reviewed_external_capture_ready status. It rejects "
                    "repo-local capture files, missing review dossiers, and "
                    "failed external-review checks; validates the exact "
                    "request digest through the capture runner; writes "
                    "attempt-compatible handoff artifacts with "
                    "preexisting_external_capture_file provenance; and can "
                    "make the actual-external gate ready in tests only for "
                    "non-quarantined admissible_external_backend_capture "
                    "material. This is evidence_present_unclosed boundary "
                    "evidence and requires theorem-closure review, "
                    "rejection-distribution preservation, or production "
                    "threshold ML-DSA security."
                )
                blockers.append(
                    "The external capture-file intake is executable, but the "
                    "repo still needs a real outside-repo reviewed nonce-DKG/TEE "
                    "capture file plus a matching external review dossier for "
                    "any future nonce-source refresh; the current checked "
                    "actual-external nonce gate is ready, but Criterion 2 "
                    "still depends on the real threshold backend and proof "
                    "review evidence."
                )
            if scan.get("p1_nonce_producer_route_selected"):
                partial_progress = True
                observed.append(
                    "P1 nonce-producer route selection is present and "
                    "source-backed: the selected route is FIPS "
                    "204-compatible threshold ML-DSA via Shamir Nonce DKG "
                    "for the P1 TEE/HSM coordinator profile. It identifies "
                    "`derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key` "
                    "as the hazmat PRF-output oracle replacement target and "
                    "targets `distributed_nonce_producer_artifact_digest` "
                    "before distributed-nonce comparator output can be treated as reviewed producer "
                    "evidence. This requires theorem-closure review, "
                    "selected-backend proof closure, production threshold "
                    "ML-DSA security, or rejection-distribution preservation."
                )
                blockers.append(
                    "A selected P1 Shamir nonce-DKG producer route is "
                    "documented, but the reviewed distributed nonce-producer "
                    "artifact digest and backend-generated producer transcript "
                    "are still required before the hazmat PRF-output oracle is "
                    "replaced."
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
            if scan.get("p1_real_threshold_backend_output_gate"):
                partial_progress = True
                observed.append(
                    "P1 real-threshold backend emission ingestion artifact is "
                    "present with a canonical backend-emission capture "
                    "schema/importer as the input path to the threshold "
                    "verifier closure contract; it requires 10,000 validators "
                    "with threshold 6,667, a 3,309-byte aggregate signature, "
                    "real threshold ML-DSA backend provenance, predecessor "
                    "certificate digests, backend source, implementation, and transcript digests, "
                    "provider-verified backend-output ingestion, standard-verifier acceptance, expected package "
                    "digest binding, and mutated "
                    "message, public key, and signature rejection evidence. "
                    "It rejects deterministic simulation "
                    "and ordinary single-key standard-provider output as "
                    "closure evidence. The checked capture schema fixture is "
                    "blocked until actual real-threshold backend evidence is "
                    "present, the checked ingestion fixture harness is blocked "
                    "as FixtureHarness, and an actual single-key ML-DSA-65 "
                    "negative-control emission fixture verifies through the "
                    "standard provider but is rejected as StandardProviderSingleKey. "
                    "This remains conformance/proof-review evidence, not "
                    "production threshold ML-DSA security, not CAVP/ACVTS "
                    "validation, requires fips validation evidence, and not a completed "
                    "cryptographic proof."
                )
                blockers.append(
                    "P1 real-threshold backend emission ingestion artifact is "
                    "present and the strict external backend capture is now "
                    "admissible, but rejection-distribution preservation, full "
                    "validation artifacts, theorem-linkage review, and reviewed "
                    "cryptographic proof remain open."
                )
            if scan.get("p1_real_threshold_backend_actual_capture_runner_gate"):
                partial_progress = True
                observed.append(
                    "Actual real-threshold backend capture runner is present "
                    "for P1; it emits externally generated "
                    "RealThresholdMldsa capture material from an "
                    "artifact-ready package into the canonical "
                    "provider-verified importer, rejects localnet and "
                    "deterministic simulation command sources plus "
                    "non-importable capture shapes before artifact write, "
                    "and records evidence_present_unclosed "
                    "conformance/proof-review evidence. This runner does "
                    "not change aggregate_rejection_equivalence from "
                    "partially_met, does not change the overall verdict from "
                    "partially_proven, and does not claim rejection-distribution "
                    "preservation, production threshold ML-DSA security, "
                    "CAVP/ACVTS validation, FIPS validation, or theorem closure."
                )
            if scan.get("p1_real_threshold_backend_emission_request_gate"):
                partial_progress = True
                observed.append(
                    "A repo-generated real-threshold backend emission request "
                    "artifact is present for P1 at "
                    "artifacts/backend-emission-request/latest/request.json; "
                    "it writes the P1 challenge contract that an external "
                    "backend must answer, including 10,000 validators, "
                    "threshold 6,667, message bytes, predecessor certificate "
                    "digests, required capture schema, external "
                    "RealThresholdMldsa evidence class, mutation rejection "
                    "requirements, forbidden localnet/simulation capture "
                    "sources, and a request SHA-256 recorded in "
                    "artifacts/backend-emission-request/latest/manifest.json. "
                    "This is evidence_present_unclosed conformance/proof-review "
                    "evidence, does not change aggregate_rejection_equivalence "
                    "from partially_met, and does not change the overall verdict "
                    "from partially_proven."
                )
            if scan.get("p1_real_threshold_backend_request_capture_binding_gate"):
                partial_progress = True
                observed.append(
                    "The real-threshold backend capture path now binds each "
                    "capture to the exact repo-generated request digest: the "
                    "runner loads request JSON, requires the capture to carry "
                    "the request schema/name/SHA-256 binding, rejects stale or "
                    "missing request bindings, and the Rust importer requires "
                    "a nonzero request digest binding before backend material "
                    "can enter the verified ingestion gate. This closes a "
                    "harness gap between request generation and capture "
                    "ingestion, but remains evidence_present_unclosed "
                    "conformance/proof-review evidence; it does not "
                    "change aggregate_rejection_equivalence from partially_met "
                    "or the overall verdict from partially_proven."
                )
            if scan.get("p1_real_threshold_backend_capture_file_intake_gate"):
                partial_progress = True
                observed.append(
                    "A real-threshold backend-emission capture-file intake is "
                    "present for P1: `scripts/stage_external_backend_emission_capture.py` "
                    "stages only an `outside_repo_capture_file`, requires an "
                    "`outside_repo_review_manifest` with schema "
                    "`lattice-aggregation:p1-external-backend-emission-capture-review:v1`, "
                    "requires review status "
                    "`reviewed_external_backend_emission_capture_ready`, validates "
                    "the exact repo request digest through the canonical backend "
                    "capture runner, records `preexisting_external_capture_file` "
                    "provenance, and rejects repo-local captures, missing or failed "
                    "review manifests, stale request bindings, localnet/simulation, "
                    "fixture, and single-key standard-provider sources before "
                    "artifact write. This is an executable handoff/intake gate "
                    "only; it does not change aggregate_rejection_equivalence from "
                    "partially_met, does not change the overall verdict from "
                    "partially_proven, and does not close Criterion 2, "
                    "rejection-distribution preservation, or theorem closure."
                )
            if scan.get("p1_hazmat_threshold_backend_capture_adapter_gate"):
                partial_progress = True
                observed.append(
                    "A repo-owned hazmat threshold backend capture adapter is "
                    "present for the 10,000-validator P1 path; it requires an "
                    "explicit backend crate path, generates a temporary Rust "
                    "emitter for the hazmat `dytallix-pq-threshold` backend, "
                    "bridges the threshold session to the standard "
                    "external-message verifier boundary, records mutation "
                    "rejection for message, public key, and signature changes, "
                    "and emits request-bound capture JSON for the canonical "
                    "runner. This is evidence_present_unclosed "
                    "conformance/proof-review infrastructure only; it does not "
                    "change aggregate_rejection_equivalence from partially_met "
                    "or the overall verdict from partially_proven."
                )
            if scan.get("p1_hazmat_rejection_predicate_transcript_gate"):
                partial_progress = True
                observed.append(
                    "The hazmat threshold backend capture adapter now emits a "
                    "per-attempt bound-predicate transcript: attempts[] records "
                    "attempt id, mask-seed digest, challenge digest, retry count "
                    "context, z/r0/ct0/hint predicate results, and "
                    "accepted_or_rejected for each backend signing attempt. "
                    "This exposes the per-attempt ML-DSA rejection predicates "
                    "needed for batch comparison against centralized ML-DSA "
                    "behavior, but it does not by itself prove "
                    "rejection-distribution preservation or move "
                    "aggregate_rejection_equivalence beyond partially_met."
                )
            if scan.get("p1_hazmat_rejection_equivalence_batch_gate"):
                partial_progress = True
                observed.append(
                    "A hazmat centralized-vs-threshold rejection-equivalence "
                    "batch comparator is present. It derives centralized "
                    "ML-DSA per-attempt predicates and threshold per-attempt "
                    "predicates from the explicit backend, records "
                    "threshold_attempts, centralized_attempts, "
                    "predicate_mismatches, challenge_digest_matches, "
                    "accepted_or_rejected_matches, and close_candidate, and "
                    "keeps claims_rejection_distribution_preservation and "
                    "claims_theorem_closure false. This is the first runnable "
                    "comparison harness for the actual rejection-sampling "
                    "question. It can also run an aligned centralized mask "
                    "domain mode keyed to centralized-rho-double-prime-kappa; "
                    "a distributed-nonce-prf-output-shares mode now consumes "
                    "active-set-bound nonce PRF output shares instead of the "
                    "centralized masking helper on the threshold contribution "
                    "path; "
                    "a zero predicate mismatches close_candidate result there "
                    "is strong algebraic closure-candidate evidence, but the "
                    "PRF-output oracle still derives from expanded secret-key "
                    "material until a reviewed distributed PRF/MPC producer "
                    "replaces it, so it still "
                    "records remaining theorem review requirements or move "
                    "aggregate_rejection_equivalence beyond partially_met "
                    "without reviewed distributed nonce-DKG replacement and "
                        "external review."
                )
            if scan.get("p1_external_backend_cryptographic_closure_candidate_gate"):
                partial_progress = True
                observed.append(
                    "A Batch 7 external-backend cryptographic closure-candidate "
                    "artifact gate is present. It composes the strict actual "
                    "external nonce-producer gate, request-bound real-threshold "
                    "backend emission capture, standard-verifier acceptance "
                    "evidence, mutation rejection evidence, and "
                    "distributed-nonce-prf-output-shares rejection comparison "
                    "into one computed close_candidate manifest. The checked "
                    "checked artifact remains evidence_present_unclosed with "
                    "close_candidate true and "
                    "claims_theorem_closure, "
                    "claims_rejection_distribution_preservation, and "
                    "claims_selected_backend_proof_closure false; it does not "
                    "close the theorem or move aggregate_rejection_equivalence "
                    "beyond partially_met until the remaining proof-review "
                    "obligations are satisfied."
                )
            if scan.get("p1_external_backend_evidence_attempt_gate"):
                partial_progress = True
                observed.append(
                    "A Batch 8 external-backend evidence attempt runner is "
                    "present. It groups the strict actual external nonce gate, "
                    "real-threshold backend emission capture, standard-verifier "
                    "acceptance evidence, mutation rejection evidence, "
                    "rejection-distribution comparison, and source_exclusion_passed "
                    "guard into the Batch 7 close_candidate artifact. The checked "
                    "attempt is external_evidence_close_candidate_ready and "
                    "keeps claims_theorem_closure, "
                    "claims_rejection_distribution_preservation, and "
                    "claims_selected_backend_proof_closure false; it does not "
                    "close the theorem or move aggregate_rejection_equivalence "
                    "beyond partially_met until distribution, validation, and "
                    "theorem-linkage review close."
                )
            if scan.get("p1_external_backend_evidence_package_review_gate"):
                partial_progress = True
                observed.append(
                    "A Batch 9 reviewed external evidence package gate is "
                    "present inside the grouped external-backend evidence "
                    "attempt. It requires schema "
                    "lattice-aggregation:p1-external-backend-evidence-package-review:v1, "
                    "reviewed_external_backend_evidence_ready status, "
                    "outside_repo_review_manifest origin, exact "
                    "review_package_binds_inputs digest binding for the nonce "
                    "gate, real-threshold backend capture, rejection batch, "
                    "and Batch 7 candidate digest, plus source-exclusion and "
                    "review-digest checks before a close_candidate attempt can "
                    "be treated as externally reviewed evidence. The checked "
                    "attempt now carries that reviewed external evidence package; "
                    "the remaining blockers are theorem-review requirements and "
                    "do not move aggregate_rejection_equivalence beyond "
                    "partially_met."
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
                            "evidence."
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
                            "framework/conformance evidence."
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
                            "framework/conformance evidence."
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
                            "evidence."
                        )
                elif scan.get("p1_aggregate_recomputation_artifact_gate"):
                    blockers.append(
                        "Real P1 aggregate recomputation artifacts, full "
                        "ACVP/FIPS KAT coverage, reviewed proof artifacts, and "
                        "CAVP/ACVTS validation artifacts are still not checked "
                        "in; the P1 gate and bounded sample-vector KAT now "
                        "identify the required backend-run evidence."
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
                    "accepted-sample checks are present as implementation-track "
                    "evidence."
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
                    "Implementation-track evidence supports transcript binding, validator "
                    "universe checks, or context-bound contribution shape."
                )
            if scan["local_acceptance_conformance_scaffold"]:
                observed.append(
                    "LocalAccept and AcceptedPartialContribution conformance "
                    "tokens are present as implementation-track evidence."
                )
            if scan["partial_soundness_evidence_gate"]:
                partial_progress = True
                observed.append(
                    "PartialContributionSoundnessEvidence and "
                    "ProofBackedLocalVerifier gates are present as "
                    "implementation-track evidence."
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
                    "hiding proof evidence are required for promotion."
                )
            status = "partially_met" if observed and blockers else "blocked"
        elif criterion["id"] == "unauthorized_aggregate_reduction":
            if scan["unauthorized_reduction_manifest_gate"]:
                partial_progress = True
                observed.append(
                    "Unauthorized aggregate reduction manifest names a base "
                    "ML-DSA forgery case and threshold-side violation cases as "
                    "implementation-track evidence."
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
                    "Threshold unforgeability reduction requires the completed "
                    "proof package."
                )

        if criterion["id"] != "partial_contribution_soundness":
            status = "partially_met" if partial_progress and blockers else (
                "blocked" if blockers else "met"
            )

        item["observed_evidence"] = observed
        item["blockers"] = blockers
        item["status"] = status
        item["verdict_contribution"] = (
            "supports_evidence_track" if status == "partially_met" else "pending_evidence"
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
        ["cargo", "test", "--test", "criterion1_proof_substance_manifest"],
        ["cargo", "test", "--test", "criterion2_proof_substance_manifest"],
        ["cargo", "test", "--test", "criterion3_proof_substance_manifest"],
        ["cargo", "test", "--test", "validator_10000_standard_verifier_gate"],
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
        ["cargo", "run", "--bin", "lattice-aggregation"],
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
        "claim_boundary": "closure-run implementation track",
        "selected_backend": scan["selected_backend_direction"],
        "thesis_operating_parameters": scan["thesis_operating_parameters"],
        "p1_nonce_producer_selection": scan["p1_nonce_producer_selection"],
        "criterion1_proof_substance": scan["criterion1_proof_substance"],
        "criterion2_proof_substance": scan["criterion2_proof_substance"],
        "criterion3_proof_substance": scan["criterion3_proof_substance"],
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
            "README lists the current evidence track for threshold backend work.",
            "README ties assessment to reviewed threshold backend artifacts and standard ML-DSA verification.",
            "Remaining proof artifacts are treated as run inputs for the implementation track.",
        ]
    return [
        "README evidence-track language was not detected; claim-drift review is required.",
    ]


def artifact_slot_dashboard(report):
    """Summarize proof-substance artifact slots by status."""
    dashboard = {}
    for report_key, label in [
        ("criterion1_proof_substance", "criterion_1"),
        ("criterion2_proof_substance", "criterion_2"),
        ("criterion3_proof_substance", "criterion_3"),
    ]:
        status = report.get(report_key, {})
        slot_statuses = status.get("artifact_slot_statuses", {})
        by_status = {}
        for slot_id, slot_status in slot_statuses.items():
            by_status.setdefault(slot_status, []).append(slot_id)
        dashboard[label] = {
            "status": status.get("status", "missing_or_incomplete"),
            "criterion_id": status.get("criterion_id", ""),
            "artifact_slot_statuses": {
                key: sorted(value) for key, value in sorted(by_status.items())
            },
        }
    return dashboard


def external_capture_provenance_requirements():
    """Return the durable provenance fields required for external captures."""
    return {
        "schema": "lattice-aggregation:external-capture-provenance:v1",
        "required_fields": [
            "request_schema",
            "request_name",
            "request_sha256",
            "capture_schema",
            "capture_sha256",
            "backend_command_sha256",
            "evidence_class",
            "runner_status",
            "claim_boundary",
            "expected_digest_fields",
            "metadata_fields",
        ],
        "metadata_fields": [
            "commit",
            "branch",
            "dirty",
            "cargo_version",
            "rustc_version",
            "os",
            "python_version",
            "cargo_lock_sha256",
        ],
        "claim_boundary": "conformance/proof-review evidence",
        "status": "evidence_present_unclosed",
    }


def build_closure_dashboard(report):
    """Build a compact current-closure dashboard from an assessment report."""
    criteria = []
    for criterion in report.get("criteria", []):
        criteria.append(
            {
                "id": criterion.get("id", ""),
                "status": criterion.get("status", ""),
                "observed_evidence_count": len(criterion.get("observed_evidence", [])),
                "blocker_count": len(criterion.get("blockers", [])),
            }
        )
    return {
        "schema": "lattice-aggregation.current-closure-dashboard.v1",
        "claim_boundary": report.get("claim_boundary", "research scaffold evidence"),
        "overall_verdict": report.get("overall_verdict", ""),
        "commit": report.get("commit", ""),
        "branch": report.get("branch", ""),
        "criteria": criteria,
        "proof_artifact_slots": artifact_slot_dashboard(report),
        "external_capture_provenance_requirements": (
            external_capture_provenance_requirements()
        ),
        "non_closure_guards": [
            "pending theorem-closure review",
            "requires selected-backend proof closure evidence",
            "requires production threshold ml-dsa security evidence",
            "requires cavp/acvts validation evidence",
            "requires fips validation evidence",
            "requires rejection-distribution preservation proof",
        ],
    }


def render_closure_dashboard_markdown(dashboard):
    """Render the current-closure dashboard as Markdown."""
    lines = [
        "# Current Closure Dashboard",
        "",
        f"Overall verdict: `{dashboard['overall_verdict']}`",
        f"Claim boundary: `{dashboard['claim_boundary']}`",
        f"Branch: `{dashboard['branch']}`",
        f"Commit: `{dashboard['commit']}`",
        "",
        "## Criteria",
        "",
    ]
    for criterion in dashboard.get("criteria", []):
        lines.append(
            f"- `{criterion['id']}`: `{criterion['status']}` "
            f"({criterion['observed_evidence_count']} evidence entries, "
            f"{criterion['blocker_count']} blockers)"
        )
    lines.extend(["", "## Proof Artifact Slots", ""])
    for criterion_id, slot_summary in dashboard.get("proof_artifact_slots", {}).items():
        lines.append(f"### {criterion_id}")
        lines.append(f"- Status: `{slot_summary['status']}`")
        for slot_status, slots in slot_summary.get("artifact_slot_statuses", {}).items():
            lines.append(f"- `{slot_status}`: {', '.join(slots) if slots else 'none'}")
        lines.append("")
    lines.extend(["## Non-Closure Guards", ""])
    for guard in dashboard.get("non_closure_guards", []):
        lines.append(f"- {guard}")
    return "\n".join(lines).rstrip() + "\n"


def write_reports(report, out_dir):
    """Write JSON, Markdown, and dashboard assessment reports."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dashboard = build_closure_dashboard(report)
    (out_dir / "assessment.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "assessment.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "closure-dashboard.json").write_text(
        json.dumps(dashboard, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "closure-dashboard.md").write_text(
        render_closure_dashboard_markdown(dashboard),
        encoding="utf-8",
    )


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

    producer = report.get("p1_nonce_producer_selection", {})
    lines.extend(["", "## P1 Nonce Producer Selection", ""])
    lines.append(
        f"- Status: `{producer.get('status', 'missing_or_incomplete')}`"
    )
    if producer.get("status") == "p1_nonce_producer_route_selected":
        lines.append(f"- Route: {producer['selected_route']}")
        lines.append(f"- Profile: {producer['profile']}")
        lines.append(
            f"- Replacement target: `{producer['replacement_target']}`"
        )
        lines.append(
            f"- Required slot: `{producer['required_artifact_slot']}`"
        )
        lines.append(
            "- Required backend artifacts: "
            + ", ".join(producer["required_backend_artifacts"])
        )
    elif producer.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(producer["missing_evidence"])
        )

    criterion1 = report.get("criterion1_proof_substance", {})
    lines.extend(["", "## Criterion 1 Proof Substance", ""])
    lines.append(
        f"- Status: `{criterion1.get('status', 'missing_or_incomplete')}`"
    )
    if criterion1.get("status") == "criterion1_proof_payload_formalized":
        lines.append(f"- Criterion: {criterion1['criterion_id']}")
        lines.append(f"- Payload status: {criterion1['payload_status']}")
        lines.append(f"- Boundary: {criterion1['scope']}")
        lines.append(f"- Profile: {criterion1['selected_profile']}")
        lines.append(f"- Output target: {criterion1['output_target']}")
        lines.append(
            "- Required artifact slots: "
            + ", ".join(criterion1["required_artifact_slots"])
        )
        artifact_statuses = criterion1.get("artifact_slot_statuses", {})
        if artifact_statuses:
            lines.append(
                "- Artifact slot statuses: "
                + ", ".join(
                    f"{slot}={artifact_statuses[slot]}"
                    for slot in criterion1["required_artifact_slots"]
                    if slot in artifact_statuses
                )
            )
        artifact_sources = criterion1.get("artifact_slot_sources", {})
        if artifact_sources:
            lines.append(
                "- Artifact evidence sources: "
                + ", ".join(
                    f"{slot}={artifact_sources[slot]}"
                    for slot in criterion1["required_artifact_slots"]
                    if slot in artifact_sources
                )
            )
        theorem_links = criterion1.get("theorem_links", [])
        if theorem_links:
            lines.append("- Theorem links: " + ", ".join(theorem_links))
    elif criterion1.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(criterion1["missing_evidence"])
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
        artifact_packages = criterion2.get("artifact_slot_packages", {})
        if artifact_packages:
            lines.append(
                "- Artifact packages: "
                + ", ".join(
                    f"{slot}={artifact_packages[slot]}"
                    for slot in criterion2["required_artifact_slots"]
                    if slot in artifact_packages
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

    criterion3 = report.get("criterion3_proof_substance", {})
    lines.extend(["", "## Criterion 3 Proof Substance", ""])
    lines.append(
        f"- Status: `{criterion3.get('status', 'missing_or_incomplete')}`"
    )
    if criterion3.get("status") == "criterion3_proof_payload_formalized":
        lines.append(f"- Criterion: {criterion3['criterion_id']}")
        lines.append(f"- Payload status: {criterion3['payload_status']}")
        lines.append(f"- Boundary: {criterion3['scope']}")
        lines.append(f"- Profile: {criterion3['selected_profile']}")
        lines.append(f"- Output target: {criterion3['output_target']}")
        lines.append(
            "- Required artifact slots: "
            + ", ".join(criterion3["required_artifact_slots"])
        )
        artifact_statuses = criterion3.get("artifact_slot_statuses", {})
        if artifact_statuses:
            lines.append(
                "- Artifact slot statuses: "
                + ", ".join(
                    f"{slot}={artifact_statuses[slot]}"
                    for slot in criterion3["required_artifact_slots"]
                    if slot in artifact_statuses
                )
            )
        artifact_sources = criterion3.get("artifact_slot_sources", {})
        if artifact_sources:
            lines.append(
                "- Artifact evidence sources: "
                + ", ".join(
                    f"{slot}={artifact_sources[slot]}"
                    for slot in criterion3["required_artifact_slots"]
                    if slot in artifact_sources
                )
            )
        theorem_links = criterion3.get("theorem_links", [])
        if theorem_links:
            lines.append("- Theorem links: " + ", ".join(theorem_links))
    elif criterion3.get("missing_evidence"):
        lines.append(
            "- Missing evidence tokens: "
            + ", ".join(criterion3["missing_evidence"])
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
