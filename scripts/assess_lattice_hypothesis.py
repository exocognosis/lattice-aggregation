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


def normalize_whitespace(text):
    """Normalize text for phrase scans across Markdown line wrapping."""
    return re.sub(r"\s+", " ", text).strip().lower()


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

    return {
        "documents": texts,
        "missing_documents": missing,
        "selected_backend_direction": selected_backend_direction(texts),
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
        "rejection_equivalence_closure_framework": (
            rejection_equivalence_closure_framework
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
            "research status" in readme
            and "deterministic simulation" in readme
            and "if the hypothesis is proven" in readme
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
                observed.append(
                    "HazmatMldsa65Provider standard-verifier smoke bridge is "
                    "present for fixed-seed ML-DSA-65 signatures and mutated "
                    "message/signature rejection; ACVP/FIPS KAT promotion "
                    "remains separately gated."
                )
            if scan["standard_verifier_blocked"]:
                if scan["hazmat_standard_verifier_bridge"]:
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
