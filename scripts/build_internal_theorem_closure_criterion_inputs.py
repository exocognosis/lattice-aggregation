#!/usr/bin/env python3
"""Build fail-closed internal theorem-closure criterion input manifests.

These manifests are deliberately not passing proof artifacts. They bind the
current proof/code/test context for each theorem criterion and enumerate the
substantive evidence that must replace each fail-closed draft before the
internal closure assessor can promote the bundle.
"""

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:internal-theorem-closure-criterion-inputs:v1"
NAME = "internal-theorem-closure-criterion-inputs-v1"
CLAIM_BOUNDARY = (
    "internal criterion input requirements only; theorem unclosed pending "
    "substantive proof, campaign validation, and independent review"
)
DEFAULT_OUT = "artifacts/internal-theorem-closure-evidence/latest"


def load_bundle_builder():
    path = Path(__file__).with_name("build_internal_theorem_closure_bundle.py")
    spec = importlib.util.spec_from_file_location(
        "internal_theorem_closure_bundle_builder_for_inputs", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("internal theorem closure bundle builder is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLE = load_bundle_builder()


COMMON_PROTOCOL_SPEC_ARTIFACTS = (
    "docs/cryptography/security-model.md",
    "docs/cryptography/threshold-mldsa-protocol-spec.md",
    "docs/cryptography/formal-security-theorem.md",
    "docs/cryptography/internal-theorem-closure-candidate.md",
    "docs/cryptography/internal-theorem-closure-bundle.md",
)


CRITERION_CONTEXT = {
    "aggregate_mask_distribution": {
        "proof_artifacts": (
            "docs/cryptography/criterion-1-proof-substance.md",
            "docs/cryptography/criterion-1-proof-substance.json",
            "docs/cryptography/mask-distribution-evidence.md",
            "docs/cryptography/distributed-mask-mpc-feasibility.md",
            "docs/cryptography/epsilon-mask-fork-decision.md",
        ),
        "implementation_artifacts": (
            "src/production/mask_distribution.rs",
            "src/production/epsilon.rs",
            "src/crypto/distributed_nonce.rs",
            "src/crypto/mldsa_primitives.rs",
        ),
        "test_artifacts": (
            "tests/production_mask_distribution.rs",
            "tests/production_epsilon.rs",
            "tests/criterion1_proof_substance_manifest.rs",
            "script_tests/test_model_distributed_mask_mpc_feasibility.py",
        ),
        "blockers": (
            "selected_mask_construction_proven requires a real exact distributed "
            "ExpandMask/MPC construction artifact",
            "centralized_distribution_reference_bound requires a reviewed ML-DSA-65 "
            "centralized mask-distribution reference proof",
            "aggregate_distribution_bound requires a concrete statistical/Renyi "
            "distance bound for the aggregate mask distribution",
            "distribution_distance_bound_nonvacuous requires a nonzero-security "
            "loss calculation at fixed ML-DSA-65 parameters",
        ),
    },
    "aggregate_rejection_equivalence": {
        "proof_artifacts": (
            "docs/cryptography/criterion-2-proof-substance.md",
            "docs/cryptography/criterion-2-proof-substance.json",
            "docs/cryptography/rejection-equivalence-evidence.md",
            "docs/cryptography/noise-rejection-proof-plan.md",
            "artifacts/p1-rejection-distribution-preservation-review/latest/manifest.json",
            "artifacts/p1-full-kat-cavp-validation-review/latest/manifest.json",
            "artifacts/theorem-closure-review/latest/manifest.json",
        ),
        "implementation_artifacts": (
            "src/production/rejection_equivalence.rs",
            "src/production/acceptance.rs",
            "src/production/provider.rs",
            "src/backend/fips_sign.rs",
            "src/backend/fips_wire.rs",
            "src/backend/threshold_core.rs",
        ),
        "test_artifacts": (
            "tests/production_rejection_equivalence.rs",
            "tests/production_acceptance.rs",
            "tests/production_provider.rs",
            "tests/criterion2_proof_substance_manifest.rs",
            "script_tests/test_build_theorem_closure_review_manifest.py",
            "script_tests/test_assess_theorem_closure_readiness.py",
        ),
        "blockers": (
            "real_threshold_recomputation_verified requires the real 10,000/6,667 "
            "distributed campaign capture and validation bundle",
            "standard_verifier_accepts requires accepted threshold outputs from the "
            "actual no-reconstruction backend, not a reference or single-key path",
            "rejection_predicates_equivalent requires per-attempt FIPS 204 predicate "
            "equivalence over accepted and rejected campaign attempts",
            "mutation_cases_rejected requires bound negative message, public-key, "
            "signature, transcript, replay, and malicious-share cases from the same "
            "campaign capture",
        ),
    },
    "abort_retry_bias": {
        "proof_artifacts": (
            "docs/cryptography/criterion-3-proof-substance.md",
            "docs/cryptography/criterion-3-proof-substance.json",
            "docs/cryptography/abort-retry-bias-evidence.md",
            "artifacts/p1-accepted-distribution-abort-review/latest/manifest.json",
            "artifacts/p1-rejection-distribution-proof-input/latest/evidence.json",
        ),
        "implementation_artifacts": (
            "src/production/abort_bias.rs",
            "src/production/prefilter.rs",
            "src/production/preprocess.rs",
            "src/production/transcript.rs",
        ),
        "test_artifacts": (
            "tests/production_abort_bias.rs",
            "tests/production_prefilter.rs",
            "tests/production_preprocess.rs",
            "tests/criterion3_proof_substance_manifest.rs",
        ),
        "blockers": (
            "retry_domain_separation_proven requires a proof and campaign evidence "
            "for retry/session domain separation under concurrent attempts",
            "abort_leakage_bound_proven requires a concrete leakage bound for "
            "selective aborts, withholding, timeout, and restart observations",
            "accepted_output_distribution_proven requires a reviewed proof that "
            "accepted outputs preserve the target ML-DSA-65 distribution",
            "adversarial_abort_corpus_passed requires the preregistered malicious "
            "abort/retry cases to pass in the real distributed campaign",
        ),
    },
    "partial_contribution_soundness": {
        "proof_artifacts": (
            "docs/cryptography/partial-soundness-evidence.md",
            "docs/cryptography/partial-soundness-advancement-2026-07-12.md",
            "docs/cryptography/vss-dkg-security-plan.md",
            "docs/cryptography/formal-threshold-mldsa-transcript.md",
        ),
        "implementation_artifacts": (
            "src/production/partial_soundness.rs",
            "src/backend/module_partial.rs",
            "src/backend/algebraic_partial.rs",
            "src/crypto/bdlop.rs",
            "src/crypto/bdlop_pok.rs",
            "src/crypto/vss_bdlop.rs",
            "src/crypto/mldsa_dkg.rs",
        ),
        "test_artifacts": (
            "tests/production_partial_soundness.rs",
            "tests/partial_soundness_real_local_verifier.rs",
            "tests/threshold_core.rs",
            "tests/ui/type_state_invalid_partial.rs",
        ),
        "blockers": (
            "vss_dkg_binding_hiding_proven requires proof-backed DKG/VSS share "
            "validity and hiding evidence on the full signing path",
            "partial_context_binding_proven requires each partial response to bind "
            "signer, commitment, challenge, attempt, transcript, and authorization",
            "malicious_partials_rejected requires full-path rejection evidence for "
            "malformed, stale, duplicate, and out-of-set partials",
            "local_accept_leakage_reviewed requires leakage review for local "
            "acceptance and partial-verification evidence",
        ),
    },
    "unauthorized_aggregate_reduction": {
        "proof_artifacts": (
            "docs/cryptography/unauthorized-aggregate-reduction.md",
            "docs/cryptography/proof-obligations.md",
            "docs/cryptography/ideal-functionality.md",
            "docs/cryptography/random-oracle-game.md",
            "docs/cryptography/internal-proof-obligation-register.json",
        ),
        "implementation_artifacts": (
            "src/production/selected_backend.rs",
            "src/production/coordinator.rs",
            "src/production/evidence.rs",
            "src/adapter/evidence.rs",
            "src/transcript.rs",
        ),
        "test_artifacts": (
            "tests/unauthorized_aggregate_reduction_manifest.rs",
            "tests/internal_proof_obligation_register.rs",
            "tests/proof_documentation_manifest.rs",
            "tests/production_coordinator.rs",
        ),
        "blockers": (
            "euf_cma_reduction_complete requires the total unauthorized-output "
            "classifier and reduction proof to be completed",
            "base_theorem_dependency_bound requires a concrete bound to ML-DSA-65 "
            "EUF-CMA/MLWE/SelfTargetMSIS assumptions",
            "simulator_complete requires a straight-line simulator for concurrent "
            "sessions under the selected corruption model",
            "hybrid_bound_nonvacuous requires concrete loss accounting that remains "
            "meaningful at fixed ML-DSA-65 parameters",
            "subthreshold_forgery_reduction_complete requires a proof that fewer "
            "than 6,667 validators cannot create an accepting aggregate except by a "
            "classified component break",
        ),
    },
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
    return result.stdout.strip() if result.returncode == 0 else None


def current_provenance(root):
    status = run_git(root, ["status", "--porcelain", "--untracked-files=all"])
    return {
        "git_commit": run_git(root, ["rev-parse", "HEAD"]),
        "worktree_clean": status == "" if status is not None else False,
        "changed_paths": (
            sorted(line[3:] for line in status.splitlines() if len(line) > 3)
            if status
            else []
        ),
    }


def file_record(root, relative_path):
    path = Path(root) / relative_path
    if not path.is_file():
        raise FileNotFoundError(f"required context artifact is missing: {relative_path}")
    return {
        "path": relative_path,
        "sha256": BUNDLE.sha256_path(path),
    }


def group_digest(root, records):
    verified = [BUNDLE.verify_declared_artifact(record, root) for record in records]
    digest_material = [
        {"path": item["path"], "sha256": item["observed_sha256"]}
        for item in verified
    ]
    return BUNDLE.sha256_text(BUNDLE.canonical_json(digest_material))


def source_inventory_digest(root):
    inventory = BUNDLE.build_inventory(BUNDLE.default_source_paths(root), root)
    return inventory["tree_sha256"]


def criterion_document(root, criterion_id, generated_at, provenance, source_tree_sha256):
    context = CRITERION_CONTEXT[criterion_id]
    artifact_groups = {
        "protocol_spec_artifacts": [
            file_record(root, path) for path in COMMON_PROTOCOL_SPEC_ARTIFACTS
        ],
        "proof_artifacts": [
            file_record(root, path) for path in context["proof_artifacts"]
        ],
        "implementation_artifacts": [
            file_record(root, path) for path in context["implementation_artifacts"]
        ],
        "test_artifacts": [
            file_record(root, path) for path in context["test_artifacts"]
        ],
    }
    evidence_digests = {
        BUNDLE.ARTIFACT_GROUP_DIGEST_KEYS[group]: group_digest(root, records)
        for group, records in artifact_groups.items()
    }
    blockers = list(context["blockers"]) + [
        "real 24-case 10,000-validator/6,667-threshold campaign capture is not bound",
        "two named internal reviewers have not signed a passing criterion manifest",
        "independent cryptographic review is pending and cannot be self-asserted",
    ]
    return {
        "schema": BUNDLE.CRITERION_EVIDENCE_SCHEMA,
        "schema_version": 1,
        "criterion_id": criterion_id,
        "generated_at": generated_at,
        "evidence_class": "fail_closed_internal_closure_input_requirements",
        "evidence_status": "required_unclosed",
        "assessment_status": "unproven",
        "readiness_only": False,
        "claim_boundary": BUNDLE.CLAIM_BOUNDARY,
        "protocol_profile": BUNDLE.PROTOCOL_PROFILE,
        "substantive_checks": {
            check: False for check in BUNDLE.CRITERION_SUBSTANTIVE_CHECKS[criterion_id]
        },
        "evidence_digests": evidence_digests,
        **artifact_groups,
        "reproducibility": {
            "commands": [],
            "required_commands": [
                "real backend campaign replay",
                "criterion proof reproduction",
                "criterion negative/fault-injection suite",
            ],
        },
        "provenance": {
            "source_class": "fail_closed_requirements_inventory",
            "source_path": DEFAULT_OUT,
            "real_distributed_threshold_core_verified": False,
            "simulation": False,
            "hazmat": False,
            "quarantined": True,
            "git_commit": provenance["git_commit"],
            "worktree_clean": provenance["worktree_clean"],
            "changed_paths": provenance["changed_paths"],
            "source_tree_sha256": source_tree_sha256,
        },
        "internal_review": {
            "completed": False,
            "reviewed_at": None,
            "reviewer_identity_sha256": None,
            "review_digest_sha256": None,
            "independent_review_completed": False,
            "required_internal_reviewer_count": 2,
        },
        "independent_review": {
            "required": True,
            "completed": False,
            "status": "pending_independent_cryptographic_review",
        },
        "claim_flags": {
            "claims_criterion_met": False,
            "claims_substantive_proof_complete": False,
            "claims_independent_review_complete": False,
            "claims_external_validation_complete": False,
        },
        "blockers": blockers,
    }


def build_report(root, generated_at=None):
    root = Path(root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    provenance = current_provenance(root)
    source_tree_sha256 = source_inventory_digest(root)
    criteria = {
        criterion_id: criterion_document(
            root, criterion_id, generated_at, provenance, source_tree_sha256
        )
        for criterion_id, _statement in BUNDLE.CRITERIA
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "input_status": "fail_closed_requirements_generated",
        "selected_profile": BUNDLE.PROTOCOL_PROFILE,
        "criterion_paths": {
            criterion_id: f"{DEFAULT_OUT}/{criterion_id}.json"
            for criterion_id in criteria
        },
        "criteria": {
            criterion_id: {
                "evidence_status": document["evidence_status"],
                "assessment_status": document["assessment_status"],
                "substantive_checks_ready": False,
                "blocker_count": len(document["blockers"]),
            }
            for criterion_id, document in criteria.items()
        },
        "source_tree_sha256": source_tree_sha256,
        "provenance": provenance,
        "claim_flags": {
            "claims_internal_theorem_closure": False,
            "claims_theorem_closure": False,
            "claims_criterion_met": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
        },
        "next_required_artifacts": [
            "real distributed 24-case campaign capture and validation",
            "passing substantive criterion manifests for all five criteria",
            "content-addressed internal closure bundle",
            "two internal reviewer signatures",
            "independent cryptographic review handoff",
        ],
    }
    return {
        "criteria": criteria,
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def render_summary(manifest):
    lines = [
        "# Internal Theorem-Closure Criterion Inputs",
        "",
        f"- Status: `{manifest['input_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Source tree SHA-256: `{manifest['source_tree_sha256']}`",
        "",
        "## Criteria",
        "",
    ]
    for criterion_id, record in manifest["criteria"].items():
        lines.append(
            f"- `{criterion_id}`: `{record['evidence_status']}` "
            f"({record['blocker_count']} blocker(s))"
        )
    lines.extend(["", "## Next Required Artifacts", ""])
    lines.extend(
        f"- {requirement}" for requirement in manifest["next_required_artifacts"]
    )
    lines.extend(
        [
            "",
            "These generated inputs are intentionally fail-closed. They bind current",
            "context for review, but they do not satisfy any theorem criterion.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    contents = {
        "manifest.json": BUNDLE.canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }
    for criterion_id, document in report["criteria"].items():
        contents[f"{criterion_id}.json"] = BUNDLE.canonical_json(document)
    return contents


def render_checksums(contents):
    return "".join(
        f"{BUNDLE.sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )


def write_artifacts(report, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build fail-closed internal theorem-closure criterion inputs"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--out", default=DEFAULT_OUT, help="artifact output directory")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(Path(args.root))
    write_artifacts(report, args.out)
    print(f"wrote internal theorem-closure criterion inputs to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
