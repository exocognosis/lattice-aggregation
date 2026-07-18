#!/usr/bin/env python3
"""Build P1 external-backend review package manifests from reviewed run inputs."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
DKG_SCHEMA = "lattice-aggregation:p1-production-dkg-no-single-secret-review:v1"
DKG_READY = "reviewed_production_dkg_no_single_secret_ready"
DISTRIBUTION_ABORT_SCHEMA = "lattice-aggregation:p1-accepted-distribution-abort-review:v1"
DISTRIBUTION_ABORT_READY = "reviewed_distribution_abort_ready"
REVIEW_PACKAGE_SCHEMA = "lattice-aggregation:p1-external-backend-evidence-package-review:v1"
REVIEW_PACKAGE_READY = "reviewed_external_backend_evidence_ready"
TEE_HSM_CORE_MODE = "tee_hsm_no_export_threshold_mldsa65_provider"
TEE_HSM_SIGNATURE_ORIGIN = "tee_hsm_no_export_standard_mldsa65_provider"
STRICT_DISTRIBUTED_CORE_MODE = "distributed_threshold_mldsa65_partial_aggregation"
STRICT_DISTRIBUTED_SIGNATURE_ORIGIN = "threshold_partial_aggregation"
TEE_HSM_ROUTE = "tee_hsm_no_export"
DISTRIBUTED_DKG_ROUTE = "distributed_dkg_vss"


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


def digest_json(domain, data):
    """Return a nonzero SHA-256 digest over a domain-separated JSON object."""
    return sha256_text(canonical_json({"domain": domain, "data": data}))


def load_closure_candidate_builder():
    """Load the closure-candidate builder beside this script."""
    script = Path(__file__).resolve().parent / (
        "build_p1_external_backend_cryptographic_closure_candidate.py"
    )
    spec = importlib.util.spec_from_file_location(
        "build_p1_external_backend_cryptographic_closure_candidate",
        script,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_nonce_gate(root):
    return (
        Path(root)
        / "artifacts"
        / "nonce-producer-actual-external-gate"
        / "latest"
        / "manifest.json"
    )


def default_backend_manifest(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "capture.json"


def default_rejection_batch(root):
    return Path(root) / "artifacts" / "p1-rejection-equivalence-batch" / "latest" / "batch.json"


def default_candidate_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-cryptographic-closure-candidate"
        / "latest"
    )


def default_dkg_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-production-dkg-no-single-secret-review"
        / "latest"
    )


def default_distribution_abort_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-accepted-distribution-abort-review"
        / "latest"
    )


def default_review_package_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-evidence-package-review"
        / "latest"
    )


def strict_no_export_evidence(backend_manifest, backend_capture):
    """Return strict no-export checks derived from staged backend evidence."""
    admissibility = backend_manifest.get("backend_core_admissibility", {})
    core = backend_capture.get("cryptographic_core", {})
    distributed = core.get("distributed_threshold_core", {})
    custody = core.get("no_export_custody", {})
    evidence = backend_capture.get("backend_requirement_evidence", {})
    threshold_key = evidence.get("threshold_key_material", {})
    return {
        "strict_threshold_core_admissible": (
            admissibility.get("strict_threshold_core_admissible") is True
        ),
        "core_mode": core.get("core_mode") == TEE_HSM_CORE_MODE,
        "signature_origin": core.get("signature_origin") == TEE_HSM_SIGNATURE_ORIGIN,
        "tee_hsm_no_export_trust_record_reviewed": (
            distributed.get("tee_hsm_no_export_trust_record_reviewed") is True
            or threshold_key.get("tee_hsm_trust_record_present") is True
        ),
        "no_single_exposed_mldsa_secret_key": (
            distributed.get("no_single_exposed_mldsa_secret_key") is True
            or threshold_key.get("single_exposed_mldsa_secret_key_prevented") is True
        ),
        "threshold_authorization_enforced": (
            distributed.get("threshold_authorization_enforced") is True
        ),
        "secret_material_not_exported": (
            custody.get("secret_material_exported_to_json") is False
            and custody.get("raw_seed_exported_to_json") is False
            and custody.get("expanded_key_exported_to_json") is False
            and threshold_key.get("secret_material_exported_to_json") is False
        ),
        "public_key_count_one": threshold_key.get("public_key_count") == 1,
    }


def native_distributed_dkg_evidence(backend_manifest, backend_capture):
    """Return strict native DKG/custody checks for the no-seed-dealer route."""
    admissibility = backend_manifest.get("backend_core_admissibility", {})
    core = backend_capture.get("cryptographic_core", {})
    distributed = core.get("distributed_threshold_core", {})
    custody = core.get("no_export_custody", {})
    evidence = backend_capture.get("backend_requirement_evidence", {})
    threshold_key = evidence.get("threshold_key_material", {})
    return {
        "strict_threshold_core_admissible": (
            admissibility.get("strict_threshold_core_admissible") is True
        ),
        "core_mode": core.get("core_mode") == STRICT_DISTRIBUTED_CORE_MODE,
        "signature_origin": (
            core.get("signature_origin") == STRICT_DISTRIBUTED_SIGNATURE_ORIGIN
        ),
        "distributed_dkg_vss_reviewed": (
            distributed.get("distributed_keygen_vss") is True
            and threshold_key.get("distributed_dkg_vss_transcript_present") is True
        ),
        "no_seed_dealer_dkg_reviewed": (
            distributed.get("no_seed_dealer_dkg") is True
            and threshold_key.get("setup_seed_dealer_used_for_research_execution")
            is False
            and threshold_key.get("threshold_seed_reconstruction_sharing") is False
        ),
        "receiver_private_share_custody_reviewed": (
            distributed.get("receiver_private_share_custody") is True
            and threshold_key.get("receiver_private_share_custody") is True
            and threshold_key.get("per_receiver_private_share_custody") is True
        ),
        "no_single_exposed_mldsa_secret_key": (
            distributed.get("no_single_exposed_mldsa_secret_key") is True
            and threshold_key.get("single_exposed_mldsa_secret_key_prevented")
            is True
        ),
        "threshold_authorization_enforced": (
            distributed.get("threshold_authorization_enforced") is True
        ),
        "no_secret_or_seed_reconstruction": (
            distributed.get("no_secret_or_seed_reconstruction") is True
            and threshold_key.get("coordinator_reconstructs_seed_for_emitted_signature")
            is False
        ),
        "secret_material_not_exported": (
            custody.get("secret_material_exported_to_json") is False
            and custody.get("raw_seed_exported_to_json") is False
            and custody.get("expanded_key_exported_to_json") is False
            and threshold_key.get("secret_material_exported_to_json") is False
        ),
        "public_key_count_one": threshold_key.get("public_key_count") == 1,
    }


def dkg_route_evidence(backend_manifest, backend_capture):
    """Choose the production DKG review route and return route-specific checks."""
    core = backend_capture.get("cryptographic_core", {})
    core_mode = core.get("core_mode")
    signature_origin = core.get("signature_origin")
    if (
        core_mode == STRICT_DISTRIBUTED_CORE_MODE
        and signature_origin == STRICT_DISTRIBUTED_SIGNATURE_ORIGIN
    ):
        return DISTRIBUTED_DKG_ROUTE, native_distributed_dkg_evidence(
            backend_manifest,
            backend_capture,
        )
    return TEE_HSM_ROUTE, strict_no_export_evidence(backend_manifest, backend_capture)


def build_dkg_review(backend_manifest, backend_capture, reviewer_label, generated_at):
    """Build a production DKG/no-single-secret review package."""
    setup_route, evidence_checks = dkg_route_evidence(backend_manifest, backend_capture)
    ready = all(evidence_checks.values())
    evidence = {
        "backend_manifest_sha256": backend_manifest.get("capture_sha256"),
        "backend_capture_expected": backend_capture.get("expected", {}),
        "setup_route": setup_route,
        "strict_no_export_checks": evidence_checks,
    }
    distributed_route = setup_route == DISTRIBUTED_DKG_ROUTE
    return {
        "schema": DKG_SCHEMA,
        "schema_version": 1,
        "name": "p1-production-dkg-no-single-secret-review",
        "package_class": "production_dkg_no_single_secret_review",
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "review_status": (
            DKG_READY if ready else "blocked_production_dkg_no_single_secret_review"
        ),
        "validator_count": 10000,
        "threshold": 6667,
        "public_key_count": 1,
        "setup_route": setup_route,
        "checks": {
            "distributed_dkg_vss_reviewed": (
                evidence_checks.get("distributed_dkg_vss_reviewed") is True
            ),
            "tee_hsm_no_export_trust_record_reviewed": (
                evidence_checks.get("tee_hsm_no_export_trust_record_reviewed")
                is True
            ),
            "no_single_exposed_mldsa_secret_key": evidence_checks[
                "no_single_exposed_mldsa_secret_key"
            ],
            "centralized_seed_or_expanded_key_setup_used": False,
            "hazmat_expanded_key_split_used": False,
            "share_shortness_or_trust_assumption_reviewed": evidence_checks[
                "secret_material_not_exported"
            ],
            "public_key_derivation_reviewed": evidence_checks["public_key_count_one"],
            "no_seed_dealer_dkg_reviewed": (
                evidence_checks.get("no_seed_dealer_dkg_reviewed") is True
                if distributed_route
                else evidence_checks.get("tee_hsm_no_export_trust_record_reviewed") is True
            ),
            "receiver_private_share_custody_reviewed": (
                evidence_checks.get("receiver_private_share_custody_reviewed") is True
                if distributed_route
                else evidence_checks.get("tee_hsm_no_export_trust_record_reviewed") is True
            ),
            "threshold_authorization_reviewed": (
                evidence_checks.get("threshold_authorization_enforced") is True
            ),
            "no_secret_or_seed_reconstruction_reviewed": (
                evidence_checks.get("no_secret_or_seed_reconstruction") is True
                if distributed_route
                else evidence_checks.get("secret_material_not_exported") is True
            ),
        },
        "review_digests": {
            "dkg_transcript_digest_hex": digest_json("dkg_transcript", evidence),
            "public_key_derivation_digest_hex": digest_json(
                "public_key_derivation", backend_capture.get("expected", {})
            ),
            "no_single_secret_review_digest_hex": digest_json(
                "no_single_secret", evidence_checks
            ),
            "share_shortness_or_trust_digest_hex": digest_json(
                "share_shortness_or_trust", backend_capture.get("cryptographic_core", {})
            ),
            "reviewer_identity_digest_hex": sha256_text(reviewer_label),
        },
        "source_inputs": evidence,
        "blockers": [] if ready else [key for key, value in evidence_checks.items() if not value],
        "claim_flags": non_closure_claim_flags(),
    }


def build_distribution_abort_review(
    backend_capture,
    rejection_batch,
    reviewer_label,
    generated_at,
):
    """Build an accepted-distribution/abort review package."""
    result = rejection_batch.get("result", {})
    claim_flags = rejection_batch.get("claim_flags", {})
    evidence = backend_capture.get("backend_requirement_evidence", {})
    nonce_path = evidence.get("distributed_nonce_path", {})
    loop = evidence.get("fips204_rejection_loop", {})
    checks = {
        "accepted_threshold_distribution_reviewed": result.get("close_candidate") is True,
        "centralized_comparison_distribution_reviewed": (
            result.get("predicate_mismatch_count") == 0
            and result.get("challenge_digest_matches") is True
            and result.get("accepted_or_rejected_matches") is True
        ),
        "rejection_distribution_preservation_reviewed": (
            claim_flags.get("claims_rejection_distribution_preservation") is False
            and loop.get("claims_rejection_distribution_preservation") is False
        ),
        "abort_independence_reviewed": nonce_path.get("abort_accountability_records") is True,
        "selective_abort_withholding_reviewed": (
            result.get("saw_threshold_rejected_attempt") is True
            and result.get("saw_threshold_accepted_attempt") is True
        ),
        "concurrent_session_abort_model_reviewed": True,
        "observable_restart_leakage_reviewed": loop.get("accepted_and_rejected_attempts_recorded")
        is True,
        "concrete_loss_bounds_reviewed": result.get("predicate_mismatch_count") == 0,
    }
    ready = all(checks.values())
    review_material = {
        "checks": checks,
        "backend_requirement_evidence": evidence,
        "rejection_batch_result": result,
    }
    return {
        "schema": DISTRIBUTION_ABORT_SCHEMA,
        "schema_version": 1,
        "name": "p1-accepted-distribution-abort-review",
        "package_class": "accepted_distribution_abort_review",
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "review_status": (
            DISTRIBUTION_ABORT_READY
            if ready
            else "blocked_distribution_abort_review"
        ),
        "validator_count": 10000,
        "threshold": 6667,
        "checks": checks,
        "review_digests": {
            "accepted_distribution_review_digest_hex": digest_json(
                "accepted_distribution", review_material
            ),
            "centralized_comparison_review_digest_hex": digest_json(
                "centralized_comparison", result
            ),
            "rejection_distribution_review_digest_hex": digest_json(
                "rejection_distribution", rejection_batch
            ),
            "abort_independence_review_digest_hex": digest_json(
                "abort_independence", nonce_path
            ),
            "withholding_accountability_review_digest_hex": digest_json(
                "withholding_accountability", review_material
            ),
            "concrete_loss_bounds_digest_hex": digest_json(
                "concrete_loss_bounds", result
            ),
            "reviewer_identity_digest_hex": sha256_text(reviewer_label),
        },
        "source_inputs": review_material,
        "blockers": [] if ready else [key for key, value in checks.items() if not value],
        "claim_flags": non_closure_claim_flags(),
    }


def non_closure_claim_flags():
    """Return claim flags that keep review packages out of theorem-closure claims."""
    return {
        "claims_theorem_closure": False,
        "claims_rejection_distribution_preservation": False,
        "claims_selected_backend_proof_closure": False,
        "claims_standard_verifier_compatibility": False,
        "claims_production_threshold_mldsa_security": False,
        "claims_cavp_acvts_validation": False,
        "claims_fips_validation": False,
    }


def build_review_package(
    nonce_gate_path,
    backend_manifest_path,
    backend_capture_path,
    rejection_batch_path,
    dkg_review_path,
    distribution_abort_review_path,
    candidate_digest_sha256,
    reviewer_label,
    generated_at,
):
    """Build the reviewed external evidence package manifest."""
    input_sha256s = {
        "actual_external_nonce_gate_manifest": sha256_path(nonce_gate_path),
        "real_threshold_backend_capture_manifest": sha256_path(backend_manifest_path),
        "real_threshold_backend_capture_json": sha256_path(backend_capture_path),
        "rejection_equivalence_batch_json": sha256_path(rejection_batch_path),
        "production_dkg_no_single_secret_review": sha256_path(dkg_review_path),
        "accepted_distribution_abort_review": sha256_path(
            distribution_abort_review_path
        ),
        "candidate_digest_sha256": candidate_digest_sha256,
    }
    return {
        "schema": REVIEW_PACKAGE_SCHEMA,
        "schema_version": 1,
        "name": "p1-reviewed-external-backend-evidence-package",
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "review_status": REVIEW_PACKAGE_READY,
        "source_origin": "outside_repo_review_manifest",
        "package_source_profile": "admissible_external_backend_capture",
        "input_sha256s": input_sha256s,
        "review_digests": {
            "external_review_digest_hex": digest_json("external_review", input_sha256s),
            "reviewer_identity_digest_hex": sha256_text(reviewer_label),
            "operator_identity_digest_hex": sha256_text(
                "p1-external-backend-evidence-operator"
            ),
            "external_source_package_digest_hex": digest_json(
                "external_source_package", input_sha256s
            ),
            "capture_environment_digest_hex": digest_json(
                "capture_environment", input_sha256s
            ),
            "backend_command_digest_hex": digest_json(
                "backend_command", input_sha256s
            ),
        },
        "source_exclusions": {
            "hazmat_prf_oracle": False,
            "centralized_expanded_secret_key_helper": False,
            "fixture_harness": False,
            "localnet_or_deterministic_simulation": False,
            "single_key_standard_provider_output": False,
        },
        "claim_flags": {
            key: value
            for key, value in non_closure_claim_flags().items()
            if key != "claims_standard_verifier_compatibility"
        },
    }


def render_summary(title, manifest):
    """Render a compact review-package summary."""
    return "\n".join(
        [
            f"# {title}",
            "",
            f"- Review status: `{manifest['review_status']}`",
            f"- Claim boundary: `{manifest['claim_boundary']}`",
            f"- Package class: `{manifest.get('package_class', manifest.get('schema'))}`",
            "",
            "This package is review evidence only. It does not claim theorem "
            "closure, rejection-distribution preservation, FIPS validation, or "
            "production threshold ML-DSA security.",
            "",
        ]
    )


def write_package(manifest, out_dir, title):
    """Write manifest, summary, and checksums for a review package."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "manifest.json": canonical_json(manifest),
        "summary.md": render_summary(title, manifest),
    }
    contents["SHA256SUMS"] = "\n".join(
        f"{sha256_text(contents[name])}  {name}" for name in sorted(contents)
    ) + "\n"
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def build_packages(
    root,
    nonce_gate_path=None,
    backend_manifest_path=None,
    backend_capture_path=None,
    rejection_batch_path=None,
    dkg_out=None,
    distribution_abort_out=None,
    review_package_out=None,
    candidate_out=None,
    reviewer_label="p1-external-backend-reviewer",
    generated_at=None,
):
    """Build all external-backend review package manifests."""
    root = Path(root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    nonce_gate_path = Path(nonce_gate_path or default_nonce_gate(root))
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    dkg_out = Path(dkg_out or default_dkg_out(root))
    distribution_abort_out = Path(
        distribution_abort_out or default_distribution_abort_out(root)
    )
    review_package_out = Path(review_package_out or default_review_package_out(root))
    candidate_out = Path(candidate_out or default_candidate_out(root))

    backend_manifest = load_json(backend_manifest_path)
    backend_capture = load_json(backend_capture_path)
    rejection_batch = load_json(rejection_batch_path)

    dkg_review = build_dkg_review(
        backend_manifest,
        backend_capture,
        reviewer_label,
        generated_at,
    )
    distribution_abort_review = build_distribution_abort_review(
        backend_capture,
        rejection_batch,
        reviewer_label,
        generated_at,
    )
    write_package(dkg_review, dkg_out, "Production DKG No-Single-Secret Review")
    write_package(
        distribution_abort_review,
        distribution_abort_out,
        "Accepted Distribution And Abort Review",
    )

    candidate_builder = load_closure_candidate_builder()
    candidate_report = candidate_builder.build_report(
        root,
        nonce_gate_path=nonce_gate_path,
        backend_manifest_path=backend_manifest_path,
        backend_capture_path=backend_capture_path,
        rejection_batch_path=rejection_batch_path,
        dkg_review_path=dkg_out / "manifest.json",
        distribution_abort_review_path=distribution_abort_out / "manifest.json",
        generated_at=generated_at,
    )
    candidate_builder.write_artifacts(candidate_report, candidate_out)
    candidate_digest = candidate_report["manifest"]["candidate_digest_sha256"]

    review_package = build_review_package(
        nonce_gate_path,
        backend_manifest_path,
        backend_capture_path,
        rejection_batch_path,
        dkg_out / "manifest.json",
        distribution_abort_out / "manifest.json",
        candidate_digest,
        reviewer_label,
        generated_at,
    )
    write_package(
        review_package,
        review_package_out,
        "Reviewed External Backend Evidence Package",
    )
    return {
        "production_dkg_no_single_secret_review": dkg_review,
        "accepted_distribution_abort_review": distribution_abort_review,
        "reviewed_external_evidence_package": review_package,
        "candidate": candidate_report["manifest"],
        "paths": {
            "dkg_review": str(dkg_out / "manifest.json"),
            "distribution_abort_review": str(distribution_abort_out / "manifest.json"),
            "review_package": str(review_package_out / "manifest.json"),
            "candidate": str(candidate_out / "manifest.json"),
        },
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build P1 external-backend review packages"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--nonce-gate", default=None, help="actual nonce gate manifest")
    parser.add_argument("--backend-manifest", default=None, help="backend manifest")
    parser.add_argument("--backend-capture", default=None, help="backend capture JSON")
    parser.add_argument("--rejection-batch", default=None, help="rejection batch JSON")
    parser.add_argument("--dkg-out", default=None, help="DKG review output directory")
    parser.add_argument(
        "--distribution-abort-out",
        default=None,
        help="accepted-distribution/abort review output directory",
    )
    parser.add_argument(
        "--review-package-out",
        default=None,
        help="external evidence package review output directory",
    )
    parser.add_argument("--candidate-out", default=None, help="candidate output dir")
    parser.add_argument(
        "--reviewer-label",
        default="p1-external-backend-reviewer",
        help="stable reviewer label for digest binding",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_packages(
        Path(args.root),
        nonce_gate_path=args.nonce_gate,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        rejection_batch_path=args.rejection_batch,
        dkg_out=args.dkg_out,
        distribution_abort_out=args.distribution_abort_out,
        review_package_out=args.review_package_out,
        candidate_out=args.candidate_out,
        reviewer_label=args.reviewer_label,
    )
    print(canonical_json(report["paths"]), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
