import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p1_external_backend_review_packages.py"
ATTEMPT_SCRIPT = ROOT / "scripts" / "run_p1_external_backend_evidence_attempt.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def actual_nonce_gate():
    return {
        "schema": "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "gate_status": "actual_external_capture_ready",
        "actual_external_capture_ready": True,
        "expected_source_profile": "admissible_external_backend_capture",
        "attempt_source_profile": "admissible_external_backend_capture",
        "handoff_source_profile": "admissible_external_backend_capture",
    }


def backend_manifest():
    return {
        "schema_version": 1,
        "claim_boundary": "conformance/proof-review evidence",
        "runner_status": "evidence_present_unclosed",
        "capture_schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "request_schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
        "request_name": "p1-real-threshold-request",
        "request_sha256": "11" * 32,
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "exit_code": 0,
        "validator_count": 10000,
        "threshold": 6667,
        "aggregate_signature_len": 3309,
        "capture_sha256": "22" * 32,
        "backend_core_admissibility": {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "tee_hsm_no_export_threshold_mldsa65_provider",
            "signature_origin": "tee_hsm_no_export_standard_mldsa65_provider",
            "reasons": [],
        },
    }


def backend_capture():
    claim_flags = {
        "claims_theorem_closure": False,
        "claims_rejection_distribution_preservation": False,
        "claims_selected_backend_proof_closure": False,
        "claims_standard_verifier_compatibility": False,
        "claims_production_threshold_mldsa_security": False,
        "claims_cavp_acvts_validation": False,
        "claims_fips_validation": False,
    }
    return {
        "name": "strict-tee-hsm-capture",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "cryptographic_core": {
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": "tee_hsm_no_export_threshold_mldsa65_provider",
            "provider": "ml-dsa crate MlDsa65",
            "signature_origin": "tee_hsm_no_export_standard_mldsa65_provider",
            "validator_count": 10000,
            "threshold": 6667,
            "distributed_threshold_core": {
                "distributed_keygen_vss": False,
                "tee_hsm_no_export_trust_record_reviewed": True,
                "no_single_exposed_mldsa_secret_key": True,
                "threshold_authorization_enforced": True,
                "standard_verifier_compatible_output": True,
                "accepted_aggregate_distribution_proven": False,
            },
            "no_export_custody": {
                "secret_material_exported_to_json": False,
                "raw_seed_exported_to_json": False,
                "expanded_key_exported_to_json": False,
            },
        },
        "backend_requirement_evidence": {
            "threshold_key_material": {
                "validator_count": 10000,
                "threshold": 6667,
                "public_key_count": 1,
                "tee_hsm_trust_record_present": True,
                "single_exposed_mldsa_secret_key_prevented": True,
                "secret_material_exported_to_json": False,
            },
            "distributed_nonce_path": {
                "abort_accountability_records": True,
            },
            "fips204_rejection_loop": {
                "accepted_and_rejected_attempts_recorded": True,
                "claims_rejection_distribution_preservation": False,
            },
            "threshold_vs_centralized_comparison": {
                "claims_theorem_closure": False,
                "claims_rejection_distribution_preservation": False,
            },
        },
        "request": {
            "schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
            "name": "p1-real-threshold-request",
            "request_sha256": "11" * 32,
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": "33" * 32,
            "threshold_output_certificate_digest_hex": "44" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "55" * 32,
        },
        "capture": {
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "public_key_hex": "06" * 1952,
            "message": {"encoding": "hex", "value": "74657374"},
            "aggregate_signature_hex": "2a" * 3309,
            "backend_source_package": {"encoding": "hex", "value": "736f75726365"},
            "backend_implementation": {"encoding": "hex", "value": "696d706c"},
            "backend_transcript": {"encoding": "hex", "value": "7472616e736372697074"},
            "mutated_message_rejected": True,
            "mutated_public_key_rejected": True,
            "mutated_signature_rejected": True,
            "reviewed": True,
        },
        "expected": {
            "backend_evidence_digest_hex": "66" * 32,
            "backend_source_package_digest_hex": "77" * 32,
            "backend_implementation_digest_hex": "88" * 32,
            "backend_transcript_digest_hex": "99" * 32,
            "threshold_core_accounting_digest_hex": "aa" * 32,
            "artifact_digest_hex": "bb" * 32,
            "public_key_digest_hex": "cc" * 32,
            "message_digest_hex": "dd" * 32,
            "accepted_signature_digest_hex": "ee" * 32,
        },
        "claim_flags": claim_flags,
    }


def distributed_dkg_backend_manifest():
    manifest = backend_manifest()
    manifest["backend_core_admissibility"].update(
        {
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "signature_origin": "threshold_partial_aggregation",
        }
    )
    return manifest


def distributed_dkg_backend_capture():
    capture = backend_capture()
    capture["name"] = "strict-distributed-dkg-capture"
    capture["cryptographic_core"].update(
        {
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "provider": "reviewed distributed ML-DSA-65 threshold backend",
            "signature_origin": "threshold_partial_aggregation",
            "distributed_threshold_core": {
                "distributed_keygen_vss": True,
                "no_seed_dealer_dkg": True,
                "receiver_private_share_custody": True,
                "no_single_exposed_mldsa_secret_key": True,
                "threshold_authorization_enforced": True,
                "no_secret_or_seed_reconstruction": True,
                "partial_signing_over_secret_shares": True,
                "partial_z_i_hint_aggregation": True,
                "fips204_rejection_loop_over_threshold_partials": True,
                "standard_verifier_compatible_output": True,
                "accepted_aggregate_distribution_proven": False,
            },
            "no_export_custody": {
                "secret_material_exported_to_json": False,
                "raw_seed_exported_to_json": False,
                "expanded_key_exported_to_json": False,
            },
        }
    )
    capture["backend_requirement_evidence"]["threshold_key_material"].update(
        {
            "threshold_seed_reconstruction_sharing": False,
            "no_seed_dealer_dkg": True,
            "distributed_dkg_vss_transcript_present": True,
            "tee_hsm_trust_record_present": False,
            "single_exposed_mldsa_secret_key_prevented": True,
            "setup_seed_dealer_used_for_research_execution": False,
            "coordinator_reconstructs_seed_for_emitted_signature": False,
            "receiver_private_share_custody": True,
            "per_receiver_private_share_custody": True,
            "secret_material_exported_to_json": False,
        }
    )
    return capture


def rejection_batch():
    return {
        "schema": "lattice-aggregation:p1-rejection-equivalence-batch:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "parameters": {
            "validator_count": 10000,
            "threshold": 6667,
            "nonce_prf_producer": "distributed-nonce-prf-output-shares",
            "reviewed_distributed_nonce_producer_present": True,
            "distributed_nonce_producer_artifact_digest": "99" * 32,
        },
        "result": {
            "predicate_mismatch_count": 0,
            "challenge_digest_matches": True,
            "accepted_or_rejected_matches": True,
            "saw_threshold_rejected_attempt": True,
            "saw_threshold_accepted_attempt": True,
            "standard_verifier_accepts_threshold_signature": True,
            "repo_provider_accepts_threshold_signature": True,
            "close_candidate": True,
        },
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_rejection_distribution_preservation": False,
        },
    }


class P1ExternalBackendReviewPackageBuilderTests(unittest.TestCase):
    def test_builds_review_packages_that_make_external_attempt_close_candidate(self):
        builder = load_module(SCRIPT, "build_p1_external_backend_review_packages")
        attempt = load_module(ATTEMPT_SCRIPT, "run_p1_external_backend_evidence_attempt")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_path = root / "rejection" / "batch.json"
            dkg_out = root / "dkg"
            distribution_out = root / "distribution"
            review_out = root / "review"
            candidate_out = root / "candidate"
            attempt_out = root / "attempt"
            write_json(nonce_path, actual_nonce_gate())
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_path, rejection_batch())

            report = builder.build_packages(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_path,
                dkg_out=dkg_out,
                distribution_abort_out=distribution_out,
                review_package_out=review_out,
                candidate_out=candidate_out,
                generated_at="2026-07-07T00:00:00Z",
            )
            attempt_report = attempt.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_path,
                dkg_review_path=dkg_out / "manifest.json",
                distribution_abort_review_path=distribution_out / "manifest.json",
                review_package_path=review_out / "manifest.json",
                candidate_out=candidate_out,
                generated_at="2026-07-07T00:00:00Z",
            )
            attempt.write_artifacts(attempt_report, attempt_out)

        self.assertEqual(
            report["production_dkg_no_single_secret_review"]["review_status"],
            "reviewed_production_dkg_no_single_secret_ready",
        )
        self.assertEqual(
            report["accepted_distribution_abort_review"]["review_status"],
            "reviewed_distribution_abort_ready",
        )
        self.assertEqual(
            attempt_report["manifest"]["attempt_status"],
            "external_evidence_close_candidate_ready",
        )
        self.assertTrue(attempt_report["manifest"]["close_candidate"])
        self.assertFalse(attempt_report["manifest"]["claims_theorem_closure"])

    def test_blocks_dkg_review_when_strict_no_export_evidence_is_missing(self):
        builder = load_module(SCRIPT, "build_p1_external_backend_review_packages")
        manifest = backend_manifest()
        capture = backend_capture()
        capture["cryptographic_core"]["no_export_custody"][
            "secret_material_exported_to_json"
        ] = True

        review = builder.build_dkg_review(
            manifest,
            capture,
            "reviewer",
            "2026-07-07T00:00:00Z",
        )

        self.assertEqual(
            review["review_status"],
            "blocked_production_dkg_no_single_secret_review",
        )
        self.assertIn("secret_material_not_exported", review["blockers"])

    def test_distributed_dkg_route_requires_no_seed_dealer_and_private_custody(self):
        builder = load_module(SCRIPT, "build_p1_external_backend_review_packages")
        review = builder.build_dkg_review(
            distributed_dkg_backend_manifest(),
            distributed_dkg_backend_capture(),
            "reviewer",
            "2026-07-07T00:00:00Z",
        )

        self.assertEqual(review["setup_route"], "distributed_dkg_vss")
        self.assertEqual(
            review["review_status"],
            "reviewed_production_dkg_no_single_secret_ready",
        )
        self.assertTrue(review["checks"]["distributed_dkg_vss_reviewed"])
        self.assertTrue(review["checks"]["no_seed_dealer_dkg_reviewed"])
        self.assertTrue(review["checks"]["receiver_private_share_custody_reviewed"])
        self.assertTrue(review["checks"]["no_secret_or_seed_reconstruction_reviewed"])

    def test_distributed_dkg_route_blocks_seed_dealer_research_setup(self):
        builder = load_module(SCRIPT, "build_p1_external_backend_review_packages")
        capture = distributed_dkg_backend_capture()
        capture["backend_requirement_evidence"]["threshold_key_material"][
            "setup_seed_dealer_used_for_research_execution"
        ] = True

        review = builder.build_dkg_review(
            distributed_dkg_backend_manifest(),
            capture,
            "reviewer",
            "2026-07-07T00:00:00Z",
        )

        self.assertEqual(review["setup_route"], "distributed_dkg_vss")
        self.assertEqual(
            review["review_status"],
            "blocked_production_dkg_no_single_secret_review",
        )
        self.assertIn("no_seed_dealer_dkg_reviewed", review["blockers"])


if __name__ == "__main__":
    unittest.main()
