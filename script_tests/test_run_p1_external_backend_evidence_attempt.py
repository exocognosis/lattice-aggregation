import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_p1_external_backend_evidence_attempt.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "run_p1_external_backend_evidence_attempt",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def actual_nonce_gate(ready=True):
    return {
        "schema": "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "gate_status": (
            "actual_external_capture_ready"
            if ready
            else "actual_external_capture_missing"
        ),
        "actual_external_capture_ready": ready,
        "expected_source_profile": "admissible_external_backend_capture",
        "attempt_source_profile": (
            "admissible_external_backend_capture"
            if ready
            else "repo_reference_cli_capture"
        ),
        "handoff_source_profile": (
            "admissible_external_backend_capture"
            if ready
            else "repo_reference_cli_capture"
        ),
        "blockers": [] if ready else ["actual external capture missing"],
    }


def backend_manifest():
    return {
        "schema_version": 1,
        "claim_boundary": "conformance/proof-review evidence",
        "runner_status": "evidence_present_unclosed",
        "capture_schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "request_schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
        "request_name": "batch8-real-threshold-request",
        "request_sha256": "11" * 32,
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "backend_command": ["/opt/threshold-backend", "emit-capture"],
        "exit_code": 0,
        "validator_count": 10000,
        "threshold": 6667,
        "aggregate_signature_len": 3309,
        "capture_sha256": "22" * 32,
        "backend_core_admissibility": {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "signature_origin": "threshold_partial_aggregation",
            "reasons": [],
        },
        "external_capture_provenance": {
            "schema": "lattice-aggregation:external-capture-provenance:v1",
            "runner_status": "evidence_present_unclosed",
        },
    }


def backend_capture():
    return {
        "name": "batch8-real-threshold-capture",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "cryptographic_core": {
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "provider": None,
            "signature_origin": "threshold_partial_aggregation",
            "validator_count": 10000,
            "threshold": 6667,
            "distributed_threshold_core": {
                "distributed_keygen_vss": True,
                "partial_signing_over_secret_shares": True,
                "partial_z_i_hint_aggregation": True,
                "fips204_rejection_loop_over_threshold_partials": True,
                "accepted_aggregate_distribution_proven": False,
            },
        },
        "request": {
            "schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
            "name": "batch8-real-threshold-request",
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
            "artifact_digest_hex": "aa" * 32,
            "public_key_digest_hex": "bb" * 32,
            "message_digest_hex": "cc" * 32,
            "accepted_signature_digest_hex": "dd" * 32,
        },
    }


def mark_as_threshold_seed_reconstruction(manifest, capture):
    manifest["backend_core_admissibility"].update(
        {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "threshold_seed_reconstruction_mldsa65_provider",
            "signature_origin": (
                "threshold_seed_reconstruction_standard_mldsa65_provider"
            ),
            "reasons": [],
        }
    )
    capture["cryptographic_core"].update(
        {
            "core_mode": "threshold_seed_reconstruction_mldsa65_provider",
            "signature_origin": (
                "threshold_seed_reconstruction_standard_mldsa65_provider"
            ),
        }
    )


def mark_as_tee_hsm_no_export(manifest, capture):
    manifest["backend_core_admissibility"].update(
        {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "tee_hsm_no_export_threshold_mldsa65_provider",
            "signature_origin": "tee_hsm_no_export_standard_mldsa65_provider",
            "reasons": [],
        }
    )
    capture["cryptographic_core"].update(
        {
            "core_mode": "tee_hsm_no_export_threshold_mldsa65_provider",
            "provider": "tee-hsm-no-export mldsa65 provider",
            "signature_origin": "tee_hsm_no_export_standard_mldsa65_provider",
            "distributed_threshold_core": {
                "distributed_keygen_vss": False,
                "tee_hsm_no_export_trust_record_reviewed": True,
                "no_single_exposed_mldsa_secret_key": True,
                "threshold_authorization_enforced": True,
                "standard_verifier_compatible_output": True,
                "accepted_aggregate_distribution_proven": False,
            },
        }
    )


def rejection_batch(close_candidate=True):
    return {
        "name": "batch8-rejection-equivalence-batch",
        "schema": "lattice-aggregation:p1-rejection-equivalence-batch:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "mldsa65-centralized-vs-threshold-rejection-batch",
        "parameters": {
            "validator_count": 10000,
            "threshold": 6667,
            "attempts": 16,
            "nonce_prf_producer": "distributed-nonce-prf-output-shares",
            "reviewed_distributed_nonce_producer_present": True,
            "distributed_nonce_producer_artifact_digest": "ee" * 32,
        },
        "result": {
            "predicate_mismatch_count": 0,
            "challenge_digest_matches": True,
            "accepted_or_rejected_matches": True,
            "saw_threshold_rejected_attempt": True,
            "saw_threshold_accepted_attempt": True,
            "standard_verifier_accepts_threshold_signature": True,
            "repo_provider_accepts_threshold_signature": True,
            "close_candidate": close_candidate,
        },
        "predicate_mismatches": [],
        "claim_flags": {
            "claims_rejection_distribution_preservation": False,
            "claims_theorem_closure": False,
        },
    }


def dkg_no_single_secret_review():
    return {
        "schema": "lattice-aggregation:p1-production-dkg-no-single-secret-review:v1",
        "name": "batch8-production-dkg-no-single-secret-review",
        "package_class": "production_dkg_no_single_secret_review",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "reviewed_production_dkg_no_single_secret_ready",
        "validator_count": 10000,
        "threshold": 6667,
        "public_key_count": 1,
        "setup_route": "tee_hsm_no_export",
        "checks": {
            "distributed_dkg_vss_reviewed": False,
            "tee_hsm_no_export_trust_record_reviewed": True,
            "no_single_exposed_mldsa_secret_key": True,
            "centralized_seed_or_expanded_key_setup_used": False,
            "hazmat_expanded_key_split_used": False,
            "share_shortness_or_trust_assumption_reviewed": True,
            "public_key_derivation_reviewed": True,
        },
        "review_digests": {
            "dkg_transcript_digest_hex": "10" * 32,
            "public_key_derivation_digest_hex": "20" * 32,
            "no_single_secret_review_digest_hex": "30" * 32,
            "share_shortness_or_trust_digest_hex": "40" * 32,
            "reviewer_identity_digest_hex": "50" * 32,
        },
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_rejection_distribution_preservation": False,
            "claims_selected_backend_proof_closure": False,
            "claims_standard_verifier_compatibility": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
        },
    }


def tee_hsm_no_export_review():
    review = dkg_no_single_secret_review()
    review["setup_route"] = "tee_hsm_no_export"
    review["checks"]["distributed_dkg_vss_reviewed"] = False
    review["checks"]["tee_hsm_no_export_trust_record_reviewed"] = True
    return review


def distribution_abort_review():
    return {
        "schema": "lattice-aggregation:p1-accepted-distribution-abort-review:v1",
        "name": "batch8-accepted-distribution-abort-review",
        "package_class": "accepted_distribution_abort_review",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "reviewed_distribution_abort_ready",
        "validator_count": 10000,
        "threshold": 6667,
        "checks": {
            "accepted_threshold_distribution_reviewed": True,
            "centralized_comparison_distribution_reviewed": True,
            "rejection_distribution_preservation_reviewed": True,
            "abort_independence_reviewed": True,
            "selective_abort_withholding_reviewed": True,
            "concurrent_session_abort_model_reviewed": True,
            "observable_restart_leakage_reviewed": True,
            "concrete_loss_bounds_reviewed": True,
        },
        "review_digests": {
            "accepted_distribution_review_digest_hex": "60" * 32,
            "centralized_comparison_review_digest_hex": "70" * 32,
            "rejection_distribution_review_digest_hex": "80" * 32,
            "abort_independence_review_digest_hex": "90" * 32,
            "withholding_accountability_review_digest_hex": "a0" * 32,
            "concrete_loss_bounds_digest_hex": "b0" * 32,
            "reviewer_identity_digest_hex": "c0" * 32,
        },
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_rejection_distribution_preservation": False,
            "claims_selected_backend_proof_closure": False,
            "claims_standard_verifier_compatibility": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
        },
    }


def reviewed_external_evidence_package(
    module,
    nonce_path,
    backend_manifest_path,
    backend_capture_path,
    rejection_batch_path,
    dkg_review_path,
    distribution_abort_review_path,
    candidate_digest_sha256,
):
    return {
        "schema": "lattice-aggregation:p1-external-backend-evidence-package-review:v1",
        "name": "batch9-reviewed-external-evidence-package",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "reviewed_external_backend_evidence_ready",
        "source_origin": "outside_repo_review_manifest",
        "package_source_profile": "admissible_external_backend_capture",
        "input_sha256s": {
            "actual_external_nonce_gate_manifest": module.sha256_path(nonce_path),
            "real_threshold_backend_capture_manifest": module.sha256_path(
                backend_manifest_path
            ),
            "real_threshold_backend_capture_json": module.sha256_path(
                backend_capture_path
            ),
            "rejection_equivalence_batch_json": module.sha256_path(
                rejection_batch_path
            ),
            "production_dkg_no_single_secret_review": module.sha256_path(
                dkg_review_path
            ),
            "accepted_distribution_abort_review": module.sha256_path(
                distribution_abort_review_path
            ),
            "candidate_digest_sha256": candidate_digest_sha256,
        },
        "review_digests": {
            "external_review_digest_hex": "12" * 32,
            "reviewer_identity_digest_hex": "34" * 32,
            "operator_identity_digest_hex": "56" * 32,
            "external_source_package_digest_hex": "78" * 32,
            "capture_environment_digest_hex": "9a" * 32,
            "backend_command_digest_hex": "bc" * 32,
        },
        "source_exclusions": {
            "hazmat_prf_oracle": False,
            "centralized_expanded_secret_key_helper": False,
            "fixture_harness": False,
            "localnet_or_deterministic_simulation": False,
            "single_key_standard_provider_output": False,
        },
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_rejection_distribution_preservation": False,
            "claims_selected_backend_proof_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
        },
    }


def build_candidate_digest(
    module,
    root,
    nonce_path,
    backend_manifest_path,
    backend_capture_path,
    rejection_batch_path,
    dkg_review_path,
    distribution_abort_review_path,
):
    candidate_builder = module.load_closure_candidate_builder()
    candidate_report = candidate_builder.build_report(
        root,
        nonce_gate_path=nonce_path,
        backend_manifest_path=backend_manifest_path,
        backend_capture_path=backend_capture_path,
        rejection_batch_path=rejection_batch_path,
        dkg_review_path=dkg_review_path,
        distribution_abort_review_path=distribution_abort_review_path,
        generated_at="2026-07-04T00:00:00Z",
    )
    return candidate_report["manifest"]["candidate_digest_sha256"]


class P1ExternalBackendEvidenceAttemptTests(unittest.TestCase):
    def test_missing_external_inputs_write_blocked_attempt_and_candidate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            report = module.build_report(root, generated_at="2026-07-04T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
        )
        self.assertEqual(manifest["attempt_status"], "blocked_external_evidence_missing")
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["claims_theorem_closure"])
        self.assertFalse(manifest["claims_rejection_distribution_preservation"])
        self.assertFalse(manifest["checks"]["strict_external_nonce_capture_ready"])
        self.assertFalse(manifest["checks"]["real_threshold_emission_present"])
        self.assertFalse(manifest["checks"]["rejection_distribution_comparison_present"])
        self.assertIn("actual external nonce capture", " ".join(manifest["blockers"]))
        self.assertIn("pending theorem-closure review", report["summary_md"])

    def test_complete_external_bundle_without_review_package_remains_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            dkg_review_path = root / "dkg-review" / "manifest.json"
            distribution_abort_review_path = root / "distribution-abort" / "manifest.json"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_batch_path, rejection_batch(True))
            write_json(dkg_review_path, dkg_no_single_secret_review())
            write_json(distribution_abort_review_path, distribution_abort_review())

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                dkg_review_path=dkg_review_path,
                distribution_abort_review_path=distribution_abort_review_path,
                generated_at="2026-07-04T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(manifest["attempt_status"], "blocked_external_evidence_missing")
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["checks"]["review_package_present"])
        self.assertFalse(manifest["checks"]["review_package_binds_inputs"])
        self.assertIn(
            "reviewed external evidence package is missing",
            " ".join(manifest["blockers"]),
        )

    def test_complete_external_bundle_writes_ready_candidate_without_closure_claims(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            dkg_review_path = root / "dkg-review" / "manifest.json"
            distribution_abort_review_path = root / "distribution-abort" / "manifest.json"
            review_package_path = root / "review" / "manifest.json"
            out_dir = root / "attempt"
            candidate_dir = root / "candidate"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_batch_path, rejection_batch(True))
            write_json(dkg_review_path, dkg_no_single_secret_review())
            write_json(distribution_abort_review_path, distribution_abort_review())
            candidate_digest = build_candidate_digest(
                module,
                root,
                nonce_path,
                backend_manifest_path,
                backend_capture_path,
                rejection_batch_path,
                dkg_review_path,
                distribution_abort_review_path,
            )
            write_json(
                review_package_path,
                reviewed_external_evidence_package(
                    module,
                    nonce_path,
                    backend_manifest_path,
                    backend_capture_path,
                    rejection_batch_path,
                    dkg_review_path,
                    distribution_abort_review_path,
                    candidate_digest,
                ),
            )

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                dkg_review_path=dkg_review_path,
                distribution_abort_review_path=distribution_abort_review_path,
                review_package_path=review_package_path,
                candidate_out=candidate_dir,
                generated_at="2026-07-04T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)

            manifest = json.loads((out_dir / "manifest.json").read_text())
            candidate = json.loads((candidate_dir / "manifest.json").read_text())
            candidate_manifest_sha256 = module.sha256_path(candidate_dir / "manifest.json")

        self.assertEqual(
            manifest["attempt_status"],
            "external_evidence_close_candidate_ready",
        )
        self.assertTrue(manifest["close_candidate"])
        self.assertTrue(candidate["close_candidate"])
        self.assertEqual(manifest["candidate_manifest_sha256"], candidate_manifest_sha256)
        self.assertTrue(all(manifest["checks"].values()))
        self.assertFalse(manifest["claims_theorem_closure"])
        self.assertFalse(manifest["claims_selected_backend_proof_closure"])
        self.assertFalse(manifest["claims_production_threshold_mldsa_security"])

    def test_tee_hsm_no_export_bundle_writes_ready_candidate_without_closure_claims(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            dkg_review_path = root / "dkg-review" / "manifest.json"
            distribution_abort_review_path = root / "distribution-abort" / "manifest.json"
            review_package_path = root / "review" / "manifest.json"
            candidate_dir = root / "candidate"
            manifest_payload = backend_manifest()
            capture_payload = backend_capture()
            mark_as_tee_hsm_no_export(manifest_payload, capture_payload)
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, manifest_payload)
            write_json(backend_capture_path, capture_payload)
            write_json(rejection_batch_path, rejection_batch(True))
            write_json(dkg_review_path, tee_hsm_no_export_review())
            write_json(distribution_abort_review_path, distribution_abort_review())
            candidate_digest = build_candidate_digest(
                module,
                root,
                nonce_path,
                backend_manifest_path,
                backend_capture_path,
                rejection_batch_path,
                dkg_review_path,
                distribution_abort_review_path,
            )
            write_json(
                review_package_path,
                reviewed_external_evidence_package(
                    module,
                    nonce_path,
                    backend_manifest_path,
                    backend_capture_path,
                    rejection_batch_path,
                    dkg_review_path,
                    distribution_abort_review_path,
                    candidate_digest,
                ),
            )

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                dkg_review_path=dkg_review_path,
                distribution_abort_review_path=distribution_abort_review_path,
                review_package_path=review_package_path,
                candidate_out=candidate_dir,
                generated_at="2026-07-04T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["attempt_status"],
            "external_evidence_close_candidate_ready",
        )
        self.assertTrue(manifest["checks"]["real_threshold_emission_present"])
        self.assertTrue(manifest["checks"]["source_exclusion_passed"])
        self.assertTrue(manifest["close_candidate"])
        self.assertFalse(manifest["claims_theorem_closure"])
        self.assertFalse(manifest["claims_rejection_distribution_preservation"])

    def test_review_package_digest_drift_blocks_close_candidate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            dkg_review_path = root / "dkg-review" / "manifest.json"
            distribution_abort_review_path = root / "distribution-abort" / "manifest.json"
            review_package_path = root / "review" / "manifest.json"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_batch_path, rejection_batch(True))
            write_json(dkg_review_path, dkg_no_single_secret_review())
            write_json(distribution_abort_review_path, distribution_abort_review())
            candidate_digest = build_candidate_digest(
                module,
                root,
                nonce_path,
                backend_manifest_path,
                backend_capture_path,
                rejection_batch_path,
                dkg_review_path,
                distribution_abort_review_path,
            )
            package = reviewed_external_evidence_package(
                module,
                nonce_path,
                backend_manifest_path,
                backend_capture_path,
                rejection_batch_path,
                dkg_review_path,
                distribution_abort_review_path,
                candidate_digest,
            )
            package["input_sha256s"]["real_threshold_backend_capture_json"] = "00" * 32
            write_json(review_package_path, package)

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                dkg_review_path=dkg_review_path,
                distribution_abort_review_path=distribution_abort_review_path,
                review_package_path=review_package_path,
                generated_at="2026-07-04T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(manifest["attempt_status"], "blocked_external_evidence_missing")
        self.assertFalse(manifest["close_candidate"])
        self.assertTrue(manifest["checks"]["review_package_present"])
        self.assertFalse(manifest["checks"]["review_package_binds_inputs"])
        self.assertIn("review package input digest mismatch", " ".join(manifest["blockers"]))

    def test_threshold_seed_reconstruction_source_blocks_external_evidence_attempt(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            dkg_review_path = root / "dkg-review" / "manifest.json"
            distribution_abort_review_path = root / "distribution-abort" / "manifest.json"
            review_package_path = root / "review" / "manifest.json"
            manifest_payload = backend_manifest()
            capture_payload = backend_capture()
            mark_as_threshold_seed_reconstruction(manifest_payload, capture_payload)
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, manifest_payload)
            write_json(backend_capture_path, capture_payload)
            write_json(rejection_batch_path, rejection_batch(True))
            write_json(dkg_review_path, dkg_no_single_secret_review())
            write_json(distribution_abort_review_path, distribution_abort_review())
            candidate_digest = build_candidate_digest(
                module,
                root,
                nonce_path,
                backend_manifest_path,
                backend_capture_path,
                rejection_batch_path,
                dkg_review_path,
                distribution_abort_review_path,
            )
            write_json(
                review_package_path,
                reviewed_external_evidence_package(
                    module,
                    nonce_path,
                    backend_manifest_path,
                    backend_capture_path,
                    rejection_batch_path,
                    dkg_review_path,
                    distribution_abort_review_path,
                    candidate_digest,
                ),
            )

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                dkg_review_path=dkg_review_path,
                distribution_abort_review_path=distribution_abort_review_path,
                review_package_path=review_package_path,
                generated_at="2026-07-04T00:00:00Z",
            )

        manifest = report["manifest"]
        blockers = " ".join(manifest["blockers"])
        self.assertEqual(manifest["attempt_status"], "blocked_external_evidence_missing")
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["checks"]["real_threshold_emission_present"])
        self.assertFalse(manifest["checks"]["source_exclusion_passed"])
        self.assertIn(
            "threshold seed-reconstruction capture cannot feed external evidence",
            blockers,
        )

    def test_rejects_hazmat_or_simulation_source_markers_before_candidate_ready(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_batch_path = root / "rejection" / "batch.json"
            bad_backend_manifest = backend_manifest()
            bad_backend_manifest["backend_command"] = [
                "/tmp/localnet-simulation-backend",
                "emit-capture",
            ]
            bad_rejection_batch = rejection_batch(True)
            bad_rejection_batch["backend_evidence"] = "hazmat-simulation-rejection-batch"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, bad_backend_manifest)
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_batch_path, bad_rejection_batch)

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_batch_path,
                generated_at="2026-07-04T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(manifest["attempt_status"], "blocked_external_evidence_missing")
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["checks"]["source_exclusion_passed"])
        blockers = " ".join(manifest["blockers"])
        self.assertIn("forbidden external-evidence source marker", blockers)
        self.assertIn("hazmat", blockers)
        self.assertIn("simulation", blockers)

    def test_strict_main_returns_two_until_close_candidate_ready(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "attempt"
            code = module.main(
                [
                    "--root",
                    str(root),
                    "--out",
                    str(out_dir),
                    "--strict",
                ]
            )
            manifest_written = (out_dir / "manifest.json").is_file()

        self.assertEqual(code, 2)
        self.assertTrue(manifest_written)


if __name__ == "__main__":
    unittest.main()
