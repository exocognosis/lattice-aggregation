import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUEST = ROOT / "artifacts" / "backend-emission-request" / "latest" / "request.json"
NONCE_REQUEST = (
    ROOT / "artifacts" / "nonce-producer-handoff" / "latest" / "request" / "request.json"
)
NONCE_READINESS = (
    ROOT / "artifacts" / "nonce-producer-backend-readiness" / "latest" / "manifest.json"
)
STAGE_SCRIPT = ROOT / "scripts" / "stage_external_backend_emission_capture.py"
NONCE_STAGE_SCRIPT = ROOT / "scripts" / "stage_external_nonce_producer_capture.py"
NONCE_GATE_SCRIPT = ROOT / "scripts" / "verify_actual_nonce_producer_capture.py"


class ThresholdBackendP1Tests(unittest.TestCase):
    def test_backend_capture_emits_threshold_reconstruction_run_without_closure_claim(
        self,
    ):
        with tempfile.TemporaryDirectory(prefix="threshold-backend-p1-strict.") as temp_dir:
            out_dir = pathlib.Path(temp_dir)
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--features",
                    "raw-real-mldsa",
                    "--bin",
                    "threshold_backend_p1",
                    "--",
                    "emit-backend-capture",
                    "--request",
                    str(REQUEST),
                    "--out-dir",
                    str(out_dir),
                    "--seed-hex",
                    "51" * 32,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            staged_dir = out_dir / "staged"
            subprocess.run(
                [
                    "python3",
                    str(STAGE_SCRIPT),
                    "--root",
                    str(ROOT),
                    "--request",
                    str(REQUEST),
                    "--capture-file",
                    str(out_dir / "capture.json"),
                    "--review-manifest",
                    str(out_dir / "review.json"),
                    "--out",
                    str(staged_dir),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            capture = json.loads((out_dir / "capture.json").read_text())
            review = json.loads((out_dir / "review.json").read_text())
            manifest = json.loads((staged_dir / "manifest.json").read_text())

        core = capture["cryptographic_core"]
        transcript = json.loads(
            bytes.fromhex(capture["capture"]["backend_transcript"]["value"]).decode(
                "utf-8"
            )
        )
        self.assertEqual(
            core["core_mode"],
            "threshold_seed_reconstruction_mldsa65_provider",
        )
        self.assertEqual(
            core["signature_origin"],
            "threshold_seed_reconstruction_standard_mldsa65_provider",
        )
        self.assertTrue(
            core["distributed_threshold_core"]["threshold_seed_reconstruction_sharing"]
        )
        self.assertTrue(
            core["distributed_threshold_core"]["standard_verifier_compatible_output"]
        )
        self.assertFalse(
            core["distributed_threshold_core"]["partial_signing_over_secret_shares"]
        )
        self.assertEqual(
            transcript["threshold_reconstruction"]["active_signer_count"],
            6667,
        )
        self.assertTrue(
            transcript["threshold_reconstruction"]["reconstruction_matches_seed_digest"]
        )
        self.assert_backend_requirement_ledger(capture, core, transcript)
        self.assertTrue(capture["capture"]["mutated_message_rejected"])
        self.assertTrue(capture["capture"]["mutated_public_key_rejected"])
        self.assertTrue(capture["capture"]["mutated_signature_rejected"])
        self.assertFalse(review["checks"]["real_distributed_threshold_core_verified"])
        self.assertTrue(review["checks"]["centralized_standard_provider_output_disclosed"])
        self.assertTrue(review["checks"]["threshold_core_limitations_reviewed"])
        self.assertEqual(manifest["runner_status"], "evidence_present_unclosed")
        self.assertTrue(manifest["backend_core_admissibility"]["quarantined"])
        self.assertIn(
            "unrecognized strict threshold core mode or signature origin",
            manifest["backend_core_admissibility"]["reasons"],
        )

    def test_smoke_backend_emits_stageable_real_mldsa65_capture_and_review_manifest(self):
        with tempfile.TemporaryDirectory(prefix="threshold-backend-p1.") as temp_dir:
            out_dir = pathlib.Path(temp_dir)
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--features",
                    "raw-real-mldsa",
                    "--bin",
                    "threshold_backend_p1",
                    "--",
                    "emit-smoke-backend-capture",
                    "--request",
                    str(REQUEST),
                    "--out-dir",
                    str(out_dir),
                    "--seed-hex",
                    "51" * 32,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            staged_dir = out_dir / "staged"
            subprocess.run(
                [
                    "python3",
                    str(STAGE_SCRIPT),
                    "--root",
                    str(ROOT),
                    "--request",
                    str(REQUEST),
                    "--capture-file",
                    str(out_dir / "capture.json"),
                    "--review-manifest",
                    str(out_dir / "review.json"),
                    "--out",
                    str(staged_dir),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            capture = json.loads((out_dir / "capture.json").read_text())
            review = json.loads((out_dir / "review.json").read_text())
            manifest = json.loads((staged_dir / "manifest.json").read_text())

        self.assertEqual(
            capture["schema"],
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        )
        self.assertEqual(capture["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(
            capture["cryptographic_core"]["core_mode"],
            "centralized_mldsa65_provider_with_threshold_evidence_envelope",
        )
        self.assertIn(
            "quarantined from the strict threshold core path",
            capture["cryptographic_core"]["closure_boundary"],
        )
        self.assertFalse(
            capture["cryptographic_core"]["distributed_threshold_core"][
                "partial_signing_over_secret_shares"
            ]
        )
        self.assertIn("threshold_core_accounting_digest_hex", capture["expected"])
        self.assertEqual(len(bytes.fromhex(capture["capture"]["public_key_hex"])), 1952)
        self.assertEqual(
            len(bytes.fromhex(capture["capture"]["aggregate_signature_hex"])),
            3309,
        )
        self.assertTrue(capture["capture"]["mutated_message_rejected"])
        self.assertTrue(capture["capture"]["mutated_public_key_rejected"])
        self.assertTrue(capture["capture"]["mutated_signature_rejected"])
        self.assertEqual(
            review["schema"],
            "lattice-aggregation:p1-external-backend-emission-capture-review:v1",
        )
        self.assertEqual(
            review["review_status"],
            "reviewed_external_backend_emission_capture_ready",
        )
        self.assertTrue(review["checks"]["centralized_standard_provider_output_disclosed"])
        self.assertFalse(review["checks"]["real_distributed_threshold_core_verified"])
        self.assertFalse(review["checks"]["no_single_key_standard_provider_output"])
        self.assertEqual(manifest["runner_status"], "evidence_present_unclosed")
        self.assertEqual(
            manifest["backend_execution_mode"],
            "preexisting_external_capture_file",
        )
        self.assertEqual(manifest["capture_file_origin"], "outside_repo_capture_file")

    def assert_backend_requirement_ledger(self, capture, core, transcript):
        expected_keys = {
            "threshold_key_material",
            "distributed_nonce_path",
            "partial_signing",
            "aggregation",
            "fips204_rejection_loop",
            "standard_verifier_compatibility",
        }
        core_ledger = core["backend_requirement_evidence"]
        capture_ledger = capture["backend_requirement_evidence"]
        transcript_ledger = transcript["backend_requirement_evidence"]
        attempt_ledger = transcript["attempts"][0]["backend_requirement_evidence"]
        self.assertEqual(set(core_ledger), expected_keys)
        self.assertEqual(set(capture_ledger), expected_keys)
        self.assertEqual(set(transcript_ledger), expected_keys)
        self.assertEqual(set(attempt_ledger), expected_keys)
        self.assertIn("backend_requirement_evidence_digest_hex", capture["expected"])

        key_material = core_ledger["threshold_key_material"]
        self.assertEqual(key_material["validator_count"], 10000)
        self.assertEqual(key_material["threshold"], 6667)
        self.assertEqual(key_material["public_key_count"], 1)
        self.assertTrue(key_material["threshold_seed_reconstruction_sharing"])
        self.assertFalse(key_material["distributed_dkg_vss_transcript_present"])
        self.assertTrue(key_material["tee_hsm_trust_record_present"])
        self.assertTrue(key_material["single_exposed_mldsa_secret_key_prevented"])

        nonce_path = core_ledger["distributed_nonce_path"]
        self.assertTrue(nonce_path["per_attempt_nonce_share_generation"])
        self.assertTrue(nonce_path["commit_before_reveal"])
        self.assertTrue(nonce_path["aggregate_commitment_w_evidence"])
        self.assertTrue(nonce_path["abort_accountability_records"])
        self.assertTrue(nonce_path["no_centralized_nonce_oracle"])
        self.assertFalse(nonce_path["live_distributed_nonce_generation"])

        partial_signing = core_ledger["partial_signing"]
        self.assertFalse(partial_signing["implemented"])
        self.assertFalse(partial_signing["partial_signing_over_secret_shares"])
        self.assertIn(
            "partial z_i over ML-DSA secret shares",
            " ".join(partial_signing["blockers"]),
        )

        aggregation = core_ledger["aggregation"]
        self.assertTrue(aggregation["standard_signature_tuple_present"])
        self.assertEqual(aggregation["signature_len"], 3309)
        self.assertFalse(aggregation["aggregate_z_from_threshold_partials"])
        self.assertFalse(aggregation["hint_h_from_threshold_partials"])

        rejection_loop = core_ledger["fips204_rejection_loop"]
        self.assertFalse(rejection_loop["real_threshold_partial_predicates"])
        self.assertTrue(rejection_loop["standard_provider_acceptance_observed"])
        self.assertFalse(rejection_loop["accepted_and_rejected_attempts_recorded"])
        self.assertIn("z_bounds", rejection_loop["required_predicates"])
        self.assertIn("hint_omega", rejection_loop["required_predicates"])

        verifier = core_ledger["standard_verifier_compatibility"]
        self.assertTrue(verifier["unmodified_mldsa65_verifier_accepts_original"])
        self.assertTrue(verifier["mutated_message_rejected"])
        self.assertTrue(verifier["mutated_public_key_rejected"])
        self.assertTrue(verifier["mutated_signature_rejected"])

    def test_backend_emits_stageable_nonce_capture_and_actual_external_gate(self):
        with tempfile.TemporaryDirectory(prefix="threshold-backend-p1-nonce.") as temp_dir:
            out_dir = pathlib.Path(temp_dir)
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--features",
                    "raw-real-mldsa",
                    "--bin",
                    "threshold_backend_p1",
                    "--",
                    "emit-nonce-capture",
                    "--request",
                    str(NONCE_REQUEST),
                    "--readiness",
                    str(NONCE_READINESS),
                    "--out-dir",
                    str(out_dir),
                    "--seed-hex",
                    "61" * 32,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            staged_dir = out_dir / "staged_nonce"
            subprocess.run(
                [
                    "python3",
                    str(NONCE_STAGE_SCRIPT),
                    "--root",
                    str(ROOT),
                    "--request",
                    str(NONCE_REQUEST),
                    "--readiness",
                    str(NONCE_READINESS),
                    "--capture-file",
                    str(out_dir / "capture.json"),
                    "--review-manifest",
                    str(out_dir / "review.json"),
                    "--out",
                    str(staged_dir),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            gate_dir = out_dir / "actual_gate"
            subprocess.run(
                [
                    "python3",
                    str(NONCE_GATE_SCRIPT),
                    "--root",
                    str(ROOT),
                    "--attempt",
                    str(staged_dir / "manifest.json"),
                    "--out",
                    str(gate_dir),
                    "--strict",
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            capture = json.loads((out_dir / "capture.json").read_text())
            review = json.loads((out_dir / "review.json").read_text())
            attempt = json.loads((staged_dir / "manifest.json").read_text())
            gate = json.loads((gate_dir / "manifest.json").read_text())

        self.assertEqual(
            capture["schema"],
            "lattice-aggregation:p1-distributed-nonce-producer-capture:v1",
        )
        self.assertEqual(
            capture["producer_evidence"],
            "p1_shamir_nonce_dkg_tee_external_capture",
        )
        self.assertEqual(
            capture["threshold_nonce_accounting"]["coefficient_count"],
            6667,
        )
        self.assertFalse(capture["threshold_nonce_accounting"]["live_network_capture"])
        self.assertIn("threshold_nonce_accounting_digest_hex", capture["expected"])
        self.assertEqual(
            len(capture["expected"]["distributed_nonce_producer_artifact_digest_hex"]),
            64,
        )
        self.assertTrue(capture["capture"]["reviewed"])
        self.assertEqual(
            review["schema"],
            "lattice-aggregation:p1-external-nonce-producer-capture-review:v1",
        )
        self.assertEqual(attempt["attempt_status"], "capture_promoted")
        self.assertEqual(
            attempt["handoff_source_profile"],
            "admissible_external_backend_capture",
        )
        self.assertFalse(attempt["handoff_quarantine"]["quarantined"])
        self.assertTrue(gate["actual_external_capture_ready"])
        self.assertEqual(gate["gate_status"], "actual_external_capture_ready")

    def test_threshold_core_capture_reports_engineering_blocker_closure(self):
        with tempfile.TemporaryDirectory(prefix="threshold-backend-p1-core.") as temp_dir:
            out_dir = pathlib.Path(temp_dir)
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--features",
                    "raw-real-mldsa",
                    "--bin",
                    "threshold_backend_p1",
                    "--",
                    "emit-threshold-core-capture",
                    "--request",
                    str(REQUEST),
                    "--out-dir",
                    str(out_dir),
                    "--seed-hex",
                    "51" * 32,
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            capture = json.loads((out_dir / "capture.json").read_text())
            review = json.loads((out_dir / "review.json").read_text())

        core = capture["cryptographic_core"]
        self.assertEqual(core["core_mode"], "threshold_mldsa_engine_live_nonce_dkg_p1")
        self.assertTrue(core["distributed_threshold_core"]["live_distributed_nonce_generation"])
        self.assertTrue(core["distributed_threshold_core"]["partial_signing_over_secret_shares"])
        self.assertFalse(
            core["distributed_threshold_core"]["fips204_rejection_loop_over_threshold_partials"]
        )
        self.assertTrue(
            core["distributed_threshold_core"][
                "provider_fips204_rejection_over_reconstructed_distributed_rnd"
            ]
        )
        self.assertTrue(core["distributed_threshold_core"]["standard_verifier_compatible_output"])
        self.assertFalse(
            core["distributed_threshold_core"]["accepted_aggregate_distribution_proven"]
        )
        self.assertTrue(
            core["blocker_status"]["algebraic_module_vector_partial_zi"]
        )

        ledger = core["backend_requirement_evidence"]
        self.assertTrue(ledger["distributed_nonce_path"]["live_distributed_nonce_generation"])
        self.assertTrue(ledger["partial_signing"]["implemented"])
        self.assertTrue(ledger["partial_signing"]["partial_signing_over_secret_shares"])
        self.assertTrue(ledger["partial_signing"]["algebraic_poly_partial_zi"])
        self.assertTrue(ledger["partial_signing"]["algebraic_module_vector_partial_zi"])
        self.assertFalse(ledger["fips204_rejection_loop"]["real_threshold_partial_predicates"])
        self.assertTrue(
            ledger["fips204_rejection_loop"][
                "provider_rejection_over_reconstructed_distributed_rnd"
            ]
        )
        self.assertFalse(
            ledger["threshold_key_material"]["single_exposed_mldsa_secret_key_prevented"]
        )
        self.assertTrue(ledger["threshold_key_material"]["coordinator_reconstructs_seed_in_process"])
        self.assertTrue(ledger["engineering_blockers_closed"])
        self.assertFalse(ledger["fully_closed"])
        self.assertFalse(ledger["production_approved"])

        blocker = core["blocker_status"]
        self.assertTrue(blocker["distributed_nonce_dkg_live"])
        self.assertTrue(blocker["engineering_blockers_closed"])
        self.assertFalse(blocker["closed_proofs"])
        self.assertFalse(blocker["closed_audits"])

        self.assertEqual(len(bytes.fromhex(capture["capture"]["public_key_hex"])), 1952)
        self.assertEqual(
            len(bytes.fromhex(capture["capture"]["aggregate_signature_hex"])),
            3309,
        )
        self.assertTrue(capture["capture"]["mutated_message_rejected"])
        self.assertIn("review_status", review)
        self.assertIn("fips_wire", ledger)
        self.assertTrue(ledger["fips_wire"]["fips204_wire_signature_accepted"])
        self.assertTrue(ledger["fips_wire"]["threshold_z_share_reconstructs_wire_z"])
        self.assertTrue(ledger["fips_wire"]["fips204_wire_from_s1_y_partials_without_provider"])
        self.assertTrue(ledger["fips_wire"]["self_contained_sign_internal"])



if __name__ == "__main__":
    unittest.main()
