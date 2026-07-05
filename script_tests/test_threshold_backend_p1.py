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
    def test_backend_emits_stageable_real_mldsa65_capture_and_review_manifest(self):
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

        self.assertEqual(
            capture["schema"],
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        )
        self.assertEqual(capture["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(
            capture["cryptographic_core"]["core_mode"],
            "centralized_mldsa65_provider_with_threshold_evidence_envelope",
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


if __name__ == "__main__":
    unittest.main()
