import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p1_rejection_distribution_preservation_review.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_p1_rejection_distribution_preservation_review",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class P1RejectionDistributionPreservationReviewTests(unittest.TestCase):
    def test_current_artifacts_build_blocked_preservation_package_without_proof_input(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-rejection-distribution-preservation-review:v1",
        )
        self.assertEqual(
            manifest["review_status"],
            "blocked_rejection_distribution_preservation_review",
        )
        self.assertEqual(
            manifest["claim_boundary"],
            "conformance/proof-review evidence",
        )
        self.assertTrue(manifest["checks"]["binds_rejection_batch_digest"])
        self.assertTrue(manifest["checks"]["binds_distribution_abort_review_digest"])
        self.assertFalse(
            manifest["checks"]["accepted_distribution_distance_bound_reviewed"]
        )
        self.assertFalse(manifest["checks"]["external_reviewer_digest_present"])
        self.assertIn(
            "accepted_distribution_distance_bound_reviewed",
            manifest["blockers"],
        )
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_reviewed_proof_input_can_build_ready_preservation_package(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            proof_path = root / "rejection-distribution-proof.json"
            write_json(
                proof_path,
                {
                    "schema": (
                        "external-review:"
                        "p1-rejection-distribution-preservation:v1"
                    ),
                    "rejection_batch_sha256": module.sha256_path(
                        module.default_rejection_batch(ROOT)
                    ),
                    "accepted_distribution_abort_review_sha256": module.sha256_path(
                        module.default_distribution_abort_review(ROOT)
                    ),
                    "external_reviewer_digest_hex": "c" * 64,
                    "concrete_loss_bound": "2^-128 or stronger under stated model",
                    "checks": {
                        "accepted_distribution_distance_bound_reviewed": True,
                        "threshold_accepted_distribution_reviewed": True,
                        "centralized_mldsa_reference_distribution_reviewed": True,
                        "rejection_sampling_conditioning_reviewed": True,
                        "selective_abort_withholding_bound_reviewed": True,
                        "restart_leakage_bound_reviewed": True,
                        "concurrency_model_reviewed": True,
                        "concrete_loss_bound_nonvacuous": True,
                    },
                    "theorem_links": [
                        "Noise Lemma D",
                        "Noise Lemma F",
                        "Noise Lemma H",
                        "FST-L7",
                    ],
                },
            )

            report = module.build_report(
                ROOT,
                proof_evidence_path=proof_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "reviewed_rejection_distribution_preservation_ready",
        )
        self.assertTrue(all(manifest["checks"].values()))
        self.assertEqual(manifest["blockers"], [])
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_proof_input_with_digest_mismatch_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            proof_path = root / "rejection-distribution-proof.json"
            write_json(
                proof_path,
                {
                    "schema": (
                        "external-review:"
                        "p1-rejection-distribution-preservation:v1"
                    ),
                    "rejection_batch_sha256": "0" * 64,
                    "accepted_distribution_abort_review_sha256": module.sha256_path(
                        module.default_distribution_abort_review(ROOT)
                    ),
                    "external_reviewer_digest_hex": "c" * 64,
                    "checks": {
                        name: True
                        for name in (
                            "accepted_distribution_distance_bound_reviewed",
                            "threshold_accepted_distribution_reviewed",
                            "centralized_mldsa_reference_distribution_reviewed",
                            "rejection_sampling_conditioning_reviewed",
                            "selective_abort_withholding_bound_reviewed",
                            "restart_leakage_bound_reviewed",
                            "concurrency_model_reviewed",
                            "concrete_loss_bound_nonvacuous",
                        )
                    },
                },
            )

            report = module.build_report(
                ROOT,
                proof_evidence_path=proof_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "blocked_rejection_distribution_preservation_review",
        )
        self.assertFalse(manifest["checks"]["binds_rejection_batch_digest"])
        self.assertIn("binds_rejection_batch_digest", manifest["blockers"])

    def test_cli_writes_manifest_summary_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "rejection-distribution-review"
            code = module.main(["--root", str(ROOT), "--out", str(out)])

            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
