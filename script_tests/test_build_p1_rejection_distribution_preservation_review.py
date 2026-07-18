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


def reviewed_proof_input(module):
    reviewer_digest = "c" * 64
    return {
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
        "external_reviewer_digest_hex": reviewer_digest,
        "concrete_loss_bound": {
            "distance_measure": "total_variation_distance",
            "accepted_distribution_bound": (
                "Delta(D_threshold | accept, D_ML-DSA | accept) <= 2^-128"
            ),
            "loss_model": (
                "epsilon_predicate + epsilon_abort + epsilon_restart "
                "+ epsilon_concurrency"
            ),
        },
        "proof_package": {
            "accepted_threshold_output_distribution_vs_centralized_mldsa_distribution": {
                "reviewed": True,
                "source": "bound rejection batch and accepted-distribution review",
            },
            "concrete_distance_loss_bound": {
                "reviewed": True,
                "instantiated_bound": "2^-128 or stronger under stated model",
            },
            "rejection_sampling_conditioning": {
                "reviewed": True,
                "conditioned_event": "FIPS 204 rejection predicates accept",
            },
            "selective_abort_withholding_bound": {
                "reviewed": True,
                "bound": "withholding adds abort-only leakage recorded by transcript",
            },
            "restart_leakage_bound": {
                "reviewed": True,
                "bound": "restart leakage limited to public attempt count and digests",
            },
            "concurrency_model": {
                "reviewed": True,
                "model": "independent transcripts per session with domain-separated digests",
            },
            "reviewer_signoff_digest": {
                "reviewed": True,
                "digest_hex": reviewer_digest,
            },
        },
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
    }


class P1RejectionDistributionPreservationReviewTests(unittest.TestCase):
    def test_current_artifacts_build_ready_preservation_package_with_reviewed_proof_input(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-rejection-distribution-preservation-review:v1",
        )
        self.assertEqual(
            manifest["review_status"],
            "reviewed_rejection_distribution_preservation_ready",
        )
        self.assertEqual(
            manifest["claim_boundary"],
            "conformance/proof-review evidence",
        )
        self.assertTrue(manifest["checks"]["binds_rejection_batch_digest"])
        self.assertTrue(manifest["checks"]["binds_distribution_abort_review_digest"])
        self.assertTrue(
            manifest["checks"]["accepted_distribution_distance_bound_reviewed"]
        )
        self.assertTrue(manifest["checks"]["external_reviewer_digest_present"])
        self.assertEqual(manifest["blockers"], [])
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_reviewed_proof_input_can_build_ready_preservation_package(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            proof_path = root / "rejection-distribution-proof.json"
            write_json(proof_path, reviewed_proof_input(module))

            report = module.build_report(
                ROOT,
                proof_evidence_path=proof_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        summary = report["summary_md"]
        self.assertEqual(
            manifest["review_status"],
            "reviewed_rejection_distribution_preservation_ready",
        )
        self.assertTrue(all(manifest["checks"].values()))
        self.assertEqual(manifest["blockers"], [])
        self.assertIn(
            "accepted_threshold_output_distribution_vs_centralized_mldsa_distribution",
            manifest["proof_package"],
        )
        self.assertEqual(
            manifest["proof_package"]["reviewer_signoff_digest"]["digest_hex"],
            "c" * 64,
        )
        self.assertIn("Proof package:", summary)
        self.assertIn(
            "accepted_threshold_output_distribution_vs_centralized_mldsa_distribution",
            summary,
        )
        self.assertIn("reviewer_signoff_digest", summary)
        self.assertIn("c" * 64, summary)
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_proof_input_missing_required_proof_package_section_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            proof_path = root / "rejection-distribution-proof.json"
            evidence = reviewed_proof_input(module)
            del evidence["proof_package"]["restart_leakage_bound"]
            write_json(proof_path, evidence)

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
        self.assertFalse(manifest["checks"]["restart_leakage_bound_reviewed"])
        self.assertIn("restart_leakage_bound_reviewed", manifest["blockers"])

    def test_proof_input_with_digest_mismatch_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            proof_path = root / "rejection-distribution-proof.json"
            evidence = reviewed_proof_input(module)
            evidence["rejection_batch_sha256"] = "0" * 64
            write_json(proof_path, evidence)

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
