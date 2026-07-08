import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_theorem_closure_blocker_requests.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_theorem_closure_blocker_requests",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TheoremClosureBlockerRequestsTests(unittest.TestCase):
    def test_current_artifacts_emit_exact_remaining_package_requests(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:theorem-closure-blocker-requests:v1",
        )
        self.assertEqual(manifest["request_status"], "blocker_inputs_satisfied")
        self.assertEqual(
            sorted(manifest["required_packages"]),
            [
                "full_kat_cavp_validation_review",
                "rejection_distribution_preservation_review",
            ],
        )
        rejection_request = manifest["required_packages"][
            "rejection_distribution_preservation_review"
        ]
        self.assertEqual(
            rejection_request["schema"],
            "lattice-aggregation:p1-rejection-distribution-preservation-review:v1",
        )
        self.assertEqual(
            rejection_request["expected_path"],
            "artifacts/p1-rejection-distribution-preservation-review/latest/manifest.json",
        )
        self.assertIn(
            "accepted_distribution_distance_bound_reviewed",
            rejection_request["required_checks"],
        )
        self.assertEqual(
            rejection_request["current_status"],
            "package_ready",
        )
        validation_request = manifest["required_packages"][
            "full_kat_cavp_validation_review"
        ]
        self.assertEqual(
            validation_request["schema"],
            "lattice-aggregation:p1-full-kat-cavp-validation-review:v1",
        )
        self.assertIn(
            "acvts_or_cavp_campaign_reviewed",
            validation_request["required_checks"],
        )
        self.assertEqual(
            validation_request["current_status"],
            "package_ready",
        )
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertIn("summary.md", report["artifact_contents"])

    def test_cli_writes_manifest_summary_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "blocker-requests"
            code = module.main(
                [
                    "--root",
                    str(ROOT),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
