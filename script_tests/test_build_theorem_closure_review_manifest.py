import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_theorem_closure_review_manifest.py"
READINESS_SCRIPT = ROOT / "scripts" / "assess_theorem_closure_readiness.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TheoremClosureReviewManifestTests(unittest.TestCase):
    def test_current_close_candidate_builds_partial_theorem_review_manifest(self):
        module = load_module(SCRIPT, "build_theorem_closure_review_manifest")

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:theorem-closure-review:v1",
        )
        self.assertEqual(
            manifest["review_status"],
            "theorem_closure_review_incomplete",
        )
        self.assertEqual(
            manifest["claim_boundary"],
            "readiness preflight only; pending theorem-closure review",
        )
        self.assertTrue(manifest["review_flags"]["proof_payload_reviewed"])
        self.assertTrue(
            manifest["review_flags"]["standard_verifier_compatibility_reviewed"]
        )
        self.assertFalse(
            manifest["review_flags"]["rejection_distribution_preservation_reviewed"]
        )
        self.assertFalse(manifest["review_flags"]["full_kat_validation_reviewed"])
        self.assertFalse(manifest["review_flags"]["theorem_linkage_reviewed"])
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertEqual(manifest["evidence_summary"]["predicate_mismatch_count"], 0)
        self.assertTrue(manifest["evidence_summary"]["saw_accepted_and_rejected"])
        self.assertTrue(manifest["evidence_summary"]["standard_verifier_accepts"])
        self.assertFalse(
            manifest["evidence_summary"]["distribution_compatibility_proven"]
        )
        self.assertIn(
            "rejection-distribution preservation is not proven by the batch",
            manifest["blocker_groups"]["rejection_distribution_review"],
        )
        self.assertIn(
            "full KAT/CAVP validation package is not present",
            manifest["blocker_groups"]["validation"],
        )
        self.assertIn(
            "theorem-linkage review package is not present",
            manifest["blocker_groups"]["theorem_linkage_review"],
        )

    def test_partial_theorem_review_narrows_readiness_blockers(self):
        builder = load_module(SCRIPT, "build_theorem_closure_review_manifest")
        readiness = load_module(READINESS_SCRIPT, "assess_theorem_closure_readiness")

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "theorem-review"
            builder.write_artifacts(
                builder.build_report(ROOT, generated_at="2026-07-07T00:00:00Z"),
                out,
            )
            report = readiness.build_report(
                ROOT,
                theorem_review_path=out / "manifest.json",
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertTrue(manifest["checks"]["theorem_review_manifest_present"])
        self.assertTrue(manifest["checks"]["theorem_review_manifest_boundary_valid"])
        self.assertFalse(manifest["checks"]["theorem_review_status_ready"])
        self.assertTrue(manifest["checks"]["proof_payload_reviewed"])
        self.assertTrue(manifest["checks"]["standard_verifier_compatibility_reviewed"])
        self.assertFalse(manifest["checks"]["full_kat_validation_reviewed"])
        self.assertFalse(
            manifest["checks"]["rejection_distribution_preservation_reviewed"]
        )
        self.assertFalse(manifest["checks"]["theorem_linkage_reviewed"])
        self.assertFalse(manifest["theorem_closure_assessment_ready"])
        self.assertEqual(manifest["blocker_groups"]["external_backend_evidence"], [])
        self.assertIn(
            "theorem review manifest has not satisfied full_kat_validation_reviewed",
            manifest["blocker_groups"]["validation"],
        )

    def test_cli_writes_manifest_summary_and_checksums(self):
        module = load_module(SCRIPT, "build_theorem_closure_review_manifest")

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "review"
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
