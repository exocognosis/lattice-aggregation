import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p1_theorem_linkage_review.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_p1_theorem_linkage_review",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P1TheoremLinkageReviewTests(unittest.TestCase):
    def test_current_evidence_builds_reviewed_theorem_linkage_package(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-theorem-linkage-review:v1",
        )
        self.assertEqual(
            manifest["review_status"],
            "reviewed_theorem_linkage_ready",
        )
        self.assertEqual(
            manifest["claim_boundary"],
            "conformance/proof-review evidence",
        )
        self.assertTrue(all(manifest["checks"].values()))
        self.assertEqual(manifest["blockers"], [])
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertIn(
            "theorem_linkage_review_digest_hex",
            manifest["review_digests"],
        )

    def test_cli_writes_manifest_summary_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "linkage"
            code = module.main(["--root", str(ROOT), "--out", str(out)])

            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
