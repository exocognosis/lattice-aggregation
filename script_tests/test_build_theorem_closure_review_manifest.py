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
        self.assertTrue(manifest["review_flags"]["theorem_linkage_reviewed"])
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertEqual(manifest["evidence_summary"]["predicate_mismatch_count"], 0)
        self.assertTrue(manifest["evidence_summary"]["saw_accepted_and_rejected"])
        self.assertTrue(manifest["evidence_summary"]["standard_verifier_accepts"])
        self.assertFalse(
            manifest["evidence_summary"]["distribution_compatibility_proven"]
        )
        self.assertTrue(
            manifest["evidence_summary"]["theorem_linkage_review"][
                "review_status_ready"
            ]
        )
        self.assertTrue(
            manifest["evidence_summary"]["validation_artifact_slot"]["slot_present"]
        )
        self.assertTrue(
            manifest["evidence_summary"]["distribution_abort_review"][
                "review_status_ready"
            ]
        )
        self.assertTrue(
            manifest["evidence_summary"]["blocker_closure_requests"][
                "request_status_ready"
            ]
        )
        self.assertTrue(
            manifest["evidence_summary"][
                "rejection_distribution_preservation_package"
            ]["present"]
        )
        self.assertFalse(
            manifest["evidence_summary"][
                "rejection_distribution_preservation_package"
            ]["review_ready"]
        )
        self.assertTrue(
            manifest["evidence_summary"]["full_kat_cavp_validation_package"][
                "present"
            ]
        )
        self.assertFalse(
            manifest["evidence_summary"]["full_kat_cavp_validation_package"][
                "review_ready"
            ]
        )
        self.assertIn(
            (
                "rejection-distribution preservation package is missing or not "
                "ready; see artifacts/theorem-closure-blocker-requests/latest/"
                "manifest.json"
            ),
            manifest["blocker_groups"]["rejection_distribution_review"],
        )
        self.assertIn(
            (
                "full KAT/CAVP validation package is missing or not ready; see "
                "artifacts/theorem-closure-blocker-requests/latest/manifest.json"
            ),
            manifest["blocker_groups"]["validation"],
        )
        self.assertEqual(manifest["blocker_groups"]["theorem_linkage_review"], [])

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
        self.assertTrue(manifest["checks"]["theorem_linkage_reviewed"])
        self.assertFalse(manifest["theorem_closure_assessment_ready"])
        self.assertEqual(manifest["blocker_groups"]["external_backend_evidence"], [])
        self.assertIn(
            "theorem review manifest has not satisfied full_kat_validation_reviewed",
            manifest["blocker_groups"]["validation"],
        )
        self.assertEqual(manifest["blocker_groups"]["theorem_linkage_review"], [])

    def test_reviewed_distribution_and_validation_packages_can_ready_assessment(self):
        module = load_module(SCRIPT, "build_theorem_closure_review_manifest")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            rejection_package = {
                "schema": (
                    "lattice-aggregation:"
                    "p1-rejection-distribution-preservation-review:v1"
                ),
                "schema_version": 1,
                "package_class": "rejection_distribution_preservation_review",
                "selected_profile": (
                    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
                ),
                "claim_boundary": "conformance/proof-review evidence",
                "review_status": "reviewed_rejection_distribution_preservation_ready",
                "source_inputs": {
                    "rejection_batch_sha256": module.sha256_path(
                        module.default_rejection_batch(ROOT)
                    ),
                    "accepted_distribution_abort_review_sha256": module.sha256_path(
                        module.default_distribution_abort_review(ROOT)
                    ),
                },
                "checks": {
                    name: True
                    for name in module.REJECTION_DISTRIBUTION_PACKAGE_CHECKS
                },
                "claim_flags": {key: False for key in module.CLAIM_FLAG_KEYS},
            }
            validation_package = {
                "schema": "lattice-aggregation:p1-full-kat-cavp-validation-review:v1",
                "schema_version": 1,
                "package_class": "full_kat_cavp_validation_review",
                "selected_profile": (
                    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
                ),
                "claim_boundary": "conformance/proof-review evidence",
                "review_status": "reviewed_full_kat_cavp_validation_ready",
                "source_inputs": {
                    "backend_capture_sha256": module.sha256_path(
                        module.default_backend_capture(ROOT)
                    ),
                    "backend_manifest_sha256": module.sha256_path(
                        module.default_backend_manifest(ROOT)
                    ),
                },
                "checks": {
                    name: True for name in module.FULL_KAT_VALIDATION_PACKAGE_CHECKS
                },
                "claim_flags": {key: False for key in module.CLAIM_FLAG_KEYS},
            }
            rejection_path = root / "rejection-package.json"
            validation_path = root / "validation-package.json"
            write_json(rejection_path, rejection_package)
            write_json(validation_path, validation_package)

            report = module.build_report(
                ROOT,
                rejection_distribution_preservation_review_path=rejection_path,
                full_kat_cavp_validation_review_path=validation_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "theorem_closure_review_ready",
        )
        self.assertTrue(
            manifest["review_flags"]["rejection_distribution_preservation_reviewed"]
        )
        self.assertTrue(manifest["review_flags"]["full_kat_validation_reviewed"])
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertEqual(manifest["blocker_groups"]["rejection_distribution_review"], [])
        self.assertEqual(manifest["blocker_groups"]["validation"], [])

    def test_theorem_linkage_artifact_claiming_closure_is_rejected(self):
        module = load_module(SCRIPT, "build_theorem_closure_review_manifest")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            bad_linkage = {
                "schema": "lattice-aggregation:p1-theorem-linkage-review:v1",
                "selected_profile": (
                    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
                ),
                "claim_boundary": "conformance/proof-review evidence",
                "review_status": "reviewed_theorem_linkage_ready",
                "checks": {"some_check": True},
                "claim_flags": {"claims_theorem_closure": True},
            }
            bad_path = root / "bad-linkage.json"
            write_json(bad_path, bad_linkage)

            report = module.build_report(
                ROOT,
                theorem_linkage_review_path=bad_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertFalse(manifest["review_flags"]["theorem_linkage_reviewed"])
        self.assertIn(
            "theorem-linkage review package is not ready",
            manifest["blocker_groups"]["theorem_linkage_review"],
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
