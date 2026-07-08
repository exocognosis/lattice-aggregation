import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p1_full_kat_cavp_validation_review.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_p1_full_kat_cavp_validation_review",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def reviewed_validation_input(module):
    reviewer_digest = "b" * 64
    return {
        "schema": "external-review:p1-full-kat-cavp-validation:v1",
        "backend_capture_sha256": module.sha256_path(
            module.default_backend_capture(ROOT)
        ),
        "backend_manifest_sha256": module.sha256_path(
            module.default_backend_manifest(ROOT)
        ),
        "implementation_digest_sha256": "a" * 64,
        "external_reviewer_digest_hex": reviewer_digest,
        "checks": {
            "provider_kat_vectors_passed": True,
            "fips204_mldsa65_kat_passed": True,
            "acvts_or_cavp_campaign_reviewed": True,
            "signing_verification_vectors_reviewed": True,
            "mutation_negative_vectors_reviewed": True,
            "public_key_signature_length_vectors_reviewed": True,
        },
        "campaign": {
            "route": "lab-reviewed-acvts-style-transcript",
            "parameter_set": "ML-DSA-65",
            "revision": "FIPS204",
            "transcript_digest_hex": "d" * 64,
            "modes": ["keyGen", "sigGen", "sigVer"],
            "lab_reviewed_equivalent": True,
        },
        "validation_package": {
            "provider_kat_vectors": {
                "reviewed": True,
                "passed": True,
                "provider": "ml-dsa crate MlDsa65",
            },
            "fips204_mldsa65_kat_vectors": {
                "reviewed": True,
                "passed": True,
                "parameter_set": "ML-DSA-65",
            },
            "acvts_cavp_campaign_transcript": {
                "reviewed": True,
                "route": "lab-reviewed-acvts-style-transcript",
                "transcript_digest_hex": "d" * 64,
            },
            "keygen_siggen_sigver_coverage": {
                "reviewed": True,
                "keyGen": True,
                "sigGen": True,
                "sigVer": True,
            },
            "reviewer_signoff_digest": {
                "reviewed": True,
                "digest_hex": reviewer_digest,
            },
        },
    }


class P1FullKatCavpValidationReviewTests(unittest.TestCase):
    def test_current_artifacts_build_ready_validation_package_with_reviewed_input(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-07T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-full-kat-cavp-validation-review:v1",
        )
        self.assertEqual(
            manifest["review_status"],
            "reviewed_full_kat_cavp_validation_ready",
        )
        self.assertEqual(
            manifest["claim_boundary"],
            "conformance/proof-review evidence",
        )
        self.assertTrue(manifest["checks"]["binds_backend_capture_digest"])
        self.assertTrue(manifest["checks"]["binds_backend_manifest_digest"])
        self.assertTrue(
            manifest["checks"]["public_key_signature_length_vectors_reviewed"]
        )
        self.assertTrue(manifest["checks"]["provider_kat_vectors_passed"])
        self.assertTrue(manifest["checks"]["fips204_mldsa65_kat_passed"])
        self.assertTrue(manifest["checks"]["acvts_or_cavp_campaign_reviewed"])
        self.assertTrue(manifest["checks"]["external_reviewer_digest_present"])
        self.assertEqual(manifest["blockers"], [])
        self.assertIn("validation_package", manifest)
        self.assertTrue(
            manifest["validation_package"]["keygen_siggen_sigver_coverage"]["keyGen"]
        )
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_reviewed_validation_input_can_build_ready_package(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            evidence_path = root / "validation-evidence.json"
            write_json(evidence_path, reviewed_validation_input(module))

            report = module.build_report(
                ROOT,
                validation_evidence_path=evidence_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "reviewed_full_kat_cavp_validation_ready",
        )
        self.assertTrue(all(manifest["checks"].values()))
        self.assertEqual(manifest["blockers"], [])
        self.assertIn("validation_package", manifest)
        self.assertEqual(
            manifest["validation_package"]["reviewer_signoff_digest"]["digest_hex"],
            "b" * 64,
        )
        self.assertIn("Validation package:", report["summary_md"])
        self.assertIn("keygen_siggen_sigver_coverage", report["summary_md"])
        self.assertIn("b" * 64, report["summary_md"])
        self.assertFalse(any(manifest["claim_flags"].values()))

    def test_validation_input_missing_coverage_section_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            evidence_path = root / "validation-evidence.json"
            evidence = reviewed_validation_input(module)
            del evidence["validation_package"]["keygen_siggen_sigver_coverage"]
            write_json(evidence_path, evidence)

            report = module.build_report(
                ROOT,
                validation_evidence_path=evidence_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "blocked_full_kat_cavp_validation_review",
        )
        self.assertFalse(manifest["checks"]["signing_verification_vectors_reviewed"])
        self.assertIn("signing_verification_vectors_reviewed", manifest["blockers"])

    def test_validation_input_with_digest_mismatch_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            evidence_path = root / "validation-evidence.json"
            evidence = reviewed_validation_input(module)
            evidence["backend_capture_sha256"] = "0" * 64
            write_json(evidence_path, evidence)

            report = module.build_report(
                ROOT,
                validation_evidence_path=evidence_path,
                generated_at="2026-07-07T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["review_status"],
            "blocked_full_kat_cavp_validation_review",
        )
        self.assertFalse(manifest["checks"]["binds_backend_capture_digest"])
        self.assertIn("binds_backend_capture_digest", manifest["blockers"])

    def test_cli_writes_manifest_summary_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "validation-review"
            code = module.main(["--root", str(ROOT), "--out", str(out)])

            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
