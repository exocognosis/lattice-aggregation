import importlib.util
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_internal_theorem_closure_attempt.py"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "run_internal_theorem_closure_attempt_under_test", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalTheoremClosureAttemptTests(unittest.TestCase):
    def test_cli_records_requested_items_and_fails_closed(self):
        runner = load_script()
        with tempfile.TemporaryDirectory() as directory:
            temp_root = pathlib.Path(directory)
            campaign_dir = temp_root / "campaign"
            criterion_dir = temp_root / "criteria"
            bundle_dir = temp_root / "bundle"
            assessment_dir = temp_root / "assessment"
            attempt_dir = temp_root / "attempt"

            with redirect_stdout(StringIO()):
                exit_code = runner.main(
                    [
                        "--root",
                        str(ROOT),
                        "--campaign-out",
                        str(campaign_dir),
                        "--criterion-evidence-dir",
                        str(criterion_dir),
                        "--bundle-out",
                        str(bundle_dir),
                        "--assessment-out",
                        str(assessment_dir),
                        "--out",
                        str(attempt_dir),
                        "--strict",
                    ]
                )

            manifest = json.loads((attempt_dir / "manifest.json").read_text())

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:internal-theorem-closure-attempt:v1",
        )
        self.assertEqual(
            manifest["attempt_status"], "blocked_before_internal_closure"
        )
        self.assertFalse(manifest["internally_closed_pending_independent_review"])
        self.assertFalse(manifest["claim_flags"]["claims_theorem_closure"])
        self.assertFalse(
            manifest["claim_flags"]["claims_production_threshold_mldsa_security"]
        )
        self.assertFalse(
            manifest["claim_flags"]["claims_independent_review_complete"]
        )
        item_ids = {item["id"] for item in manifest["requested_items"]}
        self.assertEqual(
            item_ids,
            {
                "real_24_case_n10000_t6667_distributed_campaign_capture",
                "passing_substantive_proof_manifests_for_all_five_criteria",
                "internal_closure_bundle_clean_provenance_two_internal_reviewers",
            },
        )
        statuses = {item["id"]: item["status"] for item in manifest["requested_items"]}
        self.assertEqual(
            statuses["real_24_case_n10000_t6667_distributed_campaign_capture"],
            "blocked",
        )
        self.assertIn(
            "admissible real 24-case n=10000/t=6667 distributed campaign capture",
            manifest["next_required_artifacts"],
        )
        self.assertTrue(
            any("real distributed campaign capture.json is absent" in blocker for blocker in manifest["blockers"])
        )

    def test_reviewer_signature_collection_requires_two_distinct_signers(self):
        runner = load_script()
        valid_one = {
            "reviewer_identity_sha256": "11" * 32,
            "signature_sha256": "22" * 32,
            "signed_payload_sha256": "33" * 32,
            "verdict": "approved",
        }
        valid_two = {
            "reviewer_identity_sha256": "44" * 32,
            "review_signature_sha256": "55" * 32,
            "reviewed_payload_sha256": "66" * 32,
            "verdict": "accepted",
        }
        invalid = {
            "reviewer_identity_sha256": "77" * 32,
            "signature_sha256": "88" * 32,
            "signed_payload_sha256": "99" * 32,
            "verdict": "pending",
        }
        bundle = {
            "internal_review": {
                "reviewer_signatures": [valid_one, invalid],
            }
        }
        criteria = [
            {"internal_review": {"reviewer_signatures": [valid_two]}},
        ]

        result = runner.collect_reviewer_signatures(bundle, criteria)

        self.assertEqual(result["valid_signature_count"], 2)
        self.assertEqual(result["distinct_reviewer_count"], 2)
        self.assertEqual(
            result["reviewer_identity_sha256"], ["11" * 32, "44" * 32]
        )


if __name__ == "__main__":
    unittest.main()
