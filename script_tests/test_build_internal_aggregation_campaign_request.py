import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_internal_aggregation_campaign_request.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_internal_aggregation_campaign_request", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalAggregationCampaignRequestTests(unittest.TestCase):
    def test_request_is_deterministic_and_pins_complete_campaign_matrix(self):
        module = load_module()
        first = module.build_request("theorem-closure-internal-001")
        second = module.build_request("theorem-closure-internal-001")

        self.assertEqual(first["request_json"], second["request_json"])
        self.assertEqual(first["manifest"]["request_sha256"], second["manifest"]["request_sha256"])
        request = first["request"]
        self.assertEqual(request["topology"]["validator_count"], 10000)
        self.assertEqual(request["topology"]["threshold"], 6667)
        self.assertEqual(request["topology"]["committee_size_ladder"], [8, 16, 32, 64])
        self.assertEqual(len(request["seed_corpus"]["seeds"]), 8)
        self.assertEqual(len(request["cases"]), 24)
        self.assertEqual(
            {(case["committee_size"], case["case_kind"]) for case in request["cases"]},
            {
                (size, kind)
                for size in (8, 16, 32, 64)
                for kind in (
                    "accepted",
                    "rejected",
                    "retry",
                    "abort",
                    "malicious_share",
                    "transcript_mutation",
                )
            },
        )
        requirements = request["capture_requirements"]
        self.assertTrue(requirements["exact_distributed_keygen"])
        self.assertTrue(requirements["per_receiver_private_share_custody"])
        self.assertTrue(requirements["exact_expand_mask_mpc"])
        self.assertTrue(requirements["committee_authorization_bound"])
        self.assertEqual(requirements["authorization_layer_validator_count"], 10000)
        self.assertEqual(requirements["authorization_layer_threshold"], 6667)
        self.assertIn("backend_test_results", requirements["required_evidence_file_roles"])
        self.assertIn("proof_artifact_bundle", requirements["required_evidence_file_roles"])
        self.assertIn("authorization_certificate", requirements["required_evidence_file_roles"])
        self.assertTrue(all(flag is False for flag in request["claim_flags"].values()))

    def test_request_writes_stable_contract_paths_and_checksums(self):
        module = load_module()
        report = module.build_request("theorem-closure-internal-001")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "campaign"
            module.write_artifacts(report, out_dir)
            request = json.loads((out_dir / "request.json").read_text())
            request_manifest = json.loads((out_dir / "request-manifest.json").read_text())
            checksums = (out_dir / "request-SHA256SUMS").read_text()

        contract = request["artifact_contract"]
        self.assertEqual(
            contract["capture_path"],
            "artifacts/internal-aggregation-campaign/latest/capture.json",
        )
        self.assertEqual(
            contract["validation_manifest_path"],
            "artifacts/internal-aggregation-campaign/latest/manifest.json",
        )
        self.assertEqual(request_manifest["case_count"], 24)
        self.assertIn("request.json", checksums)
        self.assertIn("request-manifest.json", checksums)

    def test_request_rejects_ambiguous_campaign_identifier(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "campaign id"):
            module.build_request("Internal Campaign With Spaces")


if __name__ == "__main__":
    unittest.main()
