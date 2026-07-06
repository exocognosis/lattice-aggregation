import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_backend_emission_request.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_backend_emission_request", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BackendEmissionRequestBuilderTests(unittest.TestCase):
    def test_build_request_manifest_writes_external_backend_challenge_contract(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "artifacts" / "backend-request"
            request = module.build_request(
                name="p1-external-backend-capture-001",
                message_hex="74657374206d657373616765",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
                generated_at="2026-07-01T00:00:00Z",
            )
            module.write_artifacts(request, out_dir)

            request_json = json.loads((out_dir / "request.json").read_text())
            summary_md = (out_dir / "summary.md").read_text()
            checksums = (out_dir / "SHA256SUMS").read_text()

        self.assertEqual(
            request_json["schema"],
            "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
        )
        self.assertEqual(
            request_json["claim_boundary"], "conformance/proof-review evidence"
        )
        self.assertEqual(
            request_json["selected_profile"],
            "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        )
        self.assertEqual(request_json["validator_count"], 10000)
        self.assertEqual(request_json["threshold"], 6667)
        self.assertEqual(request_json["aggregate_signature_len"], 3309)
        self.assertEqual(request_json["message"]["encoding"], "hex")
        self.assertEqual(request_json["message"]["value"], "74657374206d657373616765")
        self.assertEqual(
            request_json["predecessors"]["selected_profile_binding_digest_hex"],
            "11" * 32,
        )
        self.assertEqual(
            request_json["required_capture"]["schema"],
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        )
        self.assertEqual(
            request_json["required_capture"]["backend_evidence"],
            "real_threshold_mldsa_external_capture",
        )
        self.assertTrue(request_json["required_capture"]["mutated_message_rejected"])
        self.assertTrue(request_json["required_capture"]["mutated_public_key_rejected"])
        self.assertTrue(request_json["required_capture"]["mutated_signature_rejected"])
        self.assertIn("evidence_present_unclosed", summary_md)
        self.assertIn("requires Criterion 2 proof review", summary_md)
        self.assertIn("request.json", checksums)

    def test_build_request_manifest_rejects_simulation_names_bad_digests_and_bad_message_hex(
        self,
    ):
        module = load_module()

        with self.assertRaisesRegex(ValueError, "forbidden request name"):
            module.build_request(
                name="validator-localnet-request",
                message_hex="74657374",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )
        with self.assertRaisesRegex(ValueError, "selected_profile_binding_digest_hex"):
            module.build_request(
                name="p1-external-backend-capture-001",
                message_hex="74657374",
                selected_profile_binding_digest_hex="00" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )
        with self.assertRaisesRegex(ValueError, "message_hex"):
            module.build_request(
                name="p1-external-backend-capture-001",
                message_hex="not-hex",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )


if __name__ == "__main__":
    unittest.main()
