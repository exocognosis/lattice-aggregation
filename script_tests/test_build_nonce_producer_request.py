import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_nonce_producer_request.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_nonce_producer_request", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NonceProducerRequestBuilderTests(unittest.TestCase):
    def test_build_request_manifest_writes_external_nonce_producer_challenge_contract(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "artifacts" / "nonce-producer-request"
            request = module.build_request(
                name="p1-external-nonce-producer-capture-001",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
                generated_at="2026-07-02T00:00:00Z",
            )
            module.write_artifacts(request, out_dir)

            request_json = json.loads((out_dir / "request.json").read_text())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary_md = (out_dir / "summary.md").read_text()
            checksums = (out_dir / "SHA256SUMS").read_text()

        self.assertEqual(
            request_json["schema"],
            "lattice-aggregation:p1-distributed-nonce-producer-request:v1",
        )
        self.assertEqual(
            request_json["claim_boundary"], "conformance/proof-review evidence"
        )
        self.assertEqual(
            request_json["selected_profile"],
            "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        )
        self.assertEqual(
            request_json["required_capture"]["schema"],
            "lattice-aggregation:p1-distributed-nonce-producer-capture:v1",
        )
        self.assertEqual(
            request_json["required_capture"]["producer_evidence"],
            "p1_shamir_nonce_dkg_tee_external_capture",
        )
        self.assertEqual(
            request_json["predecessors"]["threshold_output_certificate_digest_hex"],
            "22" * 32,
        )
        self.assertIn("shamir_nonce_dkg_transcript", request_json["required_capture"]["material"])
        self.assertIn("hazmat PRF-output oracle", request_json["forbidden_capture_sources"])
        self.assertIn("evidence_present_unclosed", summary_md)
        self.assertIn("requires Criterion 2 proof review", summary_md)
        self.assertEqual(
            manifest["request_schema"],
            "lattice-aggregation:p1-distributed-nonce-producer-request:v1",
        )
        self.assertIn("request.json", checksums)

    def test_build_request_manifest_rejects_simulation_names_and_bad_digests(self):
        module = load_module()

        with self.assertRaisesRegex(ValueError, "forbidden request name"):
            module.build_request(
                name="deterministic-localnet-nonce-request",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )
        with self.assertRaisesRegex(ValueError, "selected_profile_binding_digest_hex"):
            module.build_request(
                name="p1-external-nonce-producer-capture-001",
                selected_profile_binding_digest_hex="00" * 32,
                threshold_output_certificate_digest_hex="22" * 32,
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )
        with self.assertRaisesRegex(ValueError, "threshold_output_certificate_digest_hex"):
            module.build_request(
                name="p1-external-nonce-producer-capture-001",
                selected_profile_binding_digest_hex="11" * 32,
                threshold_output_certificate_digest_hex="not-hex",
                standard_verifier_compatibility_artifact_digest_hex="33" * 32,
            )


if __name__ == "__main__":
    unittest.main()
