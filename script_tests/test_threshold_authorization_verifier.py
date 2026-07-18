import hashlib
import importlib.util
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "threshold_authorization_verifier.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "threshold_authorization_verifier", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_key_for(index):
    seed = hashlib.sha256(f"validator:{index}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class ThresholdAuthorizationVerifierTests(unittest.TestCase):
    def test_profile_is_bound_to_current_implementation_bytes(self):
        module = load_module()
        profile = module.verifier_profile()

        self.assertEqual(
            profile["verifier_id"], "reviewed-ed25519-threshold-authorization-v1"
        )
        self.assertEqual(
            profile["verifier_implementation_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )

    def test_verifies_ed25519_authorizer_signatures(self):
        module = load_module()
        request = {"schema": "test-request", "campaign_id": "campaign-001"}
        certificate = {
            "schema": "lattice-aggregation:threshold-authorization-certificate:v1",
            "campaign_id": "campaign-001",
            "request_sha256": module.sha256_bytes(
                module.canonical_json(request).encode()
            ),
            "validator_count": 3,
            "threshold": 2,
            "validator_set_digest_hex": "11" * 32,
            "committee_authorizations": [
                {
                    "committee_size": 2,
                    "committee_digest_hex": "22" * 32,
                    "session_binding_digest_hex": "33" * 32,
                    "authorizer_records": [],
                }
            ],
        }
        committee = certificate["committee_authorizations"][0]
        for validator_id in (1, 2):
            private_key = private_key_for(validator_id)
            public_key = private_key.public_key().public_bytes_raw()
            authorizer = {
                "validator_id": validator_id,
                "public_key_hex": public_key.hex(),
                "public_key_digest_hex": hashlib.sha256(public_key).hexdigest(),
                "signature_scheme": "ed25519",
            }
            message = module.canonical_json(
                module.signed_authorization_message(
                    certificate, request, committee, authorizer
                )
            ).encode()
            signature = private_key.sign(message)
            authorizer["signature_hex"] = signature.hex()
            authorizer["signature_digest_hex"] = hashlib.sha256(signature).hexdigest()
            committee["authorizer_records"].append(authorizer)

        verifier = module.Ed25519ThresholdAuthorizationVerifier()
        self.assertTrue(verifier(certificate, request), verifier.last_errors)

        tampered = dict(committee["authorizer_records"][0])
        tampered["signature_hex"] = "00" * 64
        committee["authorizer_records"][0] = tampered
        self.assertFalse(verifier(certificate, request))
        self.assertIn("authorizer signature verification failed", verifier.last_errors)

    def test_cli_reports_profile_and_verification_failure(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            request_path = pathlib.Path(temp_dir) / "request.json"
            certificate_path = pathlib.Path(temp_dir) / "certificate.json"
            request_path.write_text(module.canonical_json({"campaign_id": "x"}))
            certificate_path.write_text(module.canonical_json({"not": "valid"}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(["--profile"]), 0)
                self.assertEqual(module.main(["--implementation-sha256"]), 0)
                self.assertEqual(
                    module.main(
                        [
                            "--request",
                            str(request_path),
                            "--certificate",
                            str(certificate_path),
                        ]
                    ),
                    2,
                )


if __name__ == "__main__":
    unittest.main()
