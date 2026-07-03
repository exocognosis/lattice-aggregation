import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_nonce_producer_backend_readiness.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "check_nonce_producer_backend_readiness",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def external_request():
    return {
        "schema": REQUEST_SCHEMA,
        "name": "external-nonce-producer-readiness-request",
        "generated_at": "2026-07-03T00:00:00Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "request_status": "evidence_present_unclosed",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "predecessors": {
            "selected_profile_binding_digest_hex": "11" * 32,
            "threshold_output_certificate_digest_hex": "22" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "33" * 32,
        },
        "required_capture": {
            "schema": CAPTURE_SCHEMA,
            "producer_evidence": "p1_shamir_nonce_dkg_tee_external_capture",
            "claim_boundary": "conformance/proof-review evidence only",
            "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
            "material": [
                "source_reference",
                "backend_implementation",
                "coordinator_attestation",
                "shamir_nonce_dkg_transcript",
                "pairwise_mask_seed_commitments",
                "nonce_share_commitments",
                "abort_accountability",
                "external_review",
            ],
            "reviewed": True,
        },
        "forbidden_capture_sources": [
            "hazmat PRF-output oracle",
            "centralized expanded-secret-key helper",
            "fixture harness",
            "ordinary single-key standard-provider output",
            "localnet",
            "deterministic simulation",
        ],
    }


def write_request(root):
    request_path = root / "request.json"
    request_path.write_text(json.dumps(external_request()), encoding="utf-8")
    return request_path


def write_backend_crate(root, *, hazmat):
    crate = root / "backend"
    (crate / "src" / "low_level").mkdir(parents=True)
    if hazmat:
        cargo_toml = """
[package]
name = "dytallix-pq-threshold"
version = "0.1.0"
description = "Research-grade threshold ML-DSA-65 API boundary and simulation backend"
categories = ["cryptography", "simulation"]

[features]
default = ["simulated"]
simulated = []
hazmat = []
hazmat-real-mldsa = ["hazmat"]
"""
        source = """
pub struct Mldsa65DistributedNoncePrfOutputShare;
pub fn split_mldsa65_distributed_nonce_prf_output() {}
pub fn derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share() {}
pub fn derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key() {}
// deterministic test-vector plumbing for a hazmat PRF-output oracle
"""
    else:
        cargo_toml = """
[package]
name = "reviewed-p1-nonce-producer"
version = "1.2.3"
description = "Reviewed external Shamir nonce DKG TEE nonce producer"

[features]
default = []
tee-attested = []
"""
        source = """
pub struct Mldsa65DistributedNoncePrfOutputShare;
pub fn split_mldsa65_distributed_nonce_prf_output() {}
pub fn derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share() {}
pub const REVIEWED_EXTERNAL_SHAMIR_NONCE_DKG_CAPTURE_CONTRACT: &str =
    "p1_shamir_nonce_dkg_tee_external_capture";
pub const ABORT_ACCOUNTABILITY_TRANSCRIPT: &str = "abort_accountability";
"""
    (crate / "Cargo.toml").write_text(cargo_toml.lstrip(), encoding="utf-8")
    (crate / "src" / "low_level" / "mldsa65.rs").write_text(
        source.lstrip(),
        encoding="utf-8",
    )
    return crate


class NonceProducerBackendReadinessTests(unittest.TestCase):
    def test_readiness_report_blocks_hazmat_backend_but_records_nonce_capabilities(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = write_request(root)
            backend_crate = write_backend_crate(root, hazmat=True)
            out_dir = root / "artifacts" / "nonce-producer-backend-readiness"
            report = module.build_report(
                request_path=request_path,
                backend_crate=backend_crate,
                generated_at="2026-07-03T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)

            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary = (out_dir / "summary.md").read_text()

        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-nonce-producer-backend-readiness:v1",
        )
        self.assertEqual(manifest["readiness_status"], "backend_detected_not_admissible")
        self.assertFalse(
            manifest["admissibility"]["admissible_for_p1_nonce_handoff"]
        )
        self.assertEqual(
            manifest["backend"]["package_name"],
            "dytallix-pq-threshold",
        )
        self.assertTrue(
            manifest["capabilities"]["distributed_nonce_prf_output_share_interface"]
        )
        self.assertTrue(
            manifest["capabilities"]["distributed_nonce_prf_output_splitter"]
        )
        self.assertTrue(
            manifest["capabilities"]["distributed_nonce_masking_contribution"]
        )
        self.assertTrue(manifest["capabilities"]["centralized_nonce_prf_oracle"])
        blockers = " ".join(manifest["admissibility"]["detected_blockers"])
        self.assertIn("hazmat feature", blockers)
        self.assertIn("simulated default feature", blockers)
        self.assertIn("centralized nonce PRF oracle", blockers)
        self.assertIn("deterministic test-vector plumbing", blockers)
        self.assertIn("backend_detected_not_admissible", summary)
        self.assertIn("does not prove Criterion 2", summary)

    def test_readiness_report_marks_clean_reviewed_candidate_as_capture_admissible(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = write_request(root)
            backend_crate = write_backend_crate(root, hazmat=False)
            report = module.build_report(
                request_path=request_path,
                backend_crate=backend_crate,
                generated_at="2026-07-03T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["readiness_status"],
            "backend_candidate_admissible_pending_capture",
        )
        self.assertTrue(manifest["admissibility"]["admissible_for_p1_nonce_handoff"])
        self.assertEqual(manifest["admissibility"]["detected_blockers"], [])
        self.assertTrue(
            manifest["capabilities"]["reviewed_external_capture_contract"]
        )
        self.assertIn("--backend-command", manifest["next_capture_command"])
        self.assertEqual(
            manifest["request"]["schema"],
            REQUEST_SCHEMA,
        )

    def test_readiness_report_rejects_missing_backend_crate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = write_request(root)
            with self.assertRaisesRegex(ValueError, "backend crate Cargo.toml"):
                module.build_report(
                    request_path=request_path,
                    backend_crate=root / "missing",
                )


if __name__ == "__main__":
    unittest.main()
