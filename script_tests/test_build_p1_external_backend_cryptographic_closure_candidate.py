import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p1_external_backend_cryptographic_closure_candidate.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_p1_external_backend_cryptographic_closure_candidate",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def actual_nonce_gate(ready):
    return {
        "schema": "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "gate_status": (
            "actual_external_capture_ready"
            if ready
            else "actual_external_capture_missing"
        ),
        "actual_external_capture_ready": ready,
        "expected_source_profile": "admissible_external_backend_capture",
        "attempt_source_profile": (
            "admissible_external_backend_capture"
            if ready
            else "repo_reference_cli_capture"
        ),
        "handoff_source_profile": (
            "admissible_external_backend_capture"
            if ready
            else "repo_reference_cli_capture"
        ),
        "blockers": [] if ready else ["actual external capture missing"],
    }


def backend_manifest():
    return {
        "schema_version": 1,
        "claim_boundary": "conformance/proof-review evidence",
        "runner_status": "evidence_present_unclosed",
        "capture_schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "request_schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
        "request_name": "synthetic-real-threshold-request",
        "request_sha256": "11" * 32,
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "backend_command": ["/opt/threshold-backend", "emit-capture"],
        "exit_code": 0,
        "validator_count": 10000,
        "threshold": 6667,
        "aggregate_signature_len": 3309,
        "capture_sha256": "22" * 32,
        "backend_core_admissibility": {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "signature_origin": "threshold_partial_aggregation",
            "reasons": [],
        },
    }


def backend_capture():
    return {
        "name": "synthetic-real-threshold-capture",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "cryptographic_core": {
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
            "provider": None,
            "signature_origin": "threshold_partial_aggregation",
            "validator_count": 10000,
            "threshold": 6667,
            "distributed_threshold_core": {
                "distributed_keygen_vss": True,
                "partial_signing_over_secret_shares": True,
                "partial_z_i_hint_aggregation": True,
                "fips204_rejection_loop_over_threshold_partials": True,
                "accepted_aggregate_distribution_proven": False,
            },
        },
        "request": {
            "schema": "lattice-aggregation:p1-real-threshold-backend-emission-request:v1",
            "name": "synthetic-real-threshold-request",
            "request_sha256": "11" * 32,
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": "33" * 32,
            "threshold_output_certificate_digest_hex": "44" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "55" * 32,
        },
        "capture": {
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "public_key_hex": "06" * 1952,
            "message": {"encoding": "hex", "value": "74657374"},
            "aggregate_signature_hex": "2a" * 3309,
            "backend_source_package": {"encoding": "hex", "value": "736f75726365"},
            "backend_implementation": {"encoding": "hex", "value": "696d706c"},
            "backend_transcript": {"encoding": "hex", "value": "7472616e736372697074"},
            "mutated_message_rejected": True,
            "mutated_public_key_rejected": True,
            "mutated_signature_rejected": True,
            "reviewed": True,
        },
        "expected": {
            "backend_evidence_digest_hex": "66" * 32,
            "backend_source_package_digest_hex": "77" * 32,
            "backend_implementation_digest_hex": "88" * 32,
            "backend_transcript_digest_hex": "99" * 32,
            "artifact_digest_hex": "aa" * 32,
            "public_key_digest_hex": "bb" * 32,
            "message_digest_hex": "cc" * 32,
            "accepted_signature_digest_hex": "dd" * 32,
        },
    }


def mark_as_threshold_seed_reconstruction(manifest, capture):
    manifest["backend_core_admissibility"].update(
        {
            "strict_threshold_core_admissible": True,
            "quarantined": False,
            "core_mode": "threshold_seed_reconstruction_mldsa65_provider",
            "signature_origin": (
                "threshold_seed_reconstruction_standard_mldsa65_provider"
            ),
            "reasons": [],
        }
    )
    capture["cryptographic_core"].update(
        {
            "core_mode": "threshold_seed_reconstruction_mldsa65_provider",
            "signature_origin": (
                "threshold_seed_reconstruction_standard_mldsa65_provider"
            ),
        }
    )


def rejection_batch(close_candidate=True):
    return {
        "name": "synthetic-p1-rejection-equivalence-batch",
        "schema": "lattice-aggregation:p1-rejection-equivalence-batch:v1",
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "mldsa65-centralized-vs-threshold-rejection-batch",
        "parameters": {
            "validator_count": 10000,
            "threshold": 6667,
            "attempts": 16,
            "nonce_prf_producer": "distributed-nonce-prf-output-shares",
            "reviewed_distributed_nonce_producer_present": True,
            "distributed_nonce_producer_artifact_digest": "ee" * 32,
        },
        "result": {
            "predicate_mismatch_count": 0,
            "challenge_digest_matches": True,
            "accepted_or_rejected_matches": True,
            "saw_threshold_rejected_attempt": True,
            "saw_threshold_accepted_attempt": True,
            "standard_verifier_accepts_threshold_signature": True,
            "repo_provider_accepts_threshold_signature": True,
            "close_candidate": close_candidate,
        },
        "predicate_mismatches": [],
        "claim_flags": {
            "claims_rejection_distribution_preservation": False,
            "claims_theorem_closure": False,
        },
    }


class P1ExternalBackendClosureCandidateBuilderTests(unittest.TestCase):
    def test_missing_inputs_build_blocked_nonclosure_candidate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce-gate" / "manifest.json"
            write_json(nonce_path, actual_nonce_gate(False))

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=root / "backend" / "manifest.json",
                backend_capture_path=root / "backend" / "capture.json",
                rejection_batch_path=root / "rejection" / "batch.json",
            )

        manifest = report["manifest"]
        blockers = " ".join(manifest["blockers"])
        self.assertEqual(
            manifest["schema"],
            "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1",
        )
        self.assertEqual(manifest["status"], "evidence_present_unclosed")
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["claims_theorem_closure"])
        self.assertFalse(manifest["claims_rejection_distribution_preservation"])
        self.assertFalse(manifest["checks"]["strict_external_nonce_capture_ready"])
        self.assertIn("actual external nonce capture readiness required", blockers)
        self.assertIn("real threshold backend emission capture is missing", blockers)
        self.assertIn("rejection-distribution comparison is missing", blockers)
        self.assertIn("pending theorem-closure review", report["summary_md"])

    def test_complete_evidence_bundle_computes_close_candidate_without_claiming_closure(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce-gate" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_path = root / "rejection" / "batch.json"
            out_dir = root / "candidate"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_path, rejection_batch(close_candidate=True))

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_path,
                generated_at="2026-07-04T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)
            written_manifest = json.loads((out_dir / "manifest.json").read_text())

        self.assertTrue(written_manifest["close_candidate"])
        self.assertEqual(written_manifest["blockers"], [])
        self.assertTrue(all(written_manifest["checks"].values()))
        self.assertFalse(written_manifest["claims_theorem_closure"])
        self.assertFalse(written_manifest["claims_selected_backend_proof_closure"])
        self.assertFalse(written_manifest["claims_rejection_distribution_preservation"])

    def test_distribution_comparison_must_also_be_close_candidate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce-gate" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_path = root / "rejection" / "batch.json"
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, backend_manifest())
            write_json(backend_capture_path, backend_capture())
            write_json(rejection_path, rejection_batch(close_candidate=False))

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_path,
            )

        self.assertFalse(report["manifest"]["close_candidate"])
        self.assertFalse(report["manifest"]["checks"]["comparison_close_candidate"])
        self.assertIn(
            "rejection-distribution comparison requires close-candidate evidence",
            report["manifest"]["blockers"],
        )

    def test_threshold_seed_reconstruction_cannot_satisfy_strict_backend_core(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nonce_path = root / "nonce-gate" / "manifest.json"
            backend_manifest_path = root / "backend" / "manifest.json"
            backend_capture_path = root / "backend" / "capture.json"
            rejection_path = root / "rejection" / "batch.json"
            manifest_payload = backend_manifest()
            capture_payload = backend_capture()
            mark_as_threshold_seed_reconstruction(manifest_payload, capture_payload)
            write_json(nonce_path, actual_nonce_gate(True))
            write_json(backend_manifest_path, manifest_payload)
            write_json(backend_capture_path, capture_payload)
            write_json(rejection_path, rejection_batch(close_candidate=True))

            report = module.build_report(
                root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=backend_manifest_path,
                backend_capture_path=backend_capture_path,
                rejection_batch_path=rejection_path,
            )

        manifest = report["manifest"]
        blockers = " ".join(manifest["blockers"])
        self.assertFalse(manifest["close_candidate"])
        self.assertFalse(manifest["checks"]["real_threshold_emission_present"])
        self.assertIn(
            "threshold seed-reconstruction capture cannot satisfy real threshold partial aggregation",
            blockers,
        )


if __name__ == "__main__":
    unittest.main()
