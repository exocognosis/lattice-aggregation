import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stage_external_nonce_producer_capture.py"
ACTUAL_GATE_SCRIPT = ROOT / "scripts" / "verify_actual_nonce_producer_capture.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
REVIEW_SCHEMA = "lattice-aggregation:p1-external-nonce-producer-capture-review:v1"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value), encoding="utf-8")


def external_request():
    return {
        "schema": REQUEST_SCHEMA,
        "name": "p1-reviewed-nonce-producer-request-001",
        "generated_at": "2026-07-04T00:00:00Z",
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


def request_sha256(request):
    return sha256_text(canonical_json(request))


def external_capture(request):
    return {
        "name": "outside-repo-p1-nonce-producer-capture",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "producer_evidence": "p1_shamir_nonce_dkg_tee_external_capture",
        "note": "Reviewed external nonce-producer capture produced outside the repo.",
        "threshold_nonce_accounting": {
            "schema": "lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
            "validator_count": 10000,
            "threshold": 6667,
            "closure_boundary": "test nonce-accounting evidence only",
        },
        "request": {
            "schema": REQUEST_SCHEMA,
            "name": request["name"],
            "request_sha256": request_sha256(request),
        },
        "predecessors": request["predecessors"],
        "capture": {
            "source_reference": {"encoding": "hex", "value": "736f75726365"},
            "backend_implementation": {"encoding": "hex", "value": "696d706c"},
            "coordinator_attestation": {"encoding": "hex", "value": "617474657374"},
            "shamir_nonce_dkg_transcript": {"encoding": "hex", "value": "646b67"},
            "pairwise_mask_seed_commitments": {"encoding": "hex", "value": "6d61736b"},
            "nonce_share_commitments": {"encoding": "hex", "value": "7368617265"},
            "abort_accountability": {"encoding": "hex", "value": "61626f7274"},
            "external_review": {"encoding": "hex", "value": "726576696577"},
            "reviewed": True,
        },
        "expected": {
            "source_reference_digest_hex": "44" * 32,
            "backend_implementation_digest_hex": "55" * 32,
            "coordinator_attestation_digest_hex": "66" * 32,
            "shamir_nonce_dkg_transcript_digest_hex": "77" * 32,
            "pairwise_mask_seed_commitment_digest_hex": "88" * 32,
            "nonce_share_commitment_digest_hex": "99" * 32,
            "abort_accountability_digest_hex": "aa" * 32,
            "external_review_digest_hex": "bb" * 32,
            "threshold_nonce_accounting_digest_hex": "bc" * 32,
            "distributed_nonce_producer_artifact_digest_hex": "cc" * 32,
        },
    }


def admissible_readiness(request):
    return {
        "schema": READINESS_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-07-04T00:00:01Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "readiness_status": "backend_candidate_admissible_pending_capture",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "request": {
            "schema": request["schema"],
            "name": request["name"],
            "request_sha256": request_sha256(request),
            "request_path": "request/request.json",
            "capture_schema": CAPTURE_SCHEMA,
            "required_producer_evidence": "p1_shamir_nonce_dkg_tee_external_capture",
        },
        "backend": {
            "crate_path": "external-reviewed-p1-nonce-producer",
            "package_name": "external-reviewed-p1-nonce-producer",
            "version": "1.0.0",
            "description": "Reviewed external Shamir nonce DKG TEE nonce producer",
            "repository": "https://example.invalid/external-reviewed-p1-nonce-producer",
            "features": ["tee-attested"],
            "default_features": [],
            "categories": ["cryptography"],
            "cargo_toml_sha256": "dd" * 32,
            "source_tree_sha256": "ee" * 32,
            "source_file_count": 4,
            "source_inventory": [],
        },
        "capabilities": {
            "distributed_nonce_prf_output_share_interface": True,
            "distributed_nonce_prf_output_splitter": True,
            "distributed_nonce_masking_contribution": True,
            "reviewed_external_capture_contract": True,
            "centralized_nonce_prf_oracle": False,
            "hazmat_feature": False,
            "simulated_default_feature": False,
            "simulation_category": False,
            "research_grade_simulation_description": False,
            "deterministic_test_vector_plumbing": False,
        },
        "admissibility": {
            "admissible_for_p1_nonce_handoff": True,
            "detected_blockers": [],
            "blocked_reason": None,
            "requirements_to_become_admissible": [],
        },
        "closure_boundary": (
            "Backend readiness and source capability detection only; actual "
            "reviewed capture and proof review remain required."
        ),
    }


def external_review_manifest(request, capture, readiness, capture_path, readiness_path):
    capture_json = canonical_json(capture)
    return {
        "schema": REVIEW_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-07-04T00:00:02Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "reviewed_external_capture_ready",
        "capture": {
            "schema": capture["schema"],
            "producer_evidence": capture["producer_evidence"],
            "request_schema": request["schema"],
            "request_name": request["name"],
            "request_sha256": request_sha256(request),
            "capture_sha256": sha256_text(capture_json),
            "capture_file_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
        },
        "readiness": {
            "schema": readiness["schema"],
            "readiness_status": readiness["readiness_status"],
            "manifest_sha256": hashlib.sha256(readiness_path.read_bytes()).hexdigest(),
            "source_tree_sha256": readiness["backend"]["source_tree_sha256"],
        },
        "review": {
            "external_review_digest_hex": "12" * 32,
            "reviewer_identity_digest_hex": "23" * 32,
            "operator_identity_digest_hex": "34" * 32,
            "capture_environment_digest_hex": "45" * 32,
            "backend_command_digest_hex": "56" * 32,
        },
        "checks": {
            "external_backend_operated_outside_repo": True,
            "capture_generated_outside_repo": True,
            "request_binding_reviewed": True,
            "predecessor_digests_reviewed": True,
            "material_digests_reviewed": True,
            "readiness_source_tree_reviewed": True,
            "no_hazmat_prf_oracle": True,
            "no_centralized_expanded_secret_key_helper": True,
            "no_fixture_harness": True,
            "no_localnet_or_deterministic_simulation": True,
            "no_single_key_standard_provider_output": True,
        },
        "closure_boundary": (
            "External capture review dossier only; theorem closure and "
            "rejection-distribution preservation remain open."
        ),
    }


def fake_metadata(root):
    return {
        "commit": "abc123",
        "branch": "codex/p1-external-capture-file-intake",
        "dirty": False,
        "cargo_version": "cargo 1.96.0",
        "rustc_version": "rustc 1.96.0",
        "os": "TestOS",
        "python_version": "3.x",
        "cargo_lock_sha256": "lock-digest",
    }


class StageExternalNonceProducerCaptureTests(unittest.TestCase):
    def test_outside_repo_capture_file_stages_non_quarantined_attempt_for_actual_gate(
        self,
    ):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")
        gate = load_module(ACTUAL_GATE_SCRIPT, "verify_actual_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = external_request()
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = external_dir / "capture.json"
            review_path = external_dir / "review.json"
            out_dir = repo_root / "intake"
            readiness = admissible_readiness(request)
            capture = external_capture(request)
            write_json(request_path, request)
            write_json(readiness_path, readiness)
            write_json(capture_path, capture)
            write_json(
                review_path,
                external_review_manifest(
                    request,
                    capture,
                    readiness,
                    capture_path,
                    readiness_path,
                ),
            )

            report = module.build_intake(
                repo_root,
                request_path,
                readiness_path,
                capture_path,
                review_path,
                generated_at="2026-07-04T00:00:02Z",
                metadata_provider=fake_metadata,
            )
            module.write_artifacts(report, out_dir)
            gate_report = gate.build_report(repo_root, out_dir / "manifest.json")

            attempt = json.loads((out_dir / "manifest.json").read_text())
            handoff = json.loads((out_dir / "handoff" / "manifest.json").read_text())
            capture_manifest = json.loads(
                (out_dir / "handoff" / "capture" / "manifest.json").read_text()
            )

        self.assertEqual(attempt["attempt_status"], "capture_promoted")
        self.assertEqual(
            attempt["backend_execution_mode"],
            "preexisting_external_capture_file",
        )
        self.assertEqual(
            attempt["handoff_source_profile"],
            "admissible_external_backend_capture",
        )
        self.assertFalse(attempt["handoff_quarantine"]["quarantined"])
        self.assertEqual(
            handoff["handoff_source_profile"],
            "admissible_external_backend_capture",
        )
        self.assertFalse(handoff["quarantine"]["quarantined"])
        self.assertEqual(
            capture_manifest["capture_file_origin"],
            "outside_repo_capture_file",
        )
        self.assertEqual(
            capture_manifest["capture_source_profile"],
            "admissible_external_backend_capture",
        )
        self.assertEqual(
            attempt["external_capture_review"]["schema"],
            REVIEW_SCHEMA,
        )
        self.assertEqual(
            handoff["external_capture_review"]["review_status"],
            "reviewed_external_capture_ready",
        )
        self.assertEqual(
            capture_manifest["external_capture_review"]["capture_file_sha256"],
            attempt["capture_file_sha256"],
        )
        self.assertTrue(gate_report["manifest"]["actual_external_capture_ready"])
        self.assertEqual(gate_report["manifest"]["gate_status"], "actual_external_capture_ready")
        self.assertIn("does not prove Criterion 2", report["summary_md"])

    def test_repo_local_capture_file_is_rejected_before_promotion(self):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir) / "repo"
            repo_root.mkdir()
            request = external_request()
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = repo_root / "capture.json"
            write_json(request_path, request)
            write_json(readiness_path, admissible_readiness(request))
            write_json(capture_path, external_capture(request))

            with self.assertRaisesRegex(ValueError, "repo-local capture file"):
                module.build_intake(
                    repo_root,
                    request_path,
                    readiness_path,
                    capture_path,
                    metadata_provider=fake_metadata,
                )

    def test_blocked_or_stale_readiness_is_rejected_before_promotion(self):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = external_request()
            readiness = admissible_readiness(request)
            readiness["readiness_status"] = "backend_detected_not_admissible"
            readiness["admissibility"]["admissible_for_p1_nonce_handoff"] = False
            readiness["admissibility"]["detected_blockers"] = ["hazmat feature present"]
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = external_dir / "capture.json"
            write_json(request_path, request)
            write_json(readiness_path, readiness)
            write_json(capture_path, external_capture(request))

            with self.assertRaisesRegex(ValueError, "backend readiness is not admissible"):
                module.build_intake(
                    repo_root,
                    request_path,
                    readiness_path,
                    capture_path,
                    metadata_provider=fake_metadata,
                )

    def test_stale_capture_request_digest_is_rejected_before_promotion(self):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = external_request()
            capture = external_capture(request)
            capture["request"]["request_sha256"] = "ff" * 32
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = external_dir / "capture.json"
            write_json(request_path, request)
            write_json(readiness_path, admissible_readiness(request))
            write_json(capture_path, capture)

            with self.assertRaisesRegex(ValueError, "request digest mismatch"):
                module.build_intake(
                    repo_root,
                    request_path,
                    readiness_path,
                    capture_path,
                    metadata_provider=fake_metadata,
                )

    def test_missing_review_manifest_is_rejected_before_promotion(self):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = external_request()
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = external_dir / "capture.json"
            write_json(request_path, request)
            write_json(readiness_path, admissible_readiness(request))
            write_json(capture_path, external_capture(request))

            with self.assertRaisesRegex(ValueError, "external review manifest"):
                module.build_intake(
                    repo_root,
                    request_path,
                    readiness_path,
                    capture_path,
                    external_dir / "missing-review.json",
                    metadata_provider=fake_metadata,
                )

    def test_mismatched_review_manifest_is_rejected_before_promotion(self):
        module = load_module(SCRIPT, "stage_external_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = external_request()
            readiness = admissible_readiness(request)
            capture = external_capture(request)
            request_path = repo_root / "request.json"
            readiness_path = repo_root / "readiness.json"
            capture_path = external_dir / "capture.json"
            review_path = external_dir / "review.json"
            write_json(request_path, request)
            write_json(readiness_path, readiness)
            write_json(capture_path, capture)
            review = external_review_manifest(
                request,
                capture,
                readiness,
                capture_path,
                readiness_path,
            )
            review["checks"]["no_hazmat_prf_oracle"] = False
            write_json(review_path, review)

            with self.assertRaisesRegex(ValueError, "external review check failed"):
                module.build_intake(
                    repo_root,
                    request_path,
                    readiness_path,
                    capture_path,
                    review_path,
                    metadata_provider=fake_metadata,
                )


if __name__ == "__main__":
    unittest.main()
