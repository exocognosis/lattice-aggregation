import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stage_external_backend_emission_capture.py"
CANDIDATE_SCRIPT = (
    ROOT / "scripts" / "build_p1_external_backend_cryptographic_closure_candidate.py"
)
REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
REVIEW_SCHEMA = "lattice-aggregation:p1-external-backend-emission-capture-review:v1"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value), encoding="utf-8")


def backend_request():
    return {
        "schema": REQUEST_SCHEMA,
        "name": "p1-real-threshold-backend-emission-request-001",
        "generated_at": "2026-07-05T00:00:00Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "request_status": "evidence_present_unclosed",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "validator_count": 10000,
        "threshold": 6667,
        "aggregate_signature_len": 3309,
        "message": {
            "encoding": "hex",
            "value": "6f726967696e616c206170706c69636174696f6e206d657373616765",
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": "11" * 32,
            "threshold_output_certificate_digest_hex": "22" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "33" * 32,
        },
        "required_capture": {
            "schema": CAPTURE_SCHEMA,
            "backend_evidence": "real_threshold_mldsa_external_capture",
            "claim_boundary": "conformance/proof-review evidence only",
            "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "mutated_message_rejected": True,
            "mutated_public_key_rejected": True,
            "mutated_signature_rejected": True,
            "reviewed": True,
        },
        "forbidden_capture_sources": [
            "localnet",
            "deterministic simulation",
            "fixture harness",
            "ordinary single-key standard-provider output",
        ],
    }


def request_sha256(request):
    return sha256_text(canonical_json(request))


def backend_capture(request):
    return {
        "name": "outside-repo-real-threshold-backend-capture",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "note": "Reviewed external backend capture produced outside the repository.",
        "request": {
            "schema": REQUEST_SCHEMA,
            "name": request["name"],
            "request_sha256": request_sha256(request),
        },
        "predecessors": request["predecessors"],
        "capture": {
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "public_key_hex": "06" * 1952,
            "message": request["message"],
            "aggregate_signature_hex": "2a" * 3309,
            "backend_source_package": {"encoding": "hex", "value": "736f75726365"},
            "backend_implementation": {"encoding": "hex", "value": "696d706c"},
            "backend_transcript": {
                "encoding": "hex",
                "value": "7472616e736372697074",
            },
            "mutated_message_rejected": True,
            "mutated_public_key_rejected": True,
            "mutated_signature_rejected": True,
            "reviewed": True,
        },
        "expected": {
            "backend_evidence_digest_hex": "44" * 32,
            "backend_source_package_digest_hex": "55" * 32,
            "backend_implementation_digest_hex": "66" * 32,
            "backend_transcript_digest_hex": "77" * 32,
            "artifact_digest_hex": "88" * 32,
            "public_key_digest_hex": "99" * 32,
            "message_digest_hex": "aa" * 32,
            "accepted_signature_digest_hex": "bb" * 32,
        },
    }


def external_review_manifest(request, capture, capture_path):
    capture_json = canonical_json(capture)
    return {
        "schema": REVIEW_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-07-05T00:00:01Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "reviewed_external_backend_emission_capture_ready",
        "capture": {
            "schema": capture["schema"],
            "backend_evidence": capture["backend_evidence"],
            "request_schema": request["schema"],
            "request_name": request["name"],
            "request_sha256": request_sha256(request),
            "capture_sha256": sha256_text(capture_json),
            "capture_file_sha256": sha256_path(capture_path),
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
            "backend_material_digests_reviewed": True,
            "mutation_rejection_reviewed": True,
            "standard_verifier_acceptance_reviewed": True,
            "no_localnet_or_deterministic_simulation": True,
            "no_fixture_harness": True,
            "no_single_key_standard_provider_output": True,
        },
        "closure_boundary": (
            "External backend-emission capture review dossier only; theorem "
            "closure and rejection-distribution preservation remain open."
        ),
    }


def actual_nonce_gate():
    return {
        "schema": "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1",
        "claim_boundary": "conformance/proof-review evidence only",
        "gate_status": "actual_external_capture_ready",
        "actual_external_capture_ready": True,
        "expected_source_profile": "admissible_external_backend_capture",
        "attempt_source_profile": "admissible_external_backend_capture",
        "handoff_source_profile": "admissible_external_backend_capture",
        "blockers": [],
    }


def rejection_batch():
    return {
        "name": "outside-repo-rejection-equivalence-batch",
        "schema": "lattice-aggregation:p1-rejection-equivalence-batch:v1",
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "mldsa65-centralized-vs-threshold-rejection-batch",
        "parameters": {
            "validator_count": 10000,
            "threshold": 6667,
            "attempts": 16,
            "nonce_prf_producer": "distributed-nonce-prf-output-shares",
            "reviewed_distributed_nonce_producer_present": True,
            "distributed_nonce_producer_artifact_digest": "cc" * 32,
        },
        "result": {
            "predicate_mismatch_count": 0,
            "challenge_digest_matches": True,
            "accepted_or_rejected_matches": True,
            "saw_threshold_rejected_attempt": True,
            "saw_threshold_accepted_attempt": True,
            "standard_verifier_accepts_threshold_signature": True,
            "repo_provider_accepts_threshold_signature": True,
            "close_candidate": True,
        },
        "predicate_mismatches": [],
        "claim_flags": {
            "claims_rejection_distribution_preservation": False,
            "claims_theorem_closure": False,
        },
    }


def fake_metadata(root):
    return {
        "commit": "abc123",
        "branch": "codex/p1-real-external-evidence-attempt",
        "dirty": False,
        "cargo_version": "cargo 1.96.0",
        "rustc_version": "rustc 1.96.0",
        "os": "TestOS",
        "python_version": "3.x",
        "cargo_lock_sha256": "lock-digest",
    }


class StageExternalBackendEmissionCaptureTests(unittest.TestCase):
    def test_outside_repo_capture_file_writes_batch8_consumable_backend_capture(self):
        module = load_module(SCRIPT, "stage_external_backend_emission_capture")
        candidate = load_module(
            CANDIDATE_SCRIPT,
            "build_p1_external_backend_cryptographic_closure_candidate",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = backend_request()
            capture = backend_capture(request)
            request_path = repo_root / "request.json"
            capture_path = external_dir / "capture.json"
            review_path = external_dir / "review.json"
            out_dir = repo_root / "artifacts" / "backend-emission-capture" / "latest"
            nonce_path = repo_root / "nonce" / "manifest.json"
            rejection_path = repo_root / "rejection" / "batch.json"
            write_json(request_path, request)
            write_json(capture_path, capture)
            write_json(review_path, external_review_manifest(request, capture, capture_path))
            write_json(nonce_path, actual_nonce_gate())
            write_json(rejection_path, rejection_batch())

            report = module.build_intake(
                repo_root,
                request_path,
                capture_path,
                review_path,
                generated_at="2026-07-05T00:00:02Z",
                metadata_provider=fake_metadata,
            )
            module.write_artifacts(report, out_dir)
            candidate_report = candidate.build_report(
                repo_root,
                nonce_gate_path=nonce_path,
                backend_manifest_path=out_dir / "manifest.json",
                backend_capture_path=out_dir / "capture.json",
                rejection_batch_path=rejection_path,
                generated_at="2026-07-05T00:00:03Z",
            )

            manifest = json.loads((out_dir / "manifest.json").read_text())
            written_capture = json.loads((out_dir / "capture.json").read_text())

        self.assertEqual(manifest["runner_status"], "evidence_present_unclosed")
        self.assertEqual(
            manifest["backend_execution_mode"],
            "preexisting_external_capture_file",
        )
        self.assertEqual(manifest["capture_file_origin"], "outside_repo_capture_file")
        self.assertEqual(manifest["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(manifest["exit_code"], 0)
        self.assertEqual(manifest["external_capture_review"]["schema"], REVIEW_SCHEMA)
        self.assertEqual(
            manifest["external_capture_review"]["review_status"],
            "reviewed_external_backend_emission_capture_ready",
        )
        self.assertEqual(
            manifest["external_capture_review"]["review_file_origin"],
            "outside_repo_review_manifest",
        )
        self.assertEqual(written_capture["request"]["request_sha256"], request_sha256(request))
        self.assertTrue(candidate_report["manifest"]["close_candidate"])
        self.assertTrue(candidate_report["manifest"]["checks"]["real_threshold_emission_present"])
        self.assertIn("does not prove Criterion 2", report["summary_md"])

    def test_repo_local_capture_file_is_rejected_before_artifact_write(self):
        module = load_module(SCRIPT, "stage_external_backend_emission_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir) / "repo"
            repo_root.mkdir()
            request = backend_request()
            request_path = repo_root / "request.json"
            capture_path = repo_root / "capture.json"
            write_json(request_path, request)
            write_json(capture_path, backend_capture(request))

            with self.assertRaisesRegex(ValueError, "repo-local capture file"):
                module.build_intake(repo_root, request_path, capture_path)

    def test_missing_or_failed_review_manifest_is_rejected_before_artifact_write(self):
        module = load_module(SCRIPT, "stage_external_backend_emission_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = backend_request()
            capture = backend_capture(request)
            request_path = repo_root / "request.json"
            capture_path = external_dir / "capture.json"
            review_path = external_dir / "review.json"
            write_json(request_path, request)
            write_json(capture_path, capture)
            review = external_review_manifest(request, capture, capture_path)
            review["checks"]["standard_verifier_acceptance_reviewed"] = False
            write_json(review_path, review)

            with self.assertRaisesRegex(ValueError, "external review check failed"):
                module.build_intake(repo_root, request_path, capture_path, review_path)

            with self.assertRaisesRegex(ValueError, "external review manifest"):
                module.build_intake(
                    repo_root,
                    request_path,
                    capture_path,
                    external_dir / "missing-review.json",
                )

    def test_stale_capture_request_digest_is_rejected_before_artifact_write(self):
        module = load_module(SCRIPT, "stage_external_backend_emission_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            external_dir = temp_root / "external"
            request = backend_request()
            capture = backend_capture(request)
            capture["request"]["request_sha256"] = "ff" * 32
            request_path = repo_root / "request.json"
            capture_path = external_dir / "capture.json"
            write_json(request_path, request)
            write_json(capture_path, capture)

            with self.assertRaisesRegex(ValueError, "request digest mismatch"):
                module.build_intake(repo_root, request_path, capture_path)


if __name__ == "__main__":
    unittest.main()
