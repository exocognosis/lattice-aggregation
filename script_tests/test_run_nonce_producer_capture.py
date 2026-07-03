import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_nonce_producer_capture.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"


def load_module():
    spec = importlib.util.spec_from_file_location("run_nonce_producer_capture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_metadata(root):
    return {
        "commit": "abc123",
        "branch": "codex/p1-nonce-producer-capture-runner",
        "dirty": False,
        "cargo_version": "cargo 1.96.0",
        "rustc_version": "rustc 1.96.0",
        "os": "TestOS",
        "python_version": "3.x",
        "cargo_lock_sha256": "lock-digest",
    }


def external_request():
    return {
        "schema": REQUEST_SCHEMA,
        "name": "external-nonce-producer-smoke-request",
        "generated_at": "2026-07-02T00:00:00Z",
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
    module = load_module()
    return module.sha256_text(module.canonical_json(request))


def external_capture():
    request = external_request()
    return {
        "name": "external-nonce-producer-smoke-capture",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "producer_evidence": "p1_shamir_nonce_dkg_tee_external_capture",
        "note": "External nonce producer capture produced outside deterministic simulation.",
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
            "distributed_nonce_producer_artifact_digest_hex": "cc" * 32,
        },
    }


def fake_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.25,
        "stdout": json.dumps(external_capture()),
        "stderr": "",
    }


def fixture_capture_runner(command, root, env):
    capture = external_capture()
    capture["producer_evidence"] = "fixture_harness"
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def incomplete_capture_runner(command, root, env):
    capture = external_capture()
    del capture["expected"]["distributed_nonce_producer_artifact_digest_hex"]
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def malformed_capture_runner(command, root, env):
    capture = external_capture()
    capture["capture"]["backend_implementation"] = {"encoding": "base64", "value": "bad"}
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def failing_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 23,
        "duration_seconds": 0.4,
        "stdout": "partial stdout",
        "stderr": "backend stderr",
    }


class NonceProducerCaptureRunnerTests(unittest.TestCase):
    def test_build_report_invokes_nonce_producer_capture_runner_and_writes_importable_capture_json(
        self,
    ):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            out_dir = root / "artifacts" / "nonce-producer-capture"
            report = module.build_report(
                root,
                request_path=request_path,
                backend_command=["/opt/nonce-producer", "emit-capture"],
                command_runner=fake_capture_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-07-02T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)

            capture = json.loads((out_dir / "capture.json").read_text())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary_md = (out_dir / "summary.md").read_text()

        self.assertEqual(capture["schema"], CAPTURE_SCHEMA)
        self.assertEqual(capture["request"]["schema"], REQUEST_SCHEMA)
        self.assertEqual(capture["request"]["request_sha256"], request_sha256(external_request()))
        self.assertEqual(capture["producer_evidence"], "p1_shamir_nonce_dkg_tee_external_capture")
        self.assertEqual(capture["capture"]["reviewed"], True)
        self.assertIn("shamir_nonce_dkg_transcript", capture["capture"])
        self.assertIn("expected", capture)
        self.assertEqual(manifest["claim_boundary"], "conformance/proof-review evidence only")
        self.assertEqual(manifest["request_sha256"], request_sha256(external_request()))
        self.assertEqual(manifest["producer_evidence"], "p1_shamir_nonce_dkg_tee_external_capture")
        self.assertEqual(manifest["backend_command"], ["/opt/nonce-producer", "emit-capture"])
        provenance = manifest["external_capture_provenance"]
        self.assertEqual(
            provenance["schema"],
            "lattice-aggregation:external-capture-provenance:v1",
        )
        self.assertEqual(provenance["request_sha256"], request_sha256(external_request()))
        self.assertEqual(provenance["capture_sha256"], manifest["capture_sha256"])
        self.assertEqual(provenance["evidence_class"], manifest["producer_evidence"])
        self.assertEqual(provenance["runner_status"], "evidence_present_unclosed")
        self.assertEqual(provenance["claim_boundary"], "conformance/proof-review evidence only")
        self.assertIn("backend_implementation_digest_hex", provenance["expected_digest_fields"])
        self.assertIn("cargo_lock_sha256", provenance["metadata_fields"])
        self.assertIn("backend_command_sha256", provenance)
        self.assertNotIn("localnet", " ".join(manifest["backend_command"]))
        self.assertIn("evidence_present_unclosed", summary_md)
        self.assertIn("does not prove Criterion 2", summary_md)

    def test_build_report_raises_structured_execution_error_with_command_output(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "backend stderr") as caught:
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=failing_capture_runner,
                    metadata_provider=fake_metadata,
                )

        self.assertEqual(caught.exception.phase, "execution")
        self.assertEqual(caught.exception.result["exit_code"], 23)
        self.assertEqual(caught.exception.result["stdout"], "partial stdout")
        self.assertEqual(caught.exception.result["stderr"], "backend stderr")

    def test_build_report_raises_structured_validation_error_with_command_output(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical capture JSON") as caught:
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=lambda command, root, env: {
                        "command": command,
                        "exit_code": 0,
                        "duration_seconds": 0.2,
                        "stdout": "not json",
                        "stderr": "warning",
                    },
                    metadata_provider=fake_metadata,
                )

        self.assertEqual(caught.exception.phase, "validation")
        self.assertEqual(caught.exception.result["exit_code"], 0)
        self.assertEqual(caught.exception.result["stdout"], "not json")
        self.assertEqual(caught.exception.result["stderr"], "warning")

    def test_build_report_rejects_capture_that_omits_or_stales_request_binding(self):
        module = load_module()

        def missing_request_runner(command, root, env):
            capture = external_capture()
            del capture["request"]
            return {"command": command, "exit_code": 0, "duration_seconds": 0.2, "stdout": json.dumps(capture), "stderr": ""}

        def stale_request_runner(command, root, env):
            capture = external_capture()
            capture["request"]["request_sha256"] = "99" * 32
            return {"command": command, "exit_code": 0, "duration_seconds": 0.2, "stdout": json.dumps(capture), "stderr": ""}

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "request binding"):
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=missing_request_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "request digest mismatch"):
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=stale_request_runner,
                    metadata_provider=fake_metadata,
                )

    def test_build_report_rejects_hazmat_localnet_or_fixture_sources(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_report(
                    root,
                    backend_command=["cargo", "run", "--example", "validator_localnet"],
                    command_runner=fake_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_report(
                    root,
                    backend_command=["hazmat-centralized-prf", "emit-capture"],
                    command_runner=fake_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "actual external nonce-producer"):
                module.build_report(
                    root,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=fixture_capture_runner,
                    metadata_provider=fake_metadata,
                )

    def test_build_report_rejects_non_importable_capture_shape_before_artifact_write(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "missing expected digest"):
                module.build_report(
                    root,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=incomplete_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "byte encoding"):
                module.build_report(
                    root,
                    backend_command=["/opt/nonce-producer", "emit-capture"],
                    command_runner=malformed_capture_runner,
                    metadata_provider=fake_metadata,
                )


if __name__ == "__main__":
    unittest.main()
