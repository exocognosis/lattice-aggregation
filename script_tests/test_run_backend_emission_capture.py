import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_backend_emission_capture.py"


def load_module():
    spec = importlib.util.spec_from_file_location("run_backend_emission_capture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_metadata(root):
    return {
        "commit": "abc123",
        "branch": "codex/actual-crypto-capture-runner",
        "dirty": False,
        "cargo_version": "cargo 1.96.0",
        "rustc_version": "rustc 1.96.0",
        "os": "TestOS",
        "python_version": "3.x",
        "cargo_lock_sha256": "lock-digest",
    }


def external_capture():
    digest = "11" * 32
    return {
        "name": "external-threshold-backend-smoke-capture",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "note": "External backend capture produced outside deterministic simulation.",
        "predecessors": {
            "selected_profile_binding_digest_hex": digest,
            "threshold_output_certificate_digest_hex": "22" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "33" * 32,
        },
        "capture": {
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "public_key_hex": "06" * 1952,
            "message": {
                "encoding": "hex",
                "value": "74657374206d657373616765",
            },
            "aggregate_signature_hex": "2a" * 3309,
            "backend_source_package": {
                "encoding": "hex",
                "value": "736f75726365",
            },
            "backend_implementation": {
                "encoding": "hex",
                "value": "696d706c656d656e746174696f6e",
            },
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


def fake_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.25,
        "stdout": json.dumps(external_capture()),
        "stderr": "",
    }


def localnet_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": "claim_boundary=local validator-network engineering telemetry\nvalidators=4\n",
        "stderr": "",
    }


def fixture_capture_runner(command, root, env):
    capture = external_capture()
    capture["backend_evidence"] = "real_threshold_mldsa_capture_schema_fixture"
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def forged_external_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(external_capture()),
        "stderr": "",
    }


def incomplete_capture_runner(command, root, env):
    capture = external_capture()
    del capture["expected"]["artifact_digest_hex"]
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def malformed_tuple_capture_runner(command, root, env):
    capture = external_capture()
    capture["capture"]["public_key_hex"] = "06"
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def wrong_profile_capture_runner(command, root, env):
    capture = external_capture()
    capture["selected_profile"] = "simulated localnet profile"
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


def unknown_field_capture_runner(command, root, env):
    capture = external_capture()
    capture["capture"]["unexpected"] = "not in the Rust capture schema"
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(capture),
        "stderr": "",
    }


class BackendEmissionCaptureRunnerTests(unittest.TestCase):
    def test_build_report_invokes_backend_capture_runner_and_writes_importable_capture_json(
        self,
    ):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "artifacts" / "backend-capture"
            report = module.build_report(
                root,
                backend_command=["/opt/threshold-backend", "emit-capture"],
                command_runner=fake_capture_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-07-01T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)

            capture = json.loads((out_dir / "capture.json").read_text())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary_md = (out_dir / "summary.md").read_text()

        self.assertEqual(
            capture["schema"],
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        )
        self.assertEqual(capture["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(capture["capture"]["validator_count"], 10000)
        self.assertEqual(capture["capture"]["threshold"], 6667)
        self.assertEqual(capture["capture"]["aggregate_signature_len"], 3309)
        self.assertTrue(capture["capture"]["mutated_message_rejected"])
        self.assertTrue(capture["capture"]["mutated_public_key_rejected"])
        self.assertTrue(capture["capture"]["mutated_signature_rejected"])
        self.assertIn("predecessors", capture)
        self.assertIn("expected", capture)
        self.assertEqual(
            manifest["claim_boundary"], "conformance/proof-review evidence only"
        )
        self.assertEqual(manifest["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(
            manifest["backend_command"], ["/opt/threshold-backend", "emit-capture"]
        )
        self.assertNotIn("validator_localnet", " ".join(manifest["backend_command"]))
        self.assertNotIn("run_simulation_benchmarks", " ".join(manifest["backend_command"]))
        self.assertIn("evidence_present_unclosed", summary_md)

    def test_build_report_rejects_deterministic_simulation_or_localnet_capture_source(
        self,
    ):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_report(
                    root,
                    backend_command=["cargo", "run", "--example", "validator_localnet"],
                    command_runner=localnet_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "actual external real-threshold"):
                module.build_report(
                    root,
                    backend_command=["fixture-backend"],
                    command_runner=fixture_capture_runner,
                    metadata_provider=fake_metadata,
                )

    def test_build_report_rejects_forged_external_json_from_localnet_or_simulation_command(
        self,
    ):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_report(
                    root,
                    backend_command=[
                        "cargo",
                        "run",
                        "--example",
                        "validator_localnet",
                        "--emit-capture-json",
                    ],
                    command_runner=forged_external_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_report(
                    root,
                    backend_command=["./localnet-capture", "emit-capture-json"],
                    command_runner=forged_external_capture_runner,
                    metadata_provider=fake_metadata,
                )

    def test_build_report_rejects_non_importable_capture_shape_before_artifact_write(
        self,
    ):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "missing expected digest"):
                module.build_report(
                    root,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=incomplete_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "public_key_hex"):
                module.build_report(
                    root,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=malformed_tuple_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "selected profile"):
                module.build_report(
                    root,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=wrong_profile_capture_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "unknown capture field"):
                module.build_report(
                    root,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=unknown_field_capture_runner,
                    metadata_provider=fake_metadata,
                )


if __name__ == "__main__":
    unittest.main()
