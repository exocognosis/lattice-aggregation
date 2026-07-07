import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_backend_emission_capture.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"


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
    request = external_request()
    request_digest = request_sha256(request)
    return {
        "name": "external-threshold-backend-capture",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": "conformance/proof-review evidence",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "note": "External backend capture produced outside deterministic simulation.",
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
            "schema": REQUEST_SCHEMA,
            "name": request["name"],
            "request_sha256": request_digest,
        },
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
            "threshold_core_accounting_digest_hex": "cc" * 32,
            "artifact_digest_hex": "88" * 32,
            "public_key_digest_hex": "99" * 32,
            "message_digest_hex": "aa" * 32,
            "accepted_signature_digest_hex": "bb" * 32,
        },
    }


def threshold_seed_reconstruction_capture():
    capture = external_capture()
    capture["cryptographic_core"].update(
        {
            "core_mode": "threshold_seed_reconstruction_mldsa65_provider",
            "signature_origin": (
                "threshold_seed_reconstruction_standard_mldsa65_provider"
            ),
        }
    )
    return capture


def tee_hsm_no_export_capture():
    capture = external_capture()
    capture["cryptographic_core"].update(
        {
            "core_mode": "tee_hsm_no_export_threshold_mldsa65_provider",
            "provider": "tee-hsm-no-export mldsa65 provider",
            "signature_origin": "tee_hsm_no_export_standard_mldsa65_provider",
            "distributed_threshold_core": {
                "distributed_keygen_vss": False,
                "tee_hsm_no_export_trust_record_reviewed": True,
                "no_single_exposed_mldsa_secret_key": True,
                "threshold_authorization_enforced": True,
                "standard_verifier_compatible_output": True,
                "accepted_aggregate_distribution_proven": False,
            },
        }
    )
    return capture


def external_request():
    return {
        "schema": REQUEST_SCHEMA,
        "name": "external-threshold-backend-smoke-request",
        "generated_at": "2026-07-01T00:00:00Z",
        "claim_boundary": "conformance/proof-review evidence",
        "request_status": "evidence_present_unclosed",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "validator_count": 10000,
        "threshold": 6667,
        "aggregate_signature_len": 3309,
        "message": {
            "encoding": "hex",
            "value": "74657374206d657373616765",
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": "11" * 32,
            "threshold_output_certificate_digest_hex": "22" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "33" * 32,
        },
        "required_capture": {
            "schema": CAPTURE_SCHEMA,
            "backend_evidence": "real_threshold_mldsa_external_capture",
            "claim_boundary": "conformance/proof-review evidence",
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
    module = load_module()
    return module.sha256_text(module.canonical_json(request))


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


def reconstruction_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(threshold_seed_reconstruction_capture()),
        "stderr": "",
    }


def tee_hsm_no_export_capture_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 0.2,
        "stdout": json.dumps(tee_hsm_no_export_capture()),
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
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            out_dir = root / "artifacts" / "backend-capture"
            report = module.build_report(
                root,
                request_path=request_path,
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
            CAPTURE_SCHEMA,
        )
        self.assertEqual(capture["request"]["schema"], REQUEST_SCHEMA)
        self.assertEqual(
            capture["request"]["request_sha256"],
            request_sha256(external_request()),
        )
        self.assertEqual(manifest["request_sha256"], request_sha256(external_request()))
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
            manifest["claim_boundary"], "conformance/proof-review evidence"
        )
        self.assertEqual(manifest["backend_evidence"], "real_threshold_mldsa_external_capture")
        self.assertEqual(
            manifest["backend_command"], ["/opt/threshold-backend", "emit-capture"]
        )
        self.assertEqual(
            manifest["backend_command_origin"],
            "outside_repo_executable_or_script",
        )
        self.assertEqual(
            manifest["backend_core_admissibility"]["core_mode"],
            "distributed_threshold_mldsa65_partial_aggregation",
        )
        self.assertTrue(
            manifest["backend_core_admissibility"][
                "strict_threshold_core_admissible"
            ]
        )
        self.assertFalse(manifest["backend_core_admissibility"]["quarantined"])
        provenance = manifest["external_capture_provenance"]
        self.assertEqual(
            provenance["schema"],
            "lattice-aggregation:external-capture-provenance:v1",
        )
        self.assertEqual(provenance["request_sha256"], request_sha256(external_request()))
        self.assertEqual(provenance["capture_sha256"], manifest["capture_sha256"])
        self.assertEqual(provenance["evidence_class"], manifest["backend_evidence"])
        self.assertEqual(provenance["runner_status"], "evidence_present_unclosed")
        self.assertEqual(
            provenance["claim_boundary"], "conformance/proof-review evidence"
        )
        self.assertIn(
            "backend_implementation_digest_hex", provenance["expected_digest_fields"]
        )
        self.assertIn("cargo_lock_sha256", provenance["metadata_fields"])
        self.assertIn("backend_command_sha256", provenance)
        self.assertEqual(
            provenance["backend_command_origin"],
            "outside_repo_executable_or_script",
        )
        self.assertNotIn("validator_localnet", " ".join(manifest["backend_command"]))
        self.assertNotIn("run_simulation_benchmarks", " ".join(manifest["backend_command"]))
        self.assertIn("evidence_present_unclosed", summary_md)

    def test_threshold_seed_reconstruction_capture_is_quarantined(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            report = module.build_report(
                root,
                request_path=request_path,
                backend_command=["/opt/threshold-backend", "emit-capture"],
                command_runner=reconstruction_capture_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-07-01T00:00:00Z",
            )

        admissibility = report["manifest"]["backend_core_admissibility"]
        self.assertFalse(admissibility["strict_threshold_core_admissible"])
        self.assertTrue(admissibility["quarantined"])
        self.assertIn(
            "threshold seed-reconstruction core mode",
            admissibility["reasons"],
        )
        self.assertIn(
            "threshold seed-reconstruction standard-provider signature origin",
            admissibility["reasons"],
        )

    def test_tee_hsm_no_export_capture_is_strictly_admissible(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            report = module.build_report(
                root,
                request_path=request_path,
                backend_command=["/opt/threshold-backend", "emit-tee-hsm-capture"],
                command_runner=tee_hsm_no_export_capture_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-07-01T00:00:00Z",
            )

        admissibility = report["manifest"]["backend_core_admissibility"]
        self.assertTrue(admissibility["strict_threshold_core_admissible"])
        self.assertFalse(admissibility["quarantined"])
        self.assertEqual(
            admissibility["core_mode"],
            "tee_hsm_no_export_threshold_mldsa65_provider",
        )
        self.assertEqual(
            admissibility["signature_origin"],
            "tee_hsm_no_export_standard_mldsa65_provider",
        )
        self.assertEqual(admissibility["reasons"], [])

    def test_build_report_rejects_capture_that_omits_or_stales_request_binding(self):
        module = load_module()

        def missing_request_runner(command, root, env):
            capture = external_capture()
            del capture["request"]
            return {
                "command": command,
                "exit_code": 0,
                "duration_seconds": 0.2,
                "stdout": json.dumps(capture),
                "stderr": "",
            }

        def stale_request_runner(command, root, env):
            capture = external_capture()
            capture["request"]["request_sha256"] = "99" * 32
            return {
                "command": command,
                "exit_code": 0,
                "duration_seconds": 0.2,
                "stdout": json.dumps(capture),
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(external_request()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "request binding"):
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=missing_request_runner,
                    metadata_provider=fake_metadata,
                )
            with self.assertRaisesRegex(ValueError, "request digest mismatch"):
                module.build_report(
                    root,
                    request_path=request_path,
                    backend_command=["/opt/threshold-backend", "emit-capture"],
                    command_runner=stale_request_runner,
                    metadata_provider=fake_metadata,
                )

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

    def test_build_report_rejects_repo_local_backend_command_before_execution(self):
        module = load_module()

        def unexpected_runner(command, root, env):
            raise AssertionError("repo-local backend command should not execute")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            repo_command = root / "scripts" / "emit_backend_capture.py"
            repo_command.parent.mkdir(parents=True)
            repo_command.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "repo-local backend command"):
                module.build_report(
                    root,
                    backend_command=[str(repo_command), "emit-capture-json"],
                    command_runner=unexpected_runner,
                    metadata_provider=fake_metadata,
                )

            with self.assertRaisesRegex(ValueError, "repo-local backend command"):
                module.build_report(
                    root,
                    backend_command=["python3", str(repo_command), "emit-capture-json"],
                    command_runner=unexpected_runner,
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
