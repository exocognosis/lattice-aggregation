import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_production_dkg_custody_capture_attempt.py"
BUILD_REQUEST = ROOT / "scripts" / "build_internal_aggregation_campaign_request.py"
BOUNDED_CAPTURE = ROOT / "artifacts" / "p1-dkg-custody-capture" / "latest" / "capture.json"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fake_metadata(_root=None):
    return {
        "commit": "ab" * 20,
        "branch": "test",
        "dirty": False,
        "dirty_status_unavailable": False,
        "cargo_version": "cargo 1.test",
        "rustc_version": "rustc 1.test",
        "os": "test-os",
        "python_version": "3.test",
        "cargo_lock_sha256": "cd" * 32,
    }


def command_result(stdout="", stderr="", exit_code=0):
    return {
        "command": ["/opt/threshold-backend-p1", "emit-production-dkg-custody-capture"],
        "exit_code": exit_code,
        "duration_seconds": 0.01,
        "stdout": stdout,
        "stderr": stderr,
    }


def internal_request_file(root):
    builder = load_module(BUILD_REQUEST, "production_dkg_internal_request_builder")
    request = builder.build_request("theorem-closure-internal-001")["request_json"]
    request_path = root / "internal-request.json"
    request_path.write_text(request, encoding="utf-8")
    return request_path


def production_capture(runner, request):
    request_sha256 = runner.sha256_text(runner.canonical_json(request))
    return {
        "schema": runner.CAPTURE_SCHEMA,
        "name": "production-dkg-custody-capture-test",
        "capture_status": runner.READY_STATUS,
        "selected_profile": runner.SELECTED_PROFILE,
        "claim_boundary": "conformance/proof-review evidence",
        "request_binding": {
            "schema": runner.REQUEST_SCHEMA,
            "request_sha256": request_sha256,
        },
        "claim_flags": runner.false_claim_flags(),
        "target_profile": {
            "validator_count": 10_000,
            "threshold": 6_667,
        },
        "execution_profile": {
            "validator_count": 10_000,
            "threshold": 6_667,
            "dealer_count": 7,
        },
        "dkg_custody_evidence": {
            "commit_before_reveal": True,
            "no_seed_dealer_dkg": True,
            "multiple_independent_dealers": True,
            "distributed_dkg_vss_transcript_present": True,
            "encrypted_receiver_custody_seam_executed": True,
            "process_isolated_receiver_custody": True,
            "per_receiver_private_share_custody": True,
            "receiver_vault_imports_verified": True,
            "signer_consumes_custody_output": True,
            "production_profile_executed": True,
            "production_dkg_no_single_secret_ready": True,
            "coordinator_observed_clear_dkg_shares_before_custody": False,
            "secret_material_exported_to_json": False,
            "raw_seed_exported_to_json": False,
            "expanded_key_exported_to_json": False,
        },
        "transcript": {
            "session_id_hex": digest(b"session"),
            "rho_digest_hex": digest(b"rho"),
            "public_key_digest_hex": digest(b"public key"),
            "dkg_transcript_digest_hex": digest(b"dkg transcript"),
            "custody_bundle_digest_hex": digest(b"custody bundle"),
            "custody_commitments_digest_hex": digest(b"custody commitments"),
            "receiver_vault_root_hex": digest(b"receiver vault"),
            "commitment_key_digest_hex": digest(b"commitment key"),
            "accepted_dealers": [1, 2, 3, 4, 5, 6, 7],
            "dealer_commitments": [
                {
                    "dealer_id": dealer_id,
                    "commitment_digest_hex": digest(f"dealer:{dealer_id}".encode()),
                }
                for dealer_id in range(1, 8)
            ],
        },
        "blockers": [],
    }


class ProductionDkgCustodyCaptureAttemptTests(unittest.TestCase):
    def test_missing_backend_command_writes_blocked_request_artifact(self):
        runner = load_module(SCRIPT, "production_dkg_runner_missing")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = internal_request_file(root)
            out = root / "attempt"
            report = runner.build_report(
                root,
                internal_request_path=request_path,
                out=out,
                backend_command=None,
                metadata_provider=fake_metadata,
                generated_at="2026-08-19T00:00:00Z",
            )
            runner.write_attempt_artifacts(report, out)
            manifest = json.loads((out / "manifest.json").read_text())

        self.assertEqual(
            manifest["runner_status"],
            "blocked_production_dkg_custody_backend_unavailable",
        )
        self.assertFalse(manifest["production_dkg_custody_capture_ready"])
        self.assertIn(
            "production DKG/custody backend command not supplied",
            manifest["blockers"],
        )

    def test_bounded_capture_is_rejected_as_nonproduction(self):
        runner = load_module(SCRIPT, "production_dkg_runner_bounded")
        bounded_capture = BOUNDED_CAPTURE.read_text(encoding="utf-8")

        def fake_command(command, _root, _env):
            out_path = pathlib.Path(command[command.index("--out") + 1])
            out_path.write_text(bounded_capture, encoding="utf-8")
            return command_result(stdout="wrote bounded capture\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = internal_request_file(root)
            out = root / "attempt"
            report = runner.build_report(
                root,
                internal_request_path=request_path,
                out=out,
                backend_command=["/opt/threshold-backend-p1", "emit-production-dkg-custody-capture"],
                command_runner=fake_command,
                metadata_provider=fake_metadata,
                generated_at="2026-08-19T00:00:00Z",
            )
            runner.write_attempt_artifacts(report, out)
            manifest = json.loads((out / "manifest.json").read_text())

        self.assertEqual(
            manifest["runner_status"],
            "blocked_production_dkg_custody_capture_invalid",
        )
        self.assertFalse(manifest["production_dkg_custody_capture_ready"])
        self.assertIn(
            "execution validator_count mismatch: expected 10000, observed 8",
            manifest["blockers"],
        )
        self.assertIn(
            "DKG/custody evidence must be true: process_isolated_receiver_custody",
            manifest["blockers"],
        )

    def test_exact_production_capture_is_ready(self):
        runner = load_module(SCRIPT, "production_dkg_runner_ready")

        def fake_command(command, _root, _env):
            request_path = pathlib.Path(command[command.index("--request") + 1])
            out_path = pathlib.Path(command[command.index("--out") + 1])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            out_path.write_text(
                runner.canonical_json(production_capture(runner, request)),
                encoding="utf-8",
            )
            return command_result(stdout="wrote production capture\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = internal_request_file(root)
            out = root / "attempt"
            report = runner.build_report(
                root,
                internal_request_path=request_path,
                out=out,
                backend_command=["/opt/threshold-backend-p1", "emit-production-dkg-custody-capture"],
                command_runner=fake_command,
                metadata_provider=fake_metadata,
                generated_at="2026-08-19T00:00:00Z",
            )
            runner.write_attempt_artifacts(report, out)
            manifest = json.loads((out / "manifest.json").read_text())
            capture_written = (out / "capture.json").is_file()

        self.assertEqual(manifest["runner_status"], "production_dkg_custody_capture_ready")
        self.assertTrue(manifest["production_dkg_custody_capture_ready"])
        self.assertEqual(manifest["blockers"], [])
        self.assertTrue(capture_written)

    def test_production_claim_with_missing_process_isolation_fails_closed(self):
        runner = load_module(SCRIPT, "production_dkg_runner_missing_process")

        def fake_command(command, _root, _env):
            request_path = pathlib.Path(command[command.index("--request") + 1])
            out_path = pathlib.Path(command[command.index("--out") + 1])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            capture = production_capture(runner, request)
            capture["dkg_custody_evidence"]["process_isolated_receiver_custody"] = False
            out_path.write_text(runner.canonical_json(capture), encoding="utf-8")
            return command_result(stdout="wrote invalid production capture\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = internal_request_file(root)
            out = root / "attempt"
            report = runner.build_report(
                root,
                internal_request_path=request_path,
                out=out,
                backend_command=["/opt/threshold-backend-p1", "emit-production-dkg-custody-capture"],
                command_runner=fake_command,
                metadata_provider=fake_metadata,
                generated_at="2026-08-19T00:00:00Z",
            )

        self.assertEqual(
            report["manifest"]["runner_status"],
            "blocked_production_dkg_custody_capture_invalid",
        )
        self.assertIn(
            "DKG/custody evidence must be true: process_isolated_receiver_custody",
            report["manifest"]["blockers"],
        )

    def test_forbidden_and_repo_local_commands_fail_before_execution(self):
        runner = load_module(SCRIPT, "production_dkg_runner_command_checks")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "forbidden"):
                runner.validate_backend_command(root, ["/opt/smoke-dkg", "run"])
            local_command = root / "bin" / "backend"
            with self.assertRaisesRegex(ValueError, "repo-local command"):
                runner.validate_backend_command(root, [str(local_command), "run"])


if __name__ == "__main__":
    unittest.main()
