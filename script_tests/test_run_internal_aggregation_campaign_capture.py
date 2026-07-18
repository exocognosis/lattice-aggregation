import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER_SCRIPT = ROOT / "scripts" / "run_internal_aggregation_campaign_capture.py"
FIXTURE_SCRIPT = ROOT / "script_tests" / "test_validate_internal_aggregation_campaign_capture.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_metadata(_root=None):
    return {
        "commit": "ab" * 20,
        "branch": "test",
        "dirty": False,
        "cargo_version": "cargo 1.test",
        "rustc_version": "rustc 1.test",
        "os": "test-os",
        "python_version": "3.test",
        "cargo_lock_sha256": "cd" * 32,
    }


def command_result(stdout="", stderr="", exit_code=0):
    return {
        "command": ["/opt/exact-campaign", "run"],
        "exit_code": exit_code,
        "duration_seconds": 0.01,
        "stdout": stdout,
        "stderr": stderr,
    }


class InternalAggregationCampaignRunnerTests(unittest.TestCase):
    def test_command_failure_records_blocked_run_without_official_capture(self):
        runner = load_module(RUNNER_SCRIPT, "internal_campaign_runner_fail")
        fixtures = load_module(FIXTURE_SCRIPT, "internal_campaign_runner_fixtures_fail")
        builder = fixtures.build_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            campaign_out = root / "campaign"
            run_out = root / "run"
            request_path.write_text(
                builder.build_request("theorem-closure-internal-001")[
                    "request_json"
                ],
                encoding="utf-8",
            )

            report = runner.build_report(
                root,
                request_path=request_path,
                campaign_out=campaign_out,
                run_out=run_out,
                backend_command=["/opt/exact-campaign", "run"],
                command_runner=lambda _command, _root, _env: command_result(
                    stderr="exact distributed campaign backend unavailable\n",
                    exit_code=2,
                ),
                metadata_provider=fake_metadata,
                generated_at="2026-07-18T00:00:00Z",
            )
            runner.write_run_artifacts(report, run_out)

            manifest = json.loads((run_out / "run-manifest.json").read_text())
            official_capture_exists = (campaign_out / "capture.json").exists()

        self.assertEqual(
            manifest["runner_status"], "blocked_backend_command_failed"
        )
        self.assertFalse(manifest["official_capture_written"])
        self.assertIn(
            "exact distributed campaign backend command failed",
            manifest["blockers"],
        )
        self.assertFalse(official_capture_exists)

    def test_reviewed_exact_capture_promotes_to_official_campaign_artifact(self):
        runner = load_module(RUNNER_SCRIPT, "internal_campaign_runner_ready")
        fixtures = load_module(FIXTURE_SCRIPT, "internal_campaign_runner_fixtures_ready")
        builder = fixtures.build_module()
        validator = runner.load_campaign_validator()
        verifier = fixtures.ReviewedAuthorizationVerifier()
        request_report = builder.build_request(
            "theorem-closure-internal-001",
            authorization_verifier_profile=fixtures.verifier_profile(verifier),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            evidence_base = root / "evidence-base"
            request_path = root / "request.json"
            campaign_out = root / "campaign"
            run_out = root / "run"
            request = request_report["request"]
            request_path.write_text(request_report["request_json"], encoding="utf-8")
            records = fixtures.evidence_bundle(
                evidence_base, validator.REQUIRED_EVIDENCE_ROLES
            )
            capture = fixtures.capture_for(request, records)
            fixtures.install_valid_authorization(
                evidence_base, request, records, capture, validator
            )
            capture_json = validator.canonical_json(capture)

            report = runner.build_report(
                root,
                request_path=request_path,
                campaign_out=campaign_out,
                run_out=run_out,
                evidence_base=evidence_base,
                backend_command=["/opt/exact-campaign", "run"],
                authorization_verifier=verifier,
                command_runner=lambda _command, _root, _env: command_result(
                    stdout=capture_json
                ),
                metadata_provider=fake_metadata,
                generated_at="2026-07-18T00:00:00Z",
            )
            runner.write_official_campaign(
                json.loads(report["capture_json"]),
                json.loads(report["validation_json"]),
                campaign_out,
                validator,
            )
            runner.write_run_artifacts(report, run_out)
            run_manifest = json.loads((run_out / "run-manifest.json").read_text())
            validation_manifest = json.loads((campaign_out / "manifest.json").read_text())
            official_capture_exists = (campaign_out / "capture.json").is_file()
            run_capture_exists = (run_out / "capture.json").is_file()

        self.assertEqual(
            run_manifest["runner_status"], "internal_campaign_capture_ready"
        )
        self.assertTrue(run_manifest["official_capture_written"])
        self.assertTrue(run_manifest["official_validation_written"])
        self.assertEqual(
            run_manifest["validation_status"], "internal_campaign_evidence_ready"
        )
        self.assertEqual(run_manifest["validated_execution_count"], 24)
        self.assertEqual(run_manifest["blockers"], [])
        self.assertTrue(official_capture_exists)
        self.assertEqual(
            validation_manifest["campaign_status"], "internal_campaign_evidence_ready"
        )
        self.assertTrue(run_capture_exists)

    def test_non_ready_capture_is_stored_only_as_rejected_attempt(self):
        runner = load_module(RUNNER_SCRIPT, "internal_campaign_runner_rejected")
        fixtures = load_module(FIXTURE_SCRIPT, "internal_campaign_runner_fixtures_rejected")
        builder = fixtures.build_module()
        validator = runner.load_campaign_validator()
        request_report = builder.build_request("theorem-closure-internal-001")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            evidence_base = root / "evidence-base"
            request_path = root / "request.json"
            campaign_out = root / "campaign"
            run_out = root / "run"
            request = request_report["request"]
            request_path.write_text(request_report["request_json"], encoding="utf-8")
            capture = fixtures.capture_for(
                request,
                fixtures.evidence_bundle(
                    evidence_base, validator.REQUIRED_EVIDENCE_ROLES
                ),
            )

            report = runner.build_report(
                root,
                request_path=request_path,
                campaign_out=campaign_out,
                run_out=run_out,
                evidence_base=evidence_base,
                backend_command=["/opt/exact-campaign", "run"],
                command_runner=lambda _command, _root, _env: command_result(
                    stdout=validator.canonical_json(capture)
                ),
                metadata_provider=fake_metadata,
                generated_at="2026-07-18T00:00:00Z",
            )
            runner.write_run_artifacts(report, run_out)
            manifest = json.loads((run_out / "run-manifest.json").read_text())
            rejected_capture_exists = (run_out / "rejected-capture.json").is_file()
            rejected_validation_exists = (
                run_out / "rejected-validation.json"
            ).is_file()
            official_capture_exists = (campaign_out / "capture.json").exists()

        self.assertEqual(
            manifest["runner_status"], "blocked_capture_validation_failed"
        )
        self.assertFalse(manifest["official_capture_written"])
        self.assertIn(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed",
            manifest["blockers"],
        )
        self.assertTrue(rejected_capture_exists)
        self.assertTrue(rejected_validation_exists)
        self.assertFalse(official_capture_exists)

    def test_forbidden_backend_command_tokens_fail_before_execution(self):
        runner = load_module(RUNNER_SCRIPT, "internal_campaign_runner_forbidden")
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "forbidden"):
                runner.validate_backend_command(
                    pathlib.Path(temp_dir), ["/opt/smoke-campaign", "run"]
                )

    def test_repo_local_backend_command_is_rejected(self):
        runner = load_module(RUNNER_SCRIPT, "internal_campaign_runner_local")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            command = root / "bin" / "exact-campaign"
            with self.assertRaisesRegex(ValueError, "repo-local command"):
                runner.validate_backend_command(root, [str(command), "run"])


if __name__ == "__main__":
    unittest.main()
