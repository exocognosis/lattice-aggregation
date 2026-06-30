import csv
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_localnet_runner.py"

SAMPLE_STDOUT = """claim_boundary=local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security
fault_profile=honest
validators=4
triggered_validator_count=4
threshold=3
finalized=4
all_validators_finalized=true
evidence_count=0
broadcast_count=8
direct_send_count=0
dropped_message_count=0
network_bytes=2160
"""

FAULT_STDOUT = """claim_boundary=local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security
fault_profile=withheld-partial
validators=4
triggered_validator_count=4
threshold=4
finalized=1
all_validators_finalized=false
evidence_count=3
broadcast_count=8
direct_send_count=0
dropped_message_count=3
network_bytes=1920
"""

QUORUM_STDOUT = """claim_boundary=local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security
fault_profile=honest
validators=4
triggered_validator_count=3
threshold=3
finalized=3
all_validators_finalized=false
evidence_count=0
broadcast_count=6
direct_send_count=0
dropped_message_count=0
network_bytes=1512
"""


def load_module():
    spec = importlib.util.spec_from_file_location("run_localnet_runner", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_metadata(root):
    return {
        "commit": "abc123",
        "branch": "codex/localnet",
        "dirty": False,
        "cargo_version": "cargo 1.96.0",
        "rustc_version": "rustc 1.96.0",
        "os": "TestOS",
        "python_version": "3.x",
        "cargo_lock_sha256": "lock-digest",
    }


def fake_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.5,
        "stdout": SAMPLE_STDOUT,
        "stderr": "",
    }


def failing_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 101,
        "duration_seconds": 0.25,
        "stdout": "",
        "stderr": "localnet failed",
    }


def fault_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.5,
        "stdout": FAULT_STDOUT,
        "stderr": "",
    }


def quorum_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.5,
        "stdout": QUORUM_STDOUT,
        "stderr": "",
    }


class LocalnetRunnerTests(unittest.TestCase):
    def test_build_report_parses_runner_output_and_preserves_boundary(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = module.build_report(
                pathlib.Path(temp_dir),
                command_runner=fake_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-30T00:00:00Z",
            )

        self.assertEqual(report["manifest"]["schema_version"], 1)
        self.assertEqual(report["manifest"]["claim_boundary"], module.CLAIM_BOUNDARY)
        self.assertEqual(report["metrics"]["validators"], 4)
        self.assertEqual(report["metrics"]["triggered_validator_count"], 4)
        self.assertEqual(report["metrics"]["threshold"], 3)
        self.assertEqual(report["metrics"]["finalized"], 4)
        self.assertTrue(report["metrics"]["all_validators_finalized"])
        self.assertEqual(report["metrics"]["fault_profile"], "honest")
        self.assertEqual(report["metrics"]["dropped_message_count"], 0)
        self.assertEqual(report["metrics"]["network_bytes"], 2160)
        self.assertIn("not production threshold ML-DSA security", report["summary_md"])

    def test_write_artifacts_emits_packet_files_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "artifacts" / "localnet" / "sample"
            report = module.build_report(
                root,
                command_runner=fake_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-30T00:00:00Z",
            )
            module.write_artifacts(report, out_dir)

            manifest = json.loads((out_dir / "manifest.json").read_text())
            topology = json.loads((out_dir / "topology.json").read_text())
            metrics = list(csv.DictReader((out_dir / "metrics.csv").read_text().splitlines()))
            events = (out_dir / "events.jsonl").read_text().splitlines()
            node_logs_readme = (out_dir / "node-logs" / "README.md").read_text()
            node_log_exists = (out_dir / "node-logs" / "validator-1.log").exists()
            checksums = (out_dir / "SHA256SUMS").read_text()

        self.assertEqual(manifest["metadata"]["commit"], "abc123")
        self.assertEqual(manifest["claim_boundary"], module.CLAIM_BOUNDARY)
        self.assertEqual(manifest["dropped_message_count"], 0)
        self.assertEqual(topology["transport_mode"], "in-memory tokio mpsc")
        self.assertEqual(topology["fault_profile"], "honest")
        self.assertEqual(metrics[0]["validators"], "4")
        self.assertEqual(metrics[0]["triggered_validator_count"], "4")
        self.assertEqual(metrics[0]["threshold"], "3")
        self.assertEqual(metrics[0]["fault_profile"], "honest")
        self.assertEqual(metrics[0]["all_validators_finalized"], "True")
        self.assertEqual(len(events), 2)
        self.assertIn("per-validator local telemetry summaries only", node_logs_readme)
        self.assertTrue(node_log_exists)
        self.assertIn("manifest.json", checksums)
        self.assertIn("events.jsonl", checksums)
        self.assertIn("node-logs/validator-1.log", checksums)
        self.assertIn("node-logs/README.md", checksums)

    def test_fault_profile_packet_preserves_partial_success_boundary(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = module.build_report(
                pathlib.Path(temp_dir),
                profile="withheld-partial",
                command_runner=fault_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-30T00:00:00Z",
            )

        self.assertEqual(report["manifest"]["fault_profile"], "withheld-partial")
        self.assertEqual(report["manifest"]["dropped_message_count"], 3)
        self.assertFalse(report["metrics"]["all_validators_finalized"])
        self.assertEqual(report["metrics"]["dropped_message_count"], 3)
        self.assertEqual(report["metrics"]["evidence_count"], 3)
        self.assertIn("fault-injection telemetry", report["summary_md"])
        self.assertIn("not production network liveness", report["summary_md"])
        self.assertIn("--profile withheld-partial", report["summary_md"])

    def test_quorum_participation_packet_preserves_passive_validator_boundary(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = module.build_report(
                pathlib.Path(temp_dir),
                profile="quorum-participation",
                command_runner=quorum_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-30T00:00:00Z",
            )

        self.assertEqual(report["manifest"]["triggered_validator_count"], 3)
        self.assertEqual(report["metrics"]["validators"], 4)
        self.assertEqual(report["metrics"]["triggered_validator_count"], 3)
        self.assertFalse(report["metrics"]["all_validators_finalized"])
        self.assertEqual(report["metrics"]["evidence_count"], 0)
        self.assertIn("passive validator", report["summary_md"])
        self.assertIn("not slashing evidence", report["summary_md"])
        self.assertIn("--profile quorum-participation", report["summary_md"])

    def test_failed_runner_status_raises(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError) as error:
                module.build_report(
                    pathlib.Path(temp_dir),
                    command_runner=failing_runner,
                    metadata_provider=fake_metadata,
                    generated_at="2026-06-30T00:00:00Z",
                )

        self.assertIn("localnet command failed", str(error.exception))


if __name__ == "__main__":
    unittest.main()
