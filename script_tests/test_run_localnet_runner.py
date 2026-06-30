import csv
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_localnet_runner.py"

SAMPLE_STDOUT = """claim_boundary=local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security
validators=4
threshold=3
finalized=4
evidence_count=0
broadcast_count=8
direct_send_count=0
network_bytes=2160
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
        self.assertEqual(report["metrics"]["threshold"], 3)
        self.assertEqual(report["metrics"]["finalized"], 4)
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
            checksums = (out_dir / "SHA256SUMS").read_text()

        self.assertEqual(manifest["metadata"]["commit"], "abc123")
        self.assertEqual(manifest["claim_boundary"], module.CLAIM_BOUNDARY)
        self.assertEqual(topology["transport_mode"], "in-memory tokio mpsc")
        self.assertEqual(metrics[0]["validators"], "4")
        self.assertEqual(metrics[0]["threshold"], "3")
        self.assertEqual(len(events), 2)
        self.assertIn("does not yet emit per-validator log streams", node_logs_readme)
        self.assertIn("manifest.json", checksums)
        self.assertIn("events.jsonl", checksums)
        self.assertIn("node-logs/README.md", checksums)

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
