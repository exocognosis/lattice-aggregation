import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_simulation_benchmarks.py"

SAMPLE_CSV = """profile,experiment,trial,validators,threshold,malicious_validator,wall_duration_ms,logical_latency_ms,aborts,bandwidth_bytes,mldsa65_public_key_bytes,mldsa65_signature_bytes,commitment_bytes,no_wall_sleep
large,Large Baseline 3,0,3,2,none,1.0000,0,0,332,1952,3309,32,true
large,Large Regional 64,0,64,43,44,2.5000,190,3,9000,1952,3309,32,true
large,Large Regional 64,1,64,43,44,3.5000,191,4,9000,1952,3309,32,true
"""


def load_module():
    spec = importlib.util.spec_from_file_location("run_simulation_benchmarks", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_metadata():
    return {
        "commit": "abc123",
        "branch": "codex/benchmarks",
        "cargo_version": "cargo 1.90.0",
        "rustc_version": "rustc 1.90.0",
        "os": "TestOS",
        "python_version": "3.x",
    }


def fake_runner(command, root, env):
    return {
        "command": command,
        "exit_code": 0,
        "duration_seconds": 1.25,
        "stdout": SAMPLE_CSV,
        "stderr": "",
    }


class SimulationBenchmarkRunnerTests(unittest.TestCase):
    def test_build_report_summarizes_trials_and_checksums(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = module.build_report(
                pathlib.Path(temp_dir),
                profile="large",
                command_runner=fake_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-21T00:00:00Z",
            )

        self.assertEqual(report["manifest"]["profile"], "large")
        self.assertEqual(report["manifest"]["trial_count"], 3)
        self.assertEqual(
            report["manifest"]["claim_boundary"],
            "deterministic research telemetry; requires security evidence review",
        )
        self.assertEqual(
            report["manifest"]["artifacts"]["trials_csv_sha256"],
            module.sha256_text(SAMPLE_CSV),
        )
        self.assertEqual(len(report["summary_rows"]), 2)
        self.assertEqual(report["summary_rows"][1]["experiment"], "Large Regional 64")
        self.assertEqual(report["summary_rows"][1]["trials"], 2)
        self.assertEqual(report["summary_rows"][1]["mean_aborts"], 3.5)

    def test_write_artifacts_emits_manifest_csv_and_summary(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "docs" / "benchmarks" / "generated" / "latest-simulation"
            report = module.build_report(
                root,
                profile="large",
                command_runner=fake_runner,
                metadata_provider=fake_metadata,
                generated_at="2026-06-21T00:00:00Z",
            )

            module.write_artifacts(report, out_dir)

            manifest = json.loads((out_dir / "manifest.json").read_text())
            trials = (out_dir / "trials.csv").read_text()
            summary = (out_dir / "summary.md").read_text()

        self.assertEqual(manifest["metadata"]["commit"], "abc123")
        self.assertEqual(trials, SAMPLE_CSV)
        self.assertIn("# Large-Scale Simulation Benchmark Summary", summary)
        self.assertIn("deterministic research telemetry", summary)
        self.assertIn("requires security evidence review", summary)
        self.assertIn("| Large Regional 64 | 64 | 43 | 2 |", summary)


if __name__ == "__main__":
    unittest.main()
