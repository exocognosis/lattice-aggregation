import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_actual_nonce_producer_capture.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_actual_nonce_producer_capture",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def promoted_attempt(source_profile, quarantined):
    return {
        "schema": "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1",
        "attempt_status": "capture_promoted",
        "backend_command_executed": True,
        "handoff_manifest_path": "handoff/manifest.json",
        "handoff_source_profile": source_profile,
        "handoff_quarantine": {
            "quarantined": quarantined,
            "allowed_use": (
                "reference CLI handoff replay only; not actual backend evidence"
                if quarantined
                else "explicit external backend capture gated by admissible readiness"
            ),
        },
        "request_sha256": "11" * 32,
        "readiness_status": "backend_candidate_admissible_pending_capture",
        "claim_boundary": "conformance/proof-review evidence only",
    }


def handoff_manifest(source_profile, quarantined):
    return {
        "schema": "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1",
        "handoff_status": "evidence_present_unclosed",
        "handoff_source_profile": source_profile,
        "quarantine": {
            "quarantined": quarantined,
            "allowed_use": (
                "reference CLI handoff replay only; not actual backend evidence"
                if quarantined
                else "explicit external backend capture gated by admissible readiness"
            ),
        },
        "request_sha256": "11" * 32,
        "capture_sha256": "22" * 32,
        "claim_boundary": "conformance/proof-review evidence only",
    }


class ActualNonceProducerCaptureGateTests(unittest.TestCase):
    def test_reference_cli_promoted_capture_is_blocked_from_actual_external_slot(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = root / "attempt" / "manifest.json"
            write_json(
                attempt_path,
                promoted_attempt("repo_reference_cli_capture", quarantined=True),
            )
            write_json(
                root / "attempt" / "handoff" / "manifest.json",
                handoff_manifest("repo_reference_cli_capture", quarantined=True),
            )
            report = module.build_report(root, attempt_path)

        manifest = report["manifest"]
        blockers = " ".join(manifest["blockers"])
        self.assertEqual(manifest["gate_status"], "actual_external_capture_missing")
        self.assertFalse(manifest["actual_external_capture_ready"])
        self.assertEqual(manifest["attempt_source_profile"], "repo_reference_cli_capture")
        self.assertIn("repo_reference_cli_capture", blockers)
        self.assertIn("not admissible_external_backend_capture", blockers)
        self.assertIn("reference CLI", blockers)
        self.assertIn("does not prove Criterion 2", report["summary_md"])

    def test_non_quarantined_external_capture_satisfies_actual_external_slot(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = root / "attempt" / "manifest.json"
            write_json(
                attempt_path,
                promoted_attempt("admissible_external_backend_capture", quarantined=False),
            )
            write_json(
                root / "attempt" / "handoff" / "manifest.json",
                handoff_manifest("admissible_external_backend_capture", quarantined=False),
            )
            out_dir = root / "actual-gate"
            report = module.build_report(root, attempt_path)
            module.write_artifacts(report, out_dir)

            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary = (out_dir / "summary.md").read_text()

        self.assertEqual(manifest["gate_status"], "actual_external_capture_ready")
        self.assertTrue(manifest["actual_external_capture_ready"])
        self.assertEqual(manifest["blockers"], [])
        self.assertIn("admissible_external_backend_capture", summary)

    def test_strict_mode_exits_nonzero_when_actual_external_capture_is_missing(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = root / "attempt" / "manifest.json"
            out_dir = root / "actual-gate"
            write_json(
                attempt_path,
                promoted_attempt("repo_reference_cli_capture", quarantined=True),
            )
            write_json(
                root / "attempt" / "handoff" / "manifest.json",
                handoff_manifest("repo_reference_cli_capture", quarantined=True),
            )
            exit_code = module.main(
                [
                    "--root",
                    str(root),
                    "--attempt",
                    str(attempt_path),
                    "--out",
                    str(out_dir),
                    "--strict",
                ]
            )
            manifest_written = (out_dir / "manifest.json").is_file()

        self.assertEqual(exit_code, 2)
        self.assertTrue(manifest_written)


if __name__ == "__main__":
    unittest.main()
