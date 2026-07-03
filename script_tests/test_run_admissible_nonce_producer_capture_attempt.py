import importlib.util
import json
import pathlib
import stat
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_admissible_nonce_producer_capture_attempt.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
ATTEMPT_SCHEMA = "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "run_admissible_nonce_producer_capture_attempt",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_backend_crate(root, *, hazmat):
    crate = root / "backend"
    (crate / "src" / "low_level").mkdir(parents=True)
    if hazmat:
        cargo_toml = """
[package]
name = "dytallix-pq-threshold"
version = "0.1.0"
description = "Research-grade threshold ML-DSA-65 API boundary and simulation backend"
categories = ["cryptography", "simulation"]

[features]
default = ["simulated"]
simulated = []
hazmat = []
raw-real-mldsa = ["hazmat"]
"""
        source = """
pub struct Mldsa65DistributedNoncePrfOutputShare;
pub fn split_mldsa65_distributed_nonce_prf_output() {}
pub fn derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share() {}
pub fn derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key() {}
// deterministic test-vector plumbing for a hazmat PRF-output oracle
"""
    else:
        cargo_toml = """
[package]
name = "reviewed-p1-nonce-producer"
version = "1.2.3"
description = "Reviewed external Shamir nonce DKG TEE nonce producer"

[features]
default = []
tee-attested = []
"""
        source = """
pub struct Mldsa65DistributedNoncePrfOutputShare;
pub fn split_mldsa65_distributed_nonce_prf_output() {}
pub fn derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share() {}
pub const REVIEWED_EXTERNAL_SHAMIR_NONCE_DKG_CAPTURE_CONTRACT: &str =
    "p1_shamir_nonce_dkg_tee_external_capture";
pub const ABORT_ACCOUNTABILITY_TRANSCRIPT: &str = "abort_accountability";
"""
    (crate / "Cargo.toml").write_text(cargo_toml.lstrip(), encoding="utf-8")
    (crate / "src" / "low_level" / "mldsa65.rs").write_text(
        source.lstrip(),
        encoding="utf-8",
    )
    return crate


def write_backend_emitter(root, marker=None):
    emitter = root / "reviewed_backend_emitter.py"
    marker_line = (
        f"pathlib.Path({str(marker)!r}).write_text('executed\\n', encoding='utf-8')"
        if marker
        else "pass"
    )
    emitter.write_text(
        f"""#!/usr/bin/env python3
import pathlib
import subprocess
import sys

{marker_line}
request = sys.argv[sys.argv.index("--request") + 1]
subprocess.run(
    [
        sys.executable,
        {str(ROOT / "scripts" / "emit_reviewed_nonce_producer_capture.py")!r},
        "--request",
        request,
    ],
    check=True,
)
""",
        encoding="utf-8",
    )
    emitter.chmod(emitter.stat().st_mode | stat.S_IXUSR)
    return emitter


def write_failing_backend_emitter(root, *, stdout="", stderr="backend failed", code=7):
    emitter = root / "failing_backend_emitter.py"
    emitter.write_text(
        f"""#!/usr/bin/env python3
import sys

sys.stdout.write({stdout!r})
sys.stderr.write({stderr!r})
raise SystemExit({code})
""",
        encoding="utf-8",
    )
    emitter.chmod(emitter.stat().st_mode | stat.S_IXUSR)
    return emitter


def write_invalid_capture_emitter(root):
    emitter = root / "invalid_capture_emitter.py"
    emitter.write_text(
        """#!/usr/bin/env python3
print("not canonical capture json")
""",
        encoding="utf-8",
    )
    emitter.chmod(emitter.stat().st_mode | stat.S_IXUSR)
    return emitter


class AdmissibleNonceProducerCaptureAttemptTests(unittest.TestCase):
    def test_attempt_blocks_hazmat_style_backend_before_capture_command_runs(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            backend_crate = write_backend_crate(temp_root, hazmat=True)
            marker = temp_root / "backend-command-executed.txt"
            emitter = write_backend_emitter(temp_root, marker=marker)
            out_dir = temp_root / "attempt"

            report = module.build_attempt(
                ROOT,
                out_dir,
                backend_crate=backend_crate,
                backend_command=[sys.executable, str(emitter), "--request", "{request}"],
                backend_label="hazmat-style-candidate",
                generated_at="2026-07-03T00:00:00Z",
            )

            manifest = json.loads((out_dir / "manifest.json").read_text())
            readiness = json.loads((out_dir / "readiness" / "manifest.json").read_text())
            summary = (out_dir / "summary.md").read_text()

        self.assertEqual(manifest["schema"], ATTEMPT_SCHEMA)
        self.assertEqual(manifest["attempt_status"], "backend_readiness_blocked")
        self.assertFalse(manifest["backend_command_executed"])
        self.assertFalse(marker.exists())
        self.assertIsNone(manifest["handoff_manifest_path"])
        self.assertFalse((out_dir / "handoff" / "manifest.json").exists())
        self.assertEqual(readiness["schema"], READINESS_SCHEMA)
        self.assertEqual(
            manifest["request_sha256"],
            readiness["request"]["request_sha256"],
        )
        blockers = " ".join(manifest["detected_blockers"])
        self.assertIn("hazmat feature", blockers)
        self.assertIn("centralized nonce PRF oracle", blockers)
        self.assertIn("backend_readiness_blocked", summary)
        self.assertIn("does not prove Criterion 2", summary)
        self.assertEqual(report["manifest"], manifest)

    def test_attempt_promotes_capture_only_after_admissible_readiness(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            backend_crate = write_backend_crate(temp_root, hazmat=False)
            marker = temp_root / "backend-command-executed.txt"
            emitter = write_backend_emitter(temp_root, marker=marker)
            out_dir = temp_root / "attempt"

            report = module.build_attempt(
                ROOT,
                out_dir,
                backend_crate=backend_crate,
                backend_command=[sys.executable, str(emitter), "--request", "{request}"],
                backend_label="reviewed-backend-candidate",
                generated_at="2026-07-03T00:00:00Z",
            )

            manifest = json.loads((out_dir / "manifest.json").read_text())
            handoff = json.loads((out_dir / "handoff" / "manifest.json").read_text())
            request = json.loads((out_dir / "handoff" / "request" / "request.json").read_text())
            checksums = (out_dir / "SHA256SUMS").read_text()
            marker_existed = marker.exists()

        self.assertEqual(request["schema"], REQUEST_SCHEMA)
        self.assertEqual(manifest["attempt_status"], "capture_promoted")
        self.assertTrue(manifest["backend_command_executed"])
        self.assertTrue(marker_existed)
        self.assertEqual(manifest["request_sha256"], handoff["request_sha256"])
        self.assertEqual(
            manifest["readiness_status"],
            "backend_candidate_admissible_pending_capture",
        )
        self.assertTrue(manifest["admissible_for_p1_nonce_handoff"])
        self.assertEqual(manifest["detected_blockers"], [])
        self.assertEqual(manifest["handoff_manifest_path"], "handoff/manifest.json")
        self.assertIn("handoff/manifest.json", checksums)
        self.assertIn(str(out_dir / "handoff" / "request" / "request.json"), handoff["backend_command"])
        self.assertNotIn("{request}", handoff["backend_command"])
        self.assertEqual(report["handoff"]["manifest"], handoff)

    def test_attempt_requires_request_placeholder_in_backend_command(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            backend_crate = write_backend_crate(temp_root, hazmat=False)
            emitter = write_backend_emitter(temp_root)
            with self.assertRaisesRegex(ValueError, r"requires \{request\} placeholder"):
                module.build_attempt(
                    ROOT,
                    temp_root / "attempt",
                    backend_crate=backend_crate,
                    backend_command=[sys.executable, str(emitter), "--request", "stale.json"],
                    generated_at="2026-07-03T00:00:00Z",
                )

    def test_attempt_records_execution_failure_after_admissible_readiness(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            backend_crate = write_backend_crate(temp_root, hazmat=False)
            emitter = write_failing_backend_emitter(
                temp_root,
                stdout="partial output",
                stderr="backend unavailable",
                code=7,
            )
            out_dir = temp_root / "attempt"

            report = module.build_attempt(
                ROOT,
                out_dir,
                backend_crate=backend_crate,
                backend_command=[sys.executable, str(emitter), "--request", "{request}"],
                backend_label="reviewed-backend-candidate",
                generated_at="2026-07-03T00:00:00Z",
            )

            manifest = json.loads((out_dir / "manifest.json").read_text())
            summary = (out_dir / "summary.md").read_text()

        self.assertEqual(manifest["attempt_status"], "capture_execution_failed")
        self.assertTrue(manifest["backend_command_executed"])
        self.assertIsNone(manifest["handoff_manifest_path"])
        self.assertEqual(manifest["capture_failure"]["phase"], "execution")
        self.assertIn("backend unavailable", manifest["capture_failure"]["message"])
        self.assertEqual(manifest["capture_failure"]["exit_code"], 7)
        self.assertIn("partial output", manifest["capture_failure"]["stdout"])
        self.assertIn("backend unavailable", manifest["capture_failure"]["stderr"])
        self.assertIn("capture_execution_failed", summary)
        self.assertEqual(report["manifest"], manifest)

    def test_attempt_records_validation_failure_after_admissible_readiness(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            backend_crate = write_backend_crate(temp_root, hazmat=False)
            emitter = write_invalid_capture_emitter(temp_root)
            out_dir = temp_root / "attempt"

            report = module.build_attempt(
                ROOT,
                out_dir,
                backend_crate=backend_crate,
                backend_command=[sys.executable, str(emitter), "--request", "{request}"],
                backend_label="reviewed-backend-candidate",
                generated_at="2026-07-03T00:00:00Z",
            )

            manifest = json.loads((out_dir / "manifest.json").read_text())

        self.assertEqual(manifest["attempt_status"], "capture_validation_failed")
        self.assertTrue(manifest["backend_command_executed"])
        self.assertIsNone(manifest["handoff_manifest_path"])
        self.assertEqual(manifest["capture_failure"]["phase"], "validation")
        self.assertIn("canonical capture JSON", manifest["capture_failure"]["message"])
        self.assertEqual(manifest["capture_failure"]["exit_code"], 0)
        self.assertIn("not canonical capture json", manifest["capture_failure"]["stdout"])
        self.assertEqual(report["manifest"], manifest)


if __name__ == "__main__":
    unittest.main()
