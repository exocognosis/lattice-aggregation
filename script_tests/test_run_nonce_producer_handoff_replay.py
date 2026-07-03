import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HANDOFF_SCRIPT = ROOT / "scripts" / "run_nonce_producer_handoff_replay.py"
EMITTER_SCRIPT = ROOT / "scripts" / "emit_reviewed_nonce_producer_capture.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NonceProducerHandoffReplayTests(unittest.TestCase):
    def test_handoff_replay_generates_request_capture_and_provenance(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "handoff"
            report = module.build_handoff(
                ROOT,
                out_dir,
                generated_at="2026-07-02T00:00:00Z",
            )

            request = json.loads((out_dir / "request" / "request.json").read_text())
            capture = json.loads((out_dir / "capture" / "capture.json").read_text())
            capture_manifest = json.loads(
                (out_dir / "capture" / "manifest.json").read_text()
            )
            handoff_manifest = json.loads((out_dir / "manifest.json").read_text())
            summary_md = (out_dir / "summary.md").read_text()
            checksums = (out_dir / "SHA256SUMS").read_text()

        self.assertEqual(request["schema"], REQUEST_SCHEMA)
        self.assertEqual(capture["schema"], CAPTURE_SCHEMA)
        self.assertEqual(capture["request"]["schema"], REQUEST_SCHEMA)
        self.assertEqual(capture["request"]["name"], request["name"])
        self.assertEqual(
            capture["request"]["request_sha256"],
            handoff_manifest["request_sha256"],
        )
        self.assertEqual(capture["predecessors"], request["predecessors"])
        self.assertEqual(
            capture["producer_evidence"],
            "p1_shamir_nonce_dkg_tee_external_capture",
        )
        self.assertEqual(capture["capture"]["reviewed"], True)
        self.assertEqual(
            handoff_manifest["schema"],
            "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1",
        )
        self.assertEqual(handoff_manifest["handoff_status"], "evidence_present_unclosed")
        self.assertEqual(
            handoff_manifest["capture_manifest_sha256"],
            report["manifest"]["capture_manifest_sha256"],
        )
        self.assertEqual(
            handoff_manifest["external_capture_provenance"],
            capture_manifest["external_capture_provenance"],
        )
        command_text = " ".join(capture_manifest["backend_command"]).lower()
        for forbidden in (
            "hazmat",
            "localnet",
            "deterministic",
            "simulation",
            "simulated",
            "fixture",
            "centralized",
            "single-key",
        ):
            self.assertNotIn(forbidden, command_text)
        self.assertIn("request/request.json", checksums)
        self.assertIn("capture/capture.json", checksums)
        self.assertIn("evidence_present_unclosed", summary_md)
        self.assertIn("does not prove Criterion 2", summary_md)

    def test_handoff_replay_rejects_forbidden_backend_command_sources(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "forbidden backend command"):
                module.build_handoff(
                    ROOT,
                    pathlib.Path(temp_dir) / "handoff",
                    backend_command=["hazmat-centralized-prf", "emit-capture"],
                )

    def test_reviewed_capture_emitter_binds_exact_request_digest_and_expected_package(self):
        handoff = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")
        emitter = load_module(EMITTER_SCRIPT, "emit_reviewed_nonce_producer_capture")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = pathlib.Path(temp_dir)
            request_dir = temp_root / "request"
            request_report = handoff.build_request_artifacts(
                ROOT,
                request_dir,
                generated_at="2026-07-02T00:00:00Z",
            )
            capture = emitter.build_capture(
                request_dir / "request.json",
                ROOT,
                generated_at="2026-07-02T00:00:01Z",
            )

        self.assertEqual(capture["schema"], CAPTURE_SCHEMA)
        self.assertEqual(capture["request"]["name"], request_report["request"]["name"])
        self.assertEqual(
            capture["request"]["request_sha256"],
            request_report["manifest"]["request_sha256"],
        )
        self.assertEqual(
            capture["expected"]["source_reference_digest_hex"],
            emitter.domain_digest_hex(
                b"lattice-aggregation:p1-distributed-nonce-producer-source-reference:v1",
                capture["capture"]["source_reference"]["value"].encode("utf-8"),
            ),
        )
        self.assertRegex(
            capture["expected"]["distributed_nonce_producer_artifact_digest_hex"],
            r"^[0-9a-f]{64}$",
        )
        self.assertNotEqual(
            capture["expected"]["distributed_nonce_producer_artifact_digest_hex"],
            "00" * 32,
        )


if __name__ == "__main__":
    unittest.main()
