import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HANDOFF_SCRIPT = ROOT / "scripts" / "run_nonce_producer_handoff_replay.py"
EMITTER_SCRIPT = ROOT / "scripts" / "emit_reviewed_nonce_producer_capture.py"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_admissible_readiness(path, request, request_sha256):
    readiness = {
        "schema": READINESS_SCHEMA,
        "schema_version": 1,
        "generated_at": "2026-07-03T00:00:01Z",
        "claim_boundary": "conformance/proof-review evidence only",
        "readiness_status": "backend_candidate_admissible_pending_capture",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "request": {
            "schema": request["schema"],
            "name": request["name"],
            "request_sha256": request_sha256,
            "request_path": "request/request.json",
            "capture_schema": CAPTURE_SCHEMA,
            "required_producer_evidence": "p1_shamir_nonce_dkg_tee_external_capture",
        },
        "backend": {
            "crate_path": "reviewed-p1-nonce-producer",
            "package_name": "reviewed-p1-nonce-producer",
            "version": "1.0.0",
            "description": "Reviewed external Shamir nonce DKG TEE nonce producer",
            "repository": "https://example.invalid/reviewed-p1-nonce-producer",
            "features": ["tee-attested"],
            "default_features": [],
            "categories": ["cryptography"],
            "cargo_toml_sha256": "44" * 32,
            "source_tree_sha256": "55" * 32,
            "source_file_count": 2,
            "source_inventory": [],
        },
        "capabilities": {
            "distributed_nonce_prf_output_share_interface": True,
            "distributed_nonce_prf_output_splitter": True,
            "distributed_nonce_masking_contribution": True,
            "reviewed_external_capture_contract": True,
            "centralized_nonce_prf_oracle": False,
            "hazmat_feature": False,
            "simulated_default_feature": False,
            "simulation_category": False,
            "research_grade_simulation_description": False,
            "deterministic_test_vector_plumbing": False,
        },
        "admissibility": {
            "admissible_for_p1_nonce_handoff": True,
            "detected_blockers": [],
            "blocked_reason": None,
            "requirements_to_become_admissible": [],
        },
        "closure_boundary": (
            "Backend readiness and source capability detection only; an actual "
            "reviewed capture and proof review remain required."
        ),
    }
    path.write_text(json.dumps(readiness, indent=2, sort_keys=True) + "\n")
    return readiness


def write_external_nonce_producer_shim(path):
    script = f"""#!/usr/bin/env python3
import importlib.util
import pathlib
import sys

request = None
root = pathlib.Path({str(ROOT)!r})
for index, arg in enumerate(sys.argv):
    if arg == "--request":
        request = pathlib.Path(sys.argv[index + 1])
    if arg == "--root":
        root = pathlib.Path(sys.argv[index + 1])
if request is None:
    raise SystemExit("--request is required")
spec = importlib.util.spec_from_file_location(
    "reviewed_nonce_producer_capture",
    root / "scripts" / "emit_reviewed_nonce_producer_capture.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.stdout.write(module.canonical_json(module.build_capture(request, root=root)))
"""
    path.write_text(script, encoding="utf-8")
    os.chmod(path, 0o755)
    return path


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
        self.assertEqual(
            capture_manifest["capture_source_profile"],
            "quarantined_local_schema_replay",
        )
        self.assertEqual(
            handoff_manifest["handoff_source_profile"],
            "quarantined_local_schema_replay",
        )
        self.assertTrue(handoff_manifest["quarantine"]["quarantined"])
        self.assertIn(
            "schema/importer replay only",
            handoff_manifest["quarantine"]["allowed_use"],
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
        self.assertIn("quarantined local", summary_md)
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

    def test_handoff_replay_requires_readiness_for_explicit_backend_command(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "handoff"
            request_path = out_dir / "request" / "request.json"
            with self.assertRaisesRegex(ValueError, "requires admissible backend readiness"):
                module.build_handoff(
                    ROOT,
                    out_dir,
                    backend_command=module.default_backend_command(request_path),
                    generated_at="2026-07-03T00:00:00Z",
                )

    def test_handoff_replay_rejects_blocked_backend_readiness(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "handoff"
            request_path = out_dir / "request" / "request.json"
            readiness_path = pathlib.Path(temp_dir) / "blocked_readiness.json"
            readiness = json.loads(
                (
                    ROOT
                    / "artifacts"
                    / "nonce-producer-backend-readiness"
                    / "latest"
                    / "manifest.json"
                ).read_text(encoding="utf-8")
            )
            readiness["readiness_status"] = "backend_detected_not_admissible"
            readiness["admissibility"]["admissible_for_p1_nonce_handoff"] = False
            readiness["admissibility"]["detected_blockers"] = [
                "hazmat feature present",
            ]
            readiness_path.write_text(json.dumps(readiness), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "backend readiness is not admissible"):
                module.build_handoff(
                    ROOT,
                    out_dir,
                    backend_command=module.default_backend_command(request_path),
                    backend_readiness=readiness_path,
                    generated_at="2026-07-03T00:00:00Z",
                )

    def test_handoff_replay_accepts_admissible_readiness_bound_to_reused_request(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "handoff"
            request_dir = out_dir / "request"
            request_report = module.build_request_artifacts(
                ROOT,
                request_dir,
                generated_at="2026-07-03T00:00:00Z",
            )
            readiness_path = pathlib.Path(temp_dir) / "readiness.json"
            readiness = write_admissible_readiness(
                readiness_path,
                request_report["request"],
                request_report["manifest"]["request_sha256"],
            )
            producer = write_external_nonce_producer_shim(
                pathlib.Path(temp_dir) / "reviewed_nonce_producer"
            )

            report = module.build_handoff(
                ROOT,
                out_dir,
                backend_command=[
                    str(producer),
                    "emit",
                    "--request",
                    str(out_dir / "request" / "request.json"),
                    "--root",
                    str(ROOT),
                ],
                backend_readiness=readiness_path,
                reuse_request=True,
                generated_at="2026-07-03T00:00:00Z",
            )

            handoff_manifest = json.loads((out_dir / "manifest.json").read_text())

        self.assertEqual(
            handoff_manifest["backend_readiness"]["schema"],
            READINESS_SCHEMA,
        )
        self.assertEqual(
            handoff_manifest["backend_readiness"]["readiness_status"],
            "backend_candidate_admissible_pending_capture",
        )
        self.assertEqual(
            handoff_manifest["backend_readiness"]["source_tree_sha256"],
            readiness["backend"]["source_tree_sha256"],
        )
        self.assertEqual(
            handoff_manifest["backend_readiness"]["request_sha256"],
            request_report["manifest"]["request_sha256"],
        )
        self.assertEqual(
            report["manifest"]["backend_readiness"],
            handoff_manifest["backend_readiness"],
        )
        self.assertEqual(
            handoff_manifest["handoff_source_profile"],
            "admissible_external_backend_capture",
        )
        self.assertFalse(handoff_manifest["quarantine"]["quarantined"])

    def test_handoff_replay_rejects_quarantined_local_replay_as_external_backend(self):
        module = load_module(HANDOFF_SCRIPT, "run_nonce_producer_handoff_replay")

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = pathlib.Path(temp_dir) / "handoff"
            request_dir = out_dir / "request"
            request_report = module.build_request_artifacts(
                ROOT,
                request_dir,
                generated_at="2026-07-03T00:00:00Z",
            )
            readiness_path = pathlib.Path(temp_dir) / "readiness.json"
            write_admissible_readiness(
                readiness_path,
                request_report["request"],
                request_report["manifest"]["request_sha256"],
            )

            with self.assertRaisesRegex(ValueError, "quarantined local replay"):
                module.build_handoff(
                    ROOT,
                    out_dir,
                    backend_command=module.default_backend_command(
                        out_dir / "request" / "request.json"
                    ),
                    backend_readiness=readiness_path,
                    reuse_request=True,
                    generated_at="2026-07-03T00:00:00Z",
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
