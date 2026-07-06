import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_hazmat_rejection_equivalence_batch.py"
ATTEMPT_SCHEMA = "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
HANDOFF_SCHEMA = "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
EXTERNAL_PRODUCER_EVIDENCE = "p1_shamir_nonce_dkg_tee_external_capture"
ADMISSIBLE_SOURCE_PROFILE = "admissible_external_backend_capture"


def load_module():
    assert SCRIPT.is_file(), f"missing comparator script: {SCRIPT}"
    spec = importlib.util.spec_from_file_location(
        "run_hazmat_rejection_equivalence_batch", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value), encoding="utf-8")


def sha256_text(text):
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def reviewed_capture(request_name, request_sha256, digest="cc" * 32, reviewed=True):
    return {
        "name": "outside-repo-p1-nonce-producer-capture",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "note": "Reviewed external nonce-producer capture produced outside the repo.",
        "threshold_nonce_accounting": {
            "schema": "lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
            "validator_count": 10000,
            "threshold": 6667,
            "closure_boundary": "test nonce-accounting evidence only",
        },
        "request": {
            "schema": REQUEST_SCHEMA,
            "name": request_name,
            "request_sha256": request_sha256,
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": "11" * 32,
            "threshold_output_certificate_digest_hex": "22" * 32,
            "standard_verifier_compatibility_artifact_digest_hex": "33" * 32,
        },
        "capture": {
            "source_reference": {"encoding": "hex", "value": "736f75726365"},
            "backend_implementation": {"encoding": "hex", "value": "696d706c"},
            "coordinator_attestation": {"encoding": "hex", "value": "617474657374"},
            "shamir_nonce_dkg_transcript": {"encoding": "hex", "value": "646b67"},
            "pairwise_mask_seed_commitments": {"encoding": "hex", "value": "6d61736b"},
            "nonce_share_commitments": {"encoding": "hex", "value": "7368617265"},
            "abort_accountability": {"encoding": "hex", "value": "61626f7274"},
            "external_review": {"encoding": "hex", "value": "726576696577"},
            "reviewed": reviewed,
        },
        "expected": {
            "source_reference_digest_hex": "44" * 32,
            "backend_implementation_digest_hex": "55" * 32,
            "coordinator_attestation_digest_hex": "66" * 32,
            "shamir_nonce_dkg_transcript_digest_hex": "77" * 32,
            "pairwise_mask_seed_commitment_digest_hex": "88" * 32,
            "nonce_share_commitment_digest_hex": "99" * 32,
            "abort_accountability_digest_hex": "aa" * 32,
            "external_review_digest_hex": "bb" * 32,
            "threshold_nonce_accounting_digest_hex": "bc" * 32,
            "distributed_nonce_producer_artifact_digest_hex": digest,
        },
    }


def write_reviewed_attempt(
    root,
    source_profile=ADMISSIBLE_SOURCE_PROFILE,
    quarantined=False,
    digest="cc" * 32,
    reviewed=True,
):
    request_name = "p1-reviewed-nonce-producer-request-001"
    request_sha256 = "12" * 32
    attempt_path = root / "intake" / "manifest.json"
    handoff_path = root / "intake" / "handoff" / "manifest.json"
    capture_path = root / "intake" / "handoff" / "capture" / "capture.json"
    capture = reviewed_capture(
        request_name,
        request_sha256,
        digest=digest,
        reviewed=reviewed,
    )
    capture_sha256 = sha256_text(canonical_json(capture))
    quarantine = {
        "quarantined": quarantined,
        "reason": "test quarantine" if quarantined else None,
        "allowed_use": "test only" if quarantined else "explicit external backend capture",
    }
    write_json(capture_path, capture)
    write_json(
        handoff_path,
        {
            "schema": HANDOFF_SCHEMA,
            "schema_version": 1,
            "generated_at": "2026-07-04T00:00:02Z",
            "handoff_status": "evidence_present_unclosed",
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "handoff_source_profile": source_profile,
            "quarantine": quarantine,
            "request_schema": REQUEST_SCHEMA,
            "capture_schema": CAPTURE_SCHEMA,
            "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
            "request_name": request_name,
            "request_sha256": request_sha256,
            "capture_sha256": capture_sha256,
            "capture_dir": "capture",
        },
    )
    write_json(
        attempt_path,
        {
            "schema": ATTEMPT_SCHEMA,
            "schema_version": 1,
            "generated_at": "2026-07-04T00:00:02Z",
            "attempt_status": "capture_promoted",
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "request_schema": REQUEST_SCHEMA,
            "request_name": request_name,
            "request_sha256": request_sha256,
            "backend_command_executed": True,
            "handoff_manifest_path": "handoff/manifest.json",
            "handoff_source_profile": source_profile,
            "handoff_quarantine": quarantine,
        },
    )
    return attempt_path


class HazmatRejectionEquivalenceBatchTests(unittest.TestCase):
    def test_build_emitter_project_pins_centralized_threshold_comparator_surface(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            backend_crate = root / "backend"
            repo_root = root / "repo"
            work_dir = root / "emitter"
            backend_crate.mkdir()
            repo_root.mkdir()
            (backend_crate / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )
            (repo_root / "Cargo.toml").write_text(
                "[package]\nname = \"lattice-aggregation\"\n",
                encoding="utf-8",
            )

            module.write_emitter_project(work_dir, repo_root, backend_crate)

            cargo_toml = (work_dir / "Cargo.toml").read_text(encoding="utf-8")
            main_rs = (work_dir / "src" / "main.rs").read_text(encoding="utf-8")

        self.assertIn(f'path = "{backend_crate.resolve()}"', cargo_toml)
        self.assertIn(f'path = "{repo_root.resolve()}"', cargo_toml)
        self.assertIn('features = ["raw-real-mldsa"]', cargo_toml)
        self.assertIn(
            "derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key",
            main_rs,
        )
        self.assertIn(
            "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met",
            main_rs,
        )
        self.assertIn(
            "derive_mldsa65_centralized_domain_masking_contribution_from_share",
            main_rs,
        )
        self.assertIn(
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key",
            main_rs,
        )
        self.assertIn(
            "derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share",
            main_rs,
        )
        self.assertIn(
            "split_mldsa65_distributed_nonce_prf_output",
            main_rs,
        )
        self.assertIn(
            "lattice-aggregation:p1-rejection-equivalence-batch:v1",
            main_rs,
        )
        self.assertIn("mldsa65-centralized-vs-threshold-rejection-batch", main_rs)
        self.assertIn("centralized-rho-double-prime-kappa", main_rs)
        self.assertIn("distributed-nonce-prf-output-shares", main_rs)
        self.assertIn("aligned_mask_domain", main_rs)
        self.assertIn("distributed_nonce_prf_domain", main_rs)
        self.assertIn("mask_domain", main_rs)
        self.assertIn("threshold_attempts", main_rs)
        self.assertIn("centralized_attempts", main_rs)
        self.assertIn("predicate_mismatches", main_rs)
        self.assertIn("challenge_digest_matches", main_rs)
        self.assertIn("accepted_or_rejected_matches", main_rs)
        self.assertIn("close_candidate", main_rs)
        self.assertIn("nonce_prf_producer", main_rs)
        self.assertIn("hazmat-prf-output-oracle", main_rs)
        self.assertIn("reviewed_distributed_nonce_producer_present", main_rs)
        self.assertIn("distributed_nonce_producer_artifact_digest", main_rs)
        self.assertIn("--distributed-nonce-producer-artifact-digest", main_rs)
        self.assertIn("distributed-nonce-prf-output-shares", main_rs)
        self.assertIn("reviewed_distributed_nonce_producer_present(&config)", main_rs)
        self.assertIn(
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key",
            main_rs,
        )
        self.assertIn("claims_rejection_distribution_preservation", main_rs)
        self.assertIn("claims_reviewed_distributed_nonce_producer", main_rs)
        parsed = module.parse_args(["--backend-crate", "x", "--aligned-mask-domain"])
        self.assertTrue(parsed.aligned_mask_domain)
        parsed = module.parse_args(
            ["--backend-crate", "x", "--distributed-nonce-prf-domain"]
        )
        self.assertTrue(parsed.distributed_nonce_prf_domain)
        parsed = module.parse_args(
            ["--backend-crate", "x", "--backend-feature", "hazmat-real-mldsa"]
        )
        self.assertEqual(parsed.backend_feature, "hazmat-real-mldsa")
        parsed = module.parse_args(
            [
                "--backend-crate",
                "x",
                "--reviewed-distributed-nonce-producer-attempt",
                "attempt.json",
            ]
        )
        self.assertEqual(
            parsed.reviewed_distributed_nonce_producer_attempt,
            "attempt.json",
        )

    def test_build_emitter_project_allows_backend_feature_override(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            backend_crate = root / "backend"
            repo_root = root / "repo"
            work_dir = root / "emitter"
            backend_crate.mkdir()
            repo_root.mkdir()
            (backend_crate / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )
            (repo_root / "Cargo.toml").write_text(
                "[package]\nname = \"lattice-aggregation\"\n",
                encoding="utf-8",
            )

            module.write_emitter_project(
                work_dir,
                repo_root,
                backend_crate,
                backend_feature="hazmat-real-mldsa",
            )

            cargo_toml = (work_dir / "Cargo.toml").read_text(encoding="utf-8")

        backend_line = next(
            line for line in cargo_toml.splitlines() if line.startswith("dytallix-pq-threshold")
        )
        self.assertIn('features = ["hazmat-real-mldsa"]', backend_line)
        self.assertNotIn('features = ["raw-real-mldsa"]', backend_line)

    def test_reviewed_nonce_attempt_extracts_digest_from_admissible_capture(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(root, digest="cd" * 32)

            digest = module.extract_reviewed_distributed_nonce_producer_artifact_digest(
                attempt_path
            )

        self.assertEqual(digest, "cd" * 32)

    def test_reviewed_nonce_attempt_rejects_quarantined_reference_profile(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(
                root,
                source_profile="repo_reference_cli_capture",
                quarantined=True,
            )

            with self.assertRaisesRegex(ValueError, "source profile"):
                module.extract_reviewed_distributed_nonce_producer_artifact_digest(
                    attempt_path
                )

    def test_reviewed_nonce_attempt_rejects_unreviewed_or_zero_digest_capture(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(root, reviewed=False)

            with self.assertRaisesRegex(ValueError, "reviewed"):
                module.extract_reviewed_distributed_nonce_producer_artifact_digest(
                    attempt_path
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(root, digest="00" * 32)

            with self.assertRaisesRegex(ValueError, "all-zero|invalid"):
                module.extract_reviewed_distributed_nonce_producer_artifact_digest(
                    attempt_path
                )

    def test_emitter_args_forward_validated_reviewed_nonce_digest(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(root, digest="ef" * 32)
            args = module.parse_args(
                [
                    "--backend-crate",
                    "backend",
                    "--distributed-nonce-prf-domain",
                    "--reviewed-distributed-nonce-producer-attempt",
                    str(attempt_path),
                ]
            )

            emitter_args = module.emitter_args_from_options(args)

        self.assertIn("--distributed-nonce-prf-domain", emitter_args)
        self.assertEqual(
            emitter_args[-2:],
            ["--distributed-nonce-producer-artifact-digest", "ef" * 32],
        )

    def test_reviewed_nonce_attempt_requires_distributed_nonce_domain(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            attempt_path = write_reviewed_attempt(root)
            args = module.parse_args(
                [
                    "--backend-crate",
                    "backend",
                    "--reviewed-distributed-nonce-producer-attempt",
                    str(attempt_path),
                ]
            )

            with self.assertRaisesRegex(ValueError, "--distributed-nonce-prf-domain"):
                module.emitter_args_from_options(args)

    def test_run_batch_invokes_generated_release_emitter_and_returns_stdout(self):
        module = load_module()

        calls = []

        def fake_command_runner(command, cwd, **kwargs):
            calls.append((command, pathlib.Path(cwd), kwargs))

            class Result:
                returncode = 0
                stdout = '{"schema":"lattice-aggregation:p1-rejection-equivalence-batch:v1"}\n'
                stderr = "cargo build output\n"

            return Result()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            backend_crate = root / "backend"
            repo_root = root / "repo"
            work_dir = root / "emitter"
            backend_crate.mkdir()
            repo_root.mkdir()
            (backend_crate / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )
            (repo_root / "Cargo.toml").write_text(
                "[package]\nname = \"lattice-aggregation\"\n",
                encoding="utf-8",
            )

            stdout = module.run_batch(
                repo_root=repo_root,
                backend_crate=backend_crate,
                work_dir=work_dir,
                command_runner=fake_command_runner,
            )

        self.assertEqual(
            stdout, '{"schema":"lattice-aggregation:p1-rejection-equivalence-batch:v1"}\n'
        )
        self.assertEqual(len(calls), 1)
        command, cwd, kwargs = calls[0]
        self.assertEqual(cwd, work_dir)
        self.assertEqual(command, ["cargo", "run", "--release"])
        self.assertEqual(kwargs["text"], True)
        self.assertEqual(kwargs["stdout"], module.subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], module.subprocess.PIPE)


if __name__ == "__main__":
    unittest.main()
