import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_hazmat_rejection_equivalence_batch.py"


def load_module():
    assert SCRIPT.is_file(), f"missing comparator script: {SCRIPT}"
    spec = importlib.util.spec_from_file_location(
        "run_hazmat_rejection_equivalence_batch", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
