import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_hazmat_threshold_backend_capture.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "run_hazmat_threshold_backend_capture", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HazmatThresholdBackendCaptureAdapterTests(unittest.TestCase):
    def test_build_emitter_project_requires_explicit_backend_crate_and_repo_root(self):
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
        self.assertIn('features = ["hazmat-real-mldsa"]', cargo_toml)
        self.assertNotIn("Lattice Aggregation Current", cargo_toml)
        self.assertIn("backend_external_pure_verifier_accepts", main_rs)
        self.assertIn("repo_pr69_hazmat_provider_accepts", main_rs)
        self.assertIn(
            "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met",
            main_rs,
        )
        self.assertIn("attempt_count", main_rs)
        self.assertIn("retry_count", main_rs)
        self.assertIn("per-attempt-bound-predicates", main_rs)
        self.assertIn("rejection_predicate_fields_available", main_rs)
        self.assertIn("attempts", main_rs)
        self.assertIn("mask_seed_digest_hex", main_rs)
        self.assertIn("challenge_digest_hex", main_rs)
        self.assertIn("z_bound_result", main_rs)
        self.assertIn("r0_bound_result", main_rs)
        self.assertIn("ct0_bound_result", main_rs)
        self.assertIn("hint_bound_result", main_rs)
        self.assertIn("accepted_or_rejected", main_rs)
        self.assertNotIn("accepted-attempt-only", main_rs)
        self.assertNotIn(
            "blocked_until_backend_exports_bound_level_rejection_transcript",
            main_rs,
        )
        self.assertIn(
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
            main_rs,
        )

    def test_run_capture_invokes_generated_release_emitter_and_returns_stdout(self):
        module = load_module()

        calls = []

        def fake_command_runner(command, cwd, **kwargs):
            calls.append((command, pathlib.Path(cwd), kwargs))

            class Result:
                returncode = 0
                stdout = '{"schema":"capture"}\n'
                stderr = "cargo build output\n"

            return Result()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            backend_crate = root / "backend"
            repo_root = root / "repo"
            request_path = root / "request.json"
            work_dir = root / "emitter"
            backend_crate.mkdir()
            repo_root.mkdir()
            request_path.write_text("{}", encoding="utf-8")
            (backend_crate / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )
            (repo_root / "Cargo.toml").write_text(
                "[package]\nname = \"lattice-aggregation\"\n",
                encoding="utf-8",
            )

            stdout = module.run_capture(
                request_path=request_path,
                repo_root=repo_root,
                backend_crate=backend_crate,
                work_dir=work_dir,
                command_runner=fake_command_runner,
            )

        self.assertEqual(stdout, '{"schema":"capture"}\n')
        self.assertEqual(len(calls), 1)
        command, cwd, kwargs = calls[0]
        self.assertEqual(cwd, work_dir)
        self.assertEqual(command[:3], ["cargo", "run", "--release"])
        self.assertEqual(command[-2:], ["--", str(request_path)])
        self.assertEqual(kwargs["text"], True)
        self.assertEqual(kwargs["stdout"], module.subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], module.subprocess.PIPE)

    def test_run_capture_rejects_missing_or_invalid_backend_crate(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            repo_root = root / "repo"
            request_path = root / "request.json"
            missing_backend = root / "missing-backend"
            invalid_backend = root / "invalid-backend"
            repo_root.mkdir()
            invalid_backend.mkdir()
            request_path.write_text("{}", encoding="utf-8")
            (repo_root / "Cargo.toml").write_text(
                "[package]\nname = \"lattice-aggregation\"\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "backend crate path"):
                module.run_capture(
                    request_path=request_path,
                    repo_root=repo_root,
                    backend_crate=missing_backend,
                    work_dir=root / "emitter-a",
                )
            with self.assertRaisesRegex(ValueError, "backend crate Cargo.toml"):
                module.run_capture(
                    request_path=request_path,
                    repo_root=repo_root,
                    backend_crate=invalid_backend,
                    work_dir=root / "emitter-b",
                )


if __name__ == "__main__":
    unittest.main()
