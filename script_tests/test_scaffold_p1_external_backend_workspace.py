import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scaffold_p1_external_backend_workspace.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "scaffold_p1_external_backend_workspace",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P1ExternalBackendWorkspaceScaffoldTests(unittest.TestCase):
    def test_rejects_workspace_or_backend_crate_inside_repo(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "repo"
            root.mkdir()
            (root / "Cargo.toml").write_text("[package]\nname = \"repo\"\n", encoding="utf-8")
            outside = pathlib.Path(temp_dir) / "external"
            outside.mkdir()
            outside_backend = outside / "dytallix-pq-threshold"
            outside_backend.mkdir()
            (outside_backend / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )
            inside_workspace = root / "generated-backend"
            inside_backend = root / "dytallix-pq-threshold"

            with self.assertRaisesRegex(ValueError, "outside the lattice repository"):
                module.scaffold_workspace(
                    repo_root=root,
                    workspace=inside_workspace,
                    backend_crate=outside_backend,
                )

            with self.assertRaisesRegex(ValueError, "outside the lattice repository"):
                module.scaffold_workspace(
                    repo_root=root,
                    workspace=outside / "workspace",
                    backend_crate=inside_backend,
                )

    def test_writes_external_workspace_from_existing_hazmat_emitter_source(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "repo"
            root.mkdir()
            (root / "Cargo.toml").write_text("[package]\nname = \"repo\"\n", encoding="utf-8")
            workspace = pathlib.Path(temp_dir) / "external-workspace"
            backend_crate = pathlib.Path(temp_dir) / "dytallix-pq-threshold"
            backend_crate.mkdir()
            (backend_crate / "Cargo.toml").write_text(
                "[package]\nname = \"dytallix-pq-threshold\"\n",
                encoding="utf-8",
            )

            result = module.scaffold_workspace(
                repo_root=root,
                workspace=workspace,
                backend_crate=backend_crate,
                backend_feature="hazmat-real-mldsa",
                generated_at="2026-07-05T00:00:00Z",
            )

            cargo_toml = (workspace / "Cargo.toml").read_text(encoding="utf-8")
            main_rs = (workspace / "src" / "main.rs").read_text(encoding="utf-8")
            readme = (workspace / "README.md").read_text(encoding="utf-8")
            wrapper = workspace / "run_capture.sh"
            wrapper_text = wrapper.read_text(encoding="utf-8")

        self.assertEqual(result["workspace"], str(module.resolve_path(workspace)))
        self.assertEqual(
            result["backend_command"][0],
            str(module.resolve_path(wrapper)),
        )
        self.assertEqual(result["backend_feature"], "hazmat-real-mldsa")
        self.assertIn("p1-external-backend-emitter", cargo_toml)
        self.assertIn(str(backend_crate), cargo_toml)
        self.assertIn(str(root), cargo_toml)
        backend_line = next(
            line for line in cargo_toml.splitlines() if line.startswith("dytallix-pq-threshold")
        )
        self.assertIn('features = ["hazmat-real-mldsa"]', backend_line)
        self.assertNotIn('features = ["raw-real-mldsa"]', backend_line)
        self.assertIn(
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
            main_rs,
        )
        self.assertIn("scripts/run_backend_emission_capture.py", readme)
        self.assertIn("2026-07-05T00:00:00Z", readme)
        self.assertIn("hazmat-real-mldsa", readme)
        self.assertIn("cargo run --release --manifest-path", wrapper_text)


if __name__ == "__main__":
    unittest.main()
