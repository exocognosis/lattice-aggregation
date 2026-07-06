#!/usr/bin/env python3
"""Scaffold an outside-repo P1 real-threshold backend emitter workspace."""

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path


PACKAGE_NAME = "p1-external-backend-emitter"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
REQUEST_PATH_HINT = "artifacts/backend-emission-request/latest/request.json"
DEFAULT_BACKEND_FEATURE = "raw-real-mldsa"


def load_hazmat_capture_module():
    """Load the maintained Rust emitter source from the existing adapter script."""
    script = Path(__file__).resolve().parent / "run_hazmat_threshold_backend_capture.py"
    spec = importlib.util.spec_from_file_location(
        "run_hazmat_threshold_backend_capture",
        script,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_path(path):
    """Resolve a path without requiring it to exist."""
    return Path(path).expanduser().resolve(strict=False)


def path_is_within(child, parent):
    """Return true when child resolves inside parent."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def require_crate_path(path, label):
    """Require a local Rust crate/workspace root."""
    path = resolve_path(path)
    if not path.exists():
        raise ValueError(f"{label} path does not exist: {path}")
    if not (path / "Cargo.toml").is_file():
        raise ValueError(f"{label} Cargo.toml is missing: {path}")
    return path


def require_outside_repo(path, repo_root, label):
    """Require a path to resolve outside the lattice repository."""
    path = resolve_path(path)
    if path_is_within(path, repo_root):
        raise ValueError(f"{label} must be outside the lattice repository: {path}")
    return path


def cargo_toml(repo_root, backend_crate, backend_feature, hazmat_module):
    """Render the external emitter workspace Cargo manifest."""
    return "\n".join(
        [
            "[package]",
            f'name = "{PACKAGE_NAME}"',
            'version = "0.1.0"',
            'edition = "2021"',
            "publish = false",
            "",
            "[dependencies]",
            (
                "dytallix-pq-threshold = { "
                f"path = {hazmat_module.toml_path(backend_crate)}, "
                f"features = [{json.dumps(backend_feature)}], "
                "default-features = false }"
            ),
            (
                "lattice-aggregation = { "
                f"path = {hazmat_module.toml_path(repo_root)}, "
                'features = ["raw-real-mldsa"], '
                "default-features = false }"
            ),
            'serde = { version = "1", features = ["derive"] }',
            'serde_json = "1"',
            'sha2 = "0.10"',
            'sha3 = "0.10"',
            "",
        ]
    )


def wrapper_script(workspace):
    """Render an outside-repo executable wrapper for the capture importer."""
    manifest_path = workspace / "Cargo.toml"
    return "\n".join(
        [
            "#!/bin/sh",
            "set -eu",
            'if [ "$#" -ne 1 ]; then',
            '  echo "usage: run_capture.sh <backend-emission-request.json>" >&2',
            "  exit 64",
            "fi",
            (
                "exec cargo run --release --manifest-path "
                f'"{manifest_path}" -- "$1"'
            ),
            "",
        ]
    )


def readme(repo_root, backend_crate, backend_feature, workspace, generated_at):
    """Render operator notes for the generated external workspace."""
    wrapper = workspace / "run_capture.sh"
    request_path = repo_root / REQUEST_PATH_HINT
    return "\n".join(
        [
            "# P1 External Backend Emitter Workspace",
            "",
            f"Generated at: `{generated_at}`",
            "",
            "This workspace is outside the lattice repository and is intended to "
            "produce request-bound backend emission capture JSON for ingestion by "
            "`scripts/run_backend_emission_capture.py`.",
            "",
            f"- Claim boundary: `{CLAIM_BOUNDARY}`",
            f"- Capture schema: `{CAPTURE_SCHEMA}`",
            f"- Lattice repo: `{repo_root}`",
            f"- Backend crate: `{backend_crate}`",
            f"- Backend feature: `{backend_feature}`",
            "",
            "Run the importer with the outside-repo wrapper as the backend command:",
            "",
            "```bash",
            "python3 scripts/run_backend_emission_capture.py \\",
            f"  --request {request_path} \\",
            f"  --backend-command {wrapper} {request_path}",
            "```",
            "",
            "The emitted capture remains conformance/proof-review evidence. "
            "It is not a theorem-closure proof, FIPS validation, CAVP/ACVTS "
            "validation, or an independent cryptographic review package.",
            "",
        ]
    )


def scaffold_workspace(
    repo_root,
    workspace,
    backend_crate,
    backend_feature=DEFAULT_BACKEND_FEATURE,
    generated_at=None,
    force=False,
):
    """Write an external Cargo workspace and wrapper command for capture ingestion."""
    repo_root = require_crate_path(repo_root, "repo root")
    workspace = require_outside_repo(workspace, repo_root, "workspace")
    backend_crate = require_outside_repo(backend_crate, repo_root, "backend crate")
    backend_crate = require_crate_path(backend_crate, "backend crate")
    if not backend_feature:
        raise ValueError("backend feature is required")

    if workspace.exists() and any(workspace.iterdir()) and not force:
        raise ValueError(f"workspace already exists and is not empty: {workspace}")

    hazmat_module = load_hazmat_capture_module()
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    src_dir = workspace / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    (workspace / "Cargo.toml").write_text(
        cargo_toml(repo_root, backend_crate, backend_feature, hazmat_module),
        encoding="utf-8",
    )
    (src_dir / "main.rs").write_text(
        hazmat_module.RUST_EMITTER_SOURCE,
        encoding="utf-8",
    )
    wrapper = workspace / "run_capture.sh"
    wrapper.write_text(wrapper_script(workspace), encoding="utf-8")
    wrapper.chmod(0o755)
    (workspace / "README.md").write_text(
        readme(repo_root, backend_crate, backend_feature, workspace, generated_at),
        encoding="utf-8",
    )

    return {
        "workspace": str(workspace),
        "backend_crate": str(backend_crate),
        "backend_feature": backend_feature,
        "repo_root": str(repo_root),
        "backend_command": [str(wrapper)],
        "request_path_hint": str(repo_root / REQUEST_PATH_HINT),
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Scaffold an outside-repo Rust emitter workspace for P1 "
            "real-threshold backend capture ingestion"
        )
    )
    parser.add_argument("--repo-root", default=".", help="lattice repository root")
    parser.add_argument(
        "--workspace",
        required=True,
        help="outside-repo workspace directory to write",
    )
    parser.add_argument(
        "--backend-crate",
        required=True,
        help="outside-repo dytallix-pq-threshold checkout with raw-real-mldsa",
    )
    parser.add_argument(
        "--backend-feature",
        default=DEFAULT_BACKEND_FEATURE,
        help="backend crate feature exposing the hazmat ML-DSA APIs",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite files in an existing non-empty workspace",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    result = scaffold_workspace(
        repo_root=args.repo_root,
        workspace=args.workspace,
        backend_crate=args.backend_crate,
        backend_feature=args.backend_feature,
        force=args.force,
    )
    print(f"wrote external backend workspace to {result['workspace']}")
    print("backend command: " + " ".join(result["backend_command"]))
    print(f"request path hint: {result['request_path_hint']}")


if __name__ == "__main__":
    main()
