#!/usr/bin/env python3
"""Attempt a P1 nonce-producer capture only after readiness passes."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


ATTEMPT_SCHEMA = "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
ATTEMPT_STATUS_BLOCKED = "backend_readiness_blocked"
ATTEMPT_STATUS_PROMOTED = "capture_promoted"
REQUEST_PLACEHOLDER = "{request}"


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_bytes(data):
    """Return the SHA-256 digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return sha256_bytes(text.encode("utf-8"))


def sha256_path(path):
    """Return the SHA-256 digest for a file path."""
    return sha256_bytes(Path(path).read_bytes())


def load_json(path):
    """Load JSON from a path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_script_module(root, script_name, module_name):
    """Load one repo script as a Python module."""
    script = Path(root) / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_name, script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def substitute_request_placeholder(backend_command, request_path):
    """Bind a backend command template to the generated request path."""
    if not backend_command:
        raise ValueError("admissible nonce-producer attempt requires a backend command")
    if not any(REQUEST_PLACEHOLDER in arg for arg in backend_command):
        raise ValueError(
            "admissible nonce-producer attempt requires {request} placeholder"
        )
    return [
        arg.replace(REQUEST_PLACEHOLDER, str(request_path))
        for arg in list(backend_command)
    ]


def relative_to_out(out_dir, path):
    """Render a generated path relative to the attempt output directory."""
    return Path(path).relative_to(Path(out_dir)).as_posix()


def attempt_manifest(
    out_dir,
    request_report,
    readiness_manifest,
    readiness_manifest_path,
    backend_command_template,
    backend_command,
    generated_at,
    handoff_manifest_path=None,
):
    """Build the top-level capture-attempt manifest."""
    out_dir = Path(out_dir)
    admissibility = readiness_manifest["admissibility"]
    admissible = admissibility["admissible_for_p1_nonce_handoff"]
    status = ATTEMPT_STATUS_PROMOTED if admissible else ATTEMPT_STATUS_BLOCKED
    handoff_sha256 = (
        sha256_path(handoff_manifest_path) if handoff_manifest_path else None
    )
    return {
        "schema": ATTEMPT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "attempt_status": status,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "request_schema": request_report["request"]["schema"],
        "request_name": request_report["request"]["name"],
        "request_path": "handoff/request/request.json",
        "request_sha256": request_report["manifest"]["request_sha256"],
        "readiness_schema": READINESS_SCHEMA,
        "readiness_status": readiness_manifest["readiness_status"],
        "readiness_manifest_path": relative_to_out(out_dir, readiness_manifest_path),
        "readiness_manifest_sha256": sha256_path(readiness_manifest_path),
        "admissible_for_p1_nonce_handoff": admissible,
        "detected_blockers": list(admissibility["detected_blockers"]),
        "backend_package_name": readiness_manifest["backend"]["package_name"],
        "backend_source_tree_sha256": readiness_manifest["backend"][
            "source_tree_sha256"
        ],
        "backend_command_template": list(backend_command_template),
        "backend_command": list(backend_command),
        "backend_command_executed": bool(admissible),
        "handoff_manifest_path": (
            relative_to_out(out_dir, handoff_manifest_path)
            if handoff_manifest_path
            else None
        ),
        "handoff_manifest_sha256": handoff_sha256,
        "closure_boundary": (
            "Capture-attempt orchestration only; an actual reviewed external "
            "threshold nonce producer and proof review remain required for "
            "Criterion 2 or theorem closure."
        ),
    }


def render_summary(manifest):
    """Render a concise capture-attempt summary."""
    lines = [
        "# P1 Admissible Nonce-Producer Capture Attempt",
        "",
        "This artifact records the executable decision point before promoting a "
        "P1 distributed nonce-producer capture. It is conformance/proof-review "
        "evidence only.",
        "",
        f"- Status: `{manifest['attempt_status']}`",
        f"- Request: `{manifest['request_name']}`",
        f"- Request SHA-256: `{manifest['request_sha256']}`",
        f"- Backend package: `{manifest['backend_package_name']}`",
        f"- Backend command executed: `{str(manifest['backend_command_executed']).lower()}`",
        f"- Readiness status: `{manifest['readiness_status']}`",
    ]
    if manifest["detected_blockers"]:
        lines.append(
            "- Detected blockers: `"
            + "`, `".join(manifest["detected_blockers"])
            + "`"
        )
    if manifest["handoff_manifest_path"]:
        lines.append(f"- Handoff manifest: `{manifest['handoff_manifest_path']}`")
    lines.extend(
        [
            "",
            "This attempt does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )
    return "\n".join(lines)


def render_checksums(out_dir):
    """Render checksums for all generated attempt files."""
    out_dir = Path(out_dir)
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    return "\n".join(lines) + "\n"


def write_attempt_artifacts(out_dir, manifest):
    """Write top-level attempt manifest, summary, and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    (out_dir / "summary.md").write_text(render_summary(manifest), encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(render_checksums(out_dir), encoding="utf-8")


def build_attempt(
    root,
    out_dir,
    backend_crate,
    backend_command,
    backend_label=None,
    generated_at=None,
):
    """Run the readiness-gated capture-attempt workflow."""
    root = Path(root)
    out_dir = Path(out_dir)
    handoff_dir = out_dir / "handoff"
    request_dir = handoff_dir / "request"
    readiness_dir = out_dir / "readiness"
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    handoff = load_script_module(
        root,
        "run_nonce_producer_handoff_replay.py",
        "run_nonce_producer_handoff_replay_for_attempt",
    )
    readiness = load_script_module(
        root,
        "check_nonce_producer_backend_readiness.py",
        "check_nonce_producer_backend_readiness_for_attempt",
    )

    request_report = handoff.build_request_artifacts(
        root,
        request_dir,
        generated_at=generated_at,
    )
    request_path = request_dir / "request.json"
    command = substitute_request_placeholder(backend_command, request_path)
    handoff.validate_backend_command_source(root, command)

    readiness_report = readiness.build_report(
        request_path=request_path,
        backend_crate=Path(backend_crate),
        backend_label=backend_label,
        generated_at=generated_at,
    )
    readiness.write_artifacts(readiness_report, readiness_dir)
    readiness_manifest_path = readiness_dir / "manifest.json"
    readiness_manifest = readiness_report["manifest"]
    admissible = readiness_manifest["admissibility"][
        "admissible_for_p1_nonce_handoff"
    ]

    handoff_report = None
    handoff_manifest_path = None
    if admissible:
        handoff_report = handoff.build_handoff(
            root,
            handoff_dir,
            backend_command=command,
            backend_readiness=readiness_manifest_path,
            reuse_request=True,
            generated_at=generated_at,
        )
        handoff_manifest_path = handoff_dir / "manifest.json"

    manifest = attempt_manifest(
        out_dir,
        request_report,
        readiness_manifest,
        readiness_manifest_path,
        backend_command,
        command,
        generated_at,
        handoff_manifest_path=handoff_manifest_path,
    )
    write_attempt_artifacts(out_dir, manifest)
    return {
        "manifest": manifest,
        "request": request_report,
        "readiness": readiness_report,
        "handoff": handoff_report,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Generate the P1 nonce-producer request, preflight a candidate "
            "backend, and run capture only if the candidate is admissible"
        )
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-capture-attempt/latest",
        help="output directory",
    )
    parser.add_argument("--backend-crate", required=True, help="candidate backend crate")
    parser.add_argument(
        "--backend-label",
        help="stable label to record instead of a local absolute backend path",
    )
    parser.add_argument(
        "--backend-command",
        nargs=argparse.REMAINDER,
        required=True,
        help=(
            "external command template that writes canonical capture JSON to "
            "stdout; include {request} where the generated request path belongs"
        ),
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    build_attempt(
        Path(args.root),
        Path(args.out),
        backend_crate=Path(args.backend_crate),
        backend_command=args.backend_command,
        backend_label=args.backend_label,
    )
    print(f"wrote admissible nonce-producer capture attempt artifacts to {args.out}")


if __name__ == "__main__":
    main()
