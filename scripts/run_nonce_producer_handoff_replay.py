#!/usr/bin/env python3
"""Build and replay the executable P1 nonce-producer handoff artifacts."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


HANDOFF_SCHEMA = "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
EXTERNAL_PRODUCER_EVIDENCE = "p1_shamir_nonce_dkg_tee_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
HANDOFF_STATUS = "evidence_present_unclosed"
ADMISSIBLE_READINESS_STATUS = "backend_candidate_admissible_pending_capture"
BRIDGE_PATH = "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
COMPATIBILITY_PATH = (
    "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
)
REQUEST_NAME = "p1-reviewed-nonce-producer-request-001"


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


def current_predecessor_digests(root):
    """Return current predecessor digests for the P1 request."""
    root = Path(root)
    bridge = load_json(root / BRIDGE_PATH)
    compatibility = load_json(root / COMPATIBILITY_PATH)
    return {
        "selected_profile_binding_digest_hex": bridge["expected"][
            "selected_profile_binding_digest_hex"
        ],
        "threshold_output_certificate_digest_hex": compatibility["expected"][
            "threshold_output_certificate_digest_hex"
        ],
        "standard_verifier_compatibility_artifact_digest_hex": compatibility[
            "expected"
        ]["artifact_digest_hex"],
    }


def build_request_artifacts(root, out_dir, generated_at=None):
    """Generate repo-bound nonce-producer request artifacts."""
    builder = load_script_module(
        root,
        "build_nonce_producer_request.py",
        "build_nonce_producer_request",
    )
    predecessors = current_predecessor_digests(root)
    report = builder.build_request(
        name=REQUEST_NAME,
        selected_profile_binding_digest_hex=predecessors[
            "selected_profile_binding_digest_hex"
        ],
        threshold_output_certificate_digest_hex=predecessors[
            "threshold_output_certificate_digest_hex"
        ],
        standard_verifier_compatibility_artifact_digest_hex=predecessors[
            "standard_verifier_compatibility_artifact_digest_hex"
        ],
        generated_at=generated_at,
    )
    builder.write_artifacts(report, out_dir)
    return report


def load_request_artifacts(out_dir):
    """Load an already-generated nonce-producer request artifact set."""
    out_dir = Path(out_dir)
    request_path = out_dir / "request.json"
    manifest_path = out_dir / "manifest.json"
    request = load_json(request_path)
    manifest = load_json(manifest_path)
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer handoff reuse request schema mismatch")
    if manifest.get("request_schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer handoff reuse request manifest schema mismatch")
    if manifest.get("request_sha256") != sha256_text(canonical_json(request)):
        raise ValueError("nonce-producer handoff reuse request digest mismatch")
    return {
        "request": request,
        "request_json": canonical_json(request),
        "manifest": manifest,
        "summary_md": (out_dir / "summary.md").read_text(encoding="utf-8")
        if (out_dir / "summary.md").is_file()
        else "",
    }


def default_backend_command(request_path):
    """Return the checked replay emitter command used by CI."""
    return [
        "python3",
        "scripts/emit_reviewed_nonce_producer_capture.py",
        "--request",
        str(request_path),
    ]


def build_capture_artifacts(root, request_path, out_dir, backend_command=None, generated_at=None):
    """Run the capture runner against the configured backend command."""
    runner = load_script_module(
        root,
        "run_nonce_producer_capture.py",
        "run_nonce_producer_capture",
    )
    command = list(backend_command) if backend_command else default_backend_command(request_path)
    report = runner.build_report(
        Path(root),
        command,
        request_path=request_path,
        generated_at=generated_at,
    )
    runner.write_artifacts(report, out_dir)
    return report


def validate_backend_command_source(root, backend_command):
    """Fail early for explicit backend commands that are known scaffold sources."""
    if not backend_command:
        return
    runner = load_script_module(
        root,
        "run_nonce_producer_capture.py",
        "run_nonce_producer_capture_for_command_validation",
    )
    runner.validate_backend_command(list(backend_command))


def validate_backend_readiness(readiness_path, request_report):
    """Validate an admissible backend-readiness manifest for the request."""
    if not readiness_path:
        raise ValueError(
            "explicit nonce-producer backend command requires admissible backend readiness"
        )
    readiness_path = Path(readiness_path)
    readiness = load_json(readiness_path)
    if readiness.get("schema") != READINESS_SCHEMA:
        raise ValueError("backend readiness schema mismatch")
    if readiness.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("backend readiness claim boundary mismatch")
    if readiness.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("backend readiness selected profile mismatch")

    request = readiness.get("request")
    if not isinstance(request, dict):
        raise ValueError("backend readiness requires request binding")
    admissibility = readiness.get("admissibility")
    if not isinstance(admissibility, dict):
        raise ValueError("backend readiness requires admissibility result")
    blockers = admissibility.get("detected_blockers")
    if not isinstance(blockers, list):
        raise ValueError("backend readiness requires detected blockers list")
    if (
        readiness.get("readiness_status") != ADMISSIBLE_READINESS_STATUS
        or admissibility.get("admissible_for_p1_nonce_handoff") is not True
        or blockers
    ):
        raise ValueError("backend readiness is not admissible")

    request_sha256 = request_report["manifest"]["request_sha256"]
    if (
        request.get("schema") != REQUEST_SCHEMA
        or request.get("name") != request_report["request"]["name"]
        or request.get("request_sha256") != request_sha256
        or request.get("capture_schema") != CAPTURE_SCHEMA
        or request.get("required_producer_evidence") != EXTERNAL_PRODUCER_EVIDENCE
    ):
        raise ValueError("backend readiness request binding mismatch")

    backend = readiness.get("backend")
    if not isinstance(backend, dict):
        raise ValueError("backend readiness requires backend metadata")
    source_tree_sha256 = backend.get("source_tree_sha256")
    if not isinstance(source_tree_sha256, str) or len(source_tree_sha256) != 64:
        raise ValueError("backend readiness requires source tree digest")
    return {
        "schema": readiness["schema"],
        "path": str(readiness_path),
        "sha256": sha256_path(readiness_path),
        "readiness_status": readiness["readiness_status"],
        "package_name": backend.get("package_name", "unknown"),
        "source_tree_sha256": source_tree_sha256,
        "request_sha256": request_sha256,
    }


def render_summary(manifest):
    """Render a concise handoff replay summary."""
    lines = [
        "# Executable P1 Nonce-Producer Handoff Replay",
        "",
        "This artifact builds the current repo request and replays the "
        "capture/import handoff through the external-command runner. It is "
        f"{HANDOFF_STATUS} conformance/proof-review evidence only.",
        "",
        f"- Request schema: `{manifest['request_schema']}`",
        f"- Capture schema: `{manifest['capture_schema']}`",
        f"- Request: `{manifest['request_name']}`",
        f"- Request SHA-256: `{manifest['request_sha256']}`",
        f"- Capture SHA-256: `{manifest['capture_sha256']}`",
        f"- Producer evidence: `{manifest['producer_evidence']}`",
    ]
    if manifest.get("backend_readiness"):
        lines.extend(
            [
                f"- Backend readiness: `{manifest['backend_readiness']['readiness_status']}`",
                f"- Backend package: `{manifest['backend_readiness']['package_name']}`",
            ]
        )
    lines.extend(
        [
            "",
            "This replay does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )
    return "\n".join(lines)


def build_manifest(
    root,
    out_dir,
    request_report,
    capture_report,
    generated_at,
    backend_readiness_report=None,
):
    """Build the top-level handoff manifest."""
    out_dir = Path(out_dir)
    capture_manifest_path = out_dir / "capture" / "manifest.json"
    request_manifest_path = out_dir / "request" / "manifest.json"
    capture_manifest = load_json(capture_manifest_path)
    request_manifest = load_json(request_manifest_path)
    return {
        "schema": HANDOFF_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "handoff_status": HANDOFF_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "request_schema": REQUEST_SCHEMA,
        "capture_schema": CAPTURE_SCHEMA,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "request_name": request_report["request"]["name"],
        "request_sha256": request_manifest["request_sha256"],
        "request_manifest_sha256": sha256_path(request_manifest_path),
        "capture_sha256": capture_manifest["capture_sha256"],
        "capture_manifest_sha256": sha256_path(capture_manifest_path),
        "backend_command": capture_manifest["backend_command"],
        "backend_readiness": backend_readiness_report,
        "predecessors": request_report["request"]["predecessors"],
        "request_dir": "request",
        "capture_dir": "capture",
        "request_artifacts": sorted(request_report["request"].keys()),
        "capture_artifacts": sorted(capture_report["capture"].keys()),
        "external_capture_provenance": capture_manifest[
            "external_capture_provenance"
        ],
        "closure_boundary": (
            "Executable handoff replay only; a real external threshold backend "
            "capture and proof review remain required."
        ),
    }


def render_checksums(out_dir):
    """Render checksums for all generated handoff files."""
    out_dir = Path(out_dir)
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    return "\n".join(lines) + "\n"


def write_top_level_artifacts(out_dir, manifest):
    """Write top-level manifest, summary, and checksums."""
    out_dir = Path(out_dir)
    (out_dir / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    (out_dir / "summary.md").write_text(render_summary(manifest), encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(render_checksums(out_dir), encoding="utf-8")


def build_handoff(
    root,
    out_dir,
    backend_command=None,
    backend_readiness=None,
    reuse_request=False,
    generated_at=None,
):
    """Generate request, run capture command, and write replay artifacts."""
    root = Path(root)
    out_dir = Path(out_dir)
    request_dir = out_dir / "request"
    capture_dir = out_dir / "capture"
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    request_report = (
        load_request_artifacts(request_dir)
        if reuse_request
        else build_request_artifacts(root, request_dir, generated_at=generated_at)
    )
    backend_readiness_report = None
    if backend_command:
        validate_backend_command_source(root, backend_command)
        backend_readiness_report = validate_backend_readiness(
            backend_readiness,
            request_report,
        )
    capture_report = build_capture_artifacts(
        root,
        request_dir / "request.json",
        capture_dir,
        backend_command=backend_command,
        generated_at=generated_at,
    )
    manifest = build_manifest(
        root,
        out_dir,
        request_report,
        capture_report,
        generated_at,
        backend_readiness_report=backend_readiness_report,
    )
    write_top_level_artifacts(out_dir, manifest)
    return {
        "manifest": manifest,
        "request": request_report,
        "capture": capture_report,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Replay the P1 distributed nonce-producer executable handoff"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-handoff/latest",
        help="output directory",
    )
    parser.add_argument(
        "--backend-command",
        nargs=argparse.REMAINDER,
        help=(
            "backend command that writes canonical capture JSON to stdout; "
            "omit to use the checked replay emitter"
        ),
    )
    parser.add_argument(
        "--backend-readiness",
        help=(
            "admissible backend-readiness manifest required for an explicit "
            "backend command"
        ),
    )
    parser.add_argument(
        "--reuse-request",
        action="store_true",
        help="reuse the existing request artifacts under --out/request",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    build_handoff(
        Path(args.root),
        Path(args.out),
        backend_command=args.backend_command,
        backend_readiness=args.backend_readiness,
        reuse_request=args.reuse_request,
    )
    print(f"wrote nonce-producer handoff replay artifacts to {args.out}")


if __name__ == "__main__":
    main()
