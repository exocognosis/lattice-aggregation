#!/usr/bin/env python3
"""Stage a preexisting external P1 nonce-producer capture file for gating."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


ATTEMPT_SCHEMA = "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
HANDOFF_SCHEMA = "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1"
READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
EXTERNAL_PRODUCER_EVIDENCE = "p1_shamir_nonce_dkg_tee_external_capture"
ATTEMPT_STATUS_PROMOTED = "capture_promoted"
HANDOFF_STATUS = "evidence_present_unclosed"
CAPTURE_SOURCE_PROFILE_EXTERNAL = "admissible_external_backend_capture"
CAPTURE_FILE_ORIGIN_EXTERNAL = "outside_repo_capture_file"
CAPTURE_FILE_ORIGIN_REPO_LOCAL = "repo_local_capture_file"
BACKEND_EXECUTION_MODE = "preexisting_external_capture_file"
CAPTURE_COMMAND = "external-capture-file"
EXTERNAL_CAPTURE_PROVENANCE_SCHEMA = (
    "lattice-aggregation:external-capture-provenance:v1"
)
EXTERNAL_CAPTURE_REVIEW_SCHEMA = (
    "lattice-aggregation:p1-external-nonce-producer-capture-review:v1"
)
EXTERNAL_CAPTURE_REVIEW_STATUS = "reviewed_external_capture_ready"
REVIEW_FILE_ORIGIN_EXTERNAL = "outside_repo_review_manifest"
REVIEW_FILE_ORIGIN_REPO_LOCAL = "repo_local_review_manifest"
REQUIRED_REVIEW_DIGEST_FIELDS = (
    "external_review_digest_hex",
    "reviewer_identity_digest_hex",
    "operator_identity_digest_hex",
    "capture_environment_digest_hex",
    "backend_command_digest_hex",
)
REQUIRED_REVIEW_CHECKS = (
    "external_backend_operated_outside_repo",
    "capture_generated_outside_repo",
    "request_binding_reviewed",
    "predecessor_digests_reviewed",
    "material_digests_reviewed",
    "readiness_source_tree_reviewed",
    "no_hazmat_prf_oracle",
    "no_centralized_expanded_secret_key_helper",
    "no_fixture_harness",
    "no_localnet_or_deterministic_simulation",
    "no_single_key_standard_provider_output",
)


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return SHA-256 for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    """Return SHA-256 for a file path."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_json(path):
    """Load JSON from a path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_script_module(script_name, module_name):
    """Load a sibling repo script as a Python module."""
    script = Path(__file__).resolve().parent / script_name
    spec = importlib.util.spec_from_file_location(module_name, script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_path(path):
    """Resolve a path for origin comparison."""
    return Path(path).expanduser().resolve(strict=False)


def path_is_within(child, parent):
    """Return true when child resolves inside parent."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def capture_file_origin(root, capture_file):
    """Classify whether the capture file lives outside the repository."""
    repo_root = resolve_path(root)
    capture_path = resolve_path(capture_file)
    if path_is_within(capture_path, repo_root):
        return CAPTURE_FILE_ORIGIN_REPO_LOCAL
    return CAPTURE_FILE_ORIGIN_EXTERNAL


def require_outside_repo_capture_file(root, capture_file):
    """Reject repo-local capture files before actual-external promotion."""
    origin = capture_file_origin(root, capture_file)
    if origin != CAPTURE_FILE_ORIGIN_EXTERNAL:
        raise ValueError(
            "repo-local capture file cannot be staged as "
            f"{CAPTURE_SOURCE_PROFILE_EXTERNAL}"
        )
    return origin


def review_file_origin(root, review_manifest):
    """Classify whether the review manifest lives outside the repository."""
    repo_root = resolve_path(root)
    review_path = resolve_path(review_manifest)
    if path_is_within(review_path, repo_root):
        return REVIEW_FILE_ORIGIN_REPO_LOCAL
    return REVIEW_FILE_ORIGIN_EXTERNAL


def require_outside_repo_review_manifest(root, review_manifest):
    """Reject missing or repo-local review manifests before promotion."""
    if review_manifest is None:
        raise ValueError("external review manifest is required")
    review_manifest = Path(review_manifest)
    if not review_manifest.exists():
        raise ValueError("external review manifest not found")
    origin = review_file_origin(root, review_manifest)
    if origin != REVIEW_FILE_ORIGIN_EXTERNAL:
        raise ValueError(
            "repo-local external review manifest cannot be staged as "
            f"{CAPTURE_SOURCE_PROFILE_EXTERNAL}"
        )
    return origin


def require_hex_digest(value, field):
    """Validate a lowercase hex SHA-256 digest string."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"external review digest field invalid: {field}")


def validate_readiness(readiness_path, request, request_sha256):
    """Validate an admissible readiness manifest bound to the request."""
    readiness = load_json(readiness_path)
    if readiness.get("schema") != READINESS_SCHEMA:
        raise ValueError("backend readiness schema mismatch")
    if readiness.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("backend readiness claim boundary mismatch")
    if readiness.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("backend readiness selected profile mismatch")

    request_binding = readiness.get("request")
    if not isinstance(request_binding, dict):
        raise ValueError("backend readiness requires request binding")
    if (
        request_binding.get("schema") != REQUEST_SCHEMA
        or request_binding.get("name") != request["name"]
        or request_binding.get("request_sha256") != request_sha256
        or request_binding.get("capture_schema") != CAPTURE_SCHEMA
        or request_binding.get("required_producer_evidence")
        != EXTERNAL_PRODUCER_EVIDENCE
    ):
        raise ValueError("backend readiness request binding mismatch")

    admissibility = readiness.get("admissibility")
    if not isinstance(admissibility, dict):
        raise ValueError("backend readiness requires admissibility result")
    blockers = admissibility.get("detected_blockers")
    if not isinstance(blockers, list):
        raise ValueError("backend readiness requires detected blockers list")
    if (
        readiness.get("readiness_status")
        != "backend_candidate_admissible_pending_capture"
        or admissibility.get("admissible_for_p1_nonce_handoff") is not True
        or blockers
    ):
        raise ValueError("backend readiness is not admissible")

    backend = readiness.get("backend")
    if not isinstance(backend, dict):
        raise ValueError("backend readiness requires backend metadata")
    source_tree_sha256 = backend.get("source_tree_sha256")
    if not isinstance(source_tree_sha256, str) or len(source_tree_sha256) != 64:
        raise ValueError("backend readiness requires source tree digest")
    return readiness


def validate_external_review_manifest(
    root,
    review_manifest_path,
    request,
    request_sha256,
    readiness,
    readiness_path,
    capture,
    capture_json,
    capture_file,
):
    """Validate review dossier binding for an outside-repo capture file."""
    origin = require_outside_repo_review_manifest(root, review_manifest_path)
    review_manifest_path = Path(review_manifest_path)
    review = load_json(review_manifest_path)
    if review.get("schema") != EXTERNAL_CAPTURE_REVIEW_SCHEMA:
        raise ValueError("external review manifest schema mismatch")
    if review.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("external review manifest claim boundary mismatch")
    if review.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("external review manifest selected profile mismatch")
    if review.get("review_status") != EXTERNAL_CAPTURE_REVIEW_STATUS:
        raise ValueError("external review manifest is not ready")

    capture_binding = review.get("capture")
    if not isinstance(capture_binding, dict):
        raise ValueError("external review manifest requires capture binding")
    expected_capture = {
        "schema": CAPTURE_SCHEMA,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "request_schema": REQUEST_SCHEMA,
        "request_name": request["name"],
        "request_sha256": request_sha256,
        "capture_sha256": sha256_text(capture_json),
        "capture_file_sha256": sha256_path(capture_file),
    }
    for field, expected in expected_capture.items():
        if capture_binding.get(field) != expected:
            raise ValueError(f"external review capture binding mismatch: {field}")

    readiness_binding = review.get("readiness")
    if not isinstance(readiness_binding, dict):
        raise ValueError("external review manifest requires readiness binding")
    expected_readiness = {
        "schema": READINESS_SCHEMA,
        "readiness_status": readiness["readiness_status"],
        "manifest_sha256": sha256_path(readiness_path),
        "source_tree_sha256": readiness["backend"]["source_tree_sha256"],
    }
    for field, expected in expected_readiness.items():
        if readiness_binding.get(field) != expected:
            raise ValueError(f"external review readiness binding mismatch: {field}")

    review_fields = review.get("review")
    if not isinstance(review_fields, dict):
        raise ValueError("external review manifest requires review digests")
    for field in REQUIRED_REVIEW_DIGEST_FIELDS:
        require_hex_digest(review_fields.get(field), field)

    checks = review.get("checks")
    if not isinstance(checks, dict):
        raise ValueError("external review manifest requires checks")
    for field in REQUIRED_REVIEW_CHECKS:
        if checks.get(field) is not True:
            raise ValueError(f"external review check failed: {field}")

    return {
        "schema": review["schema"],
        "path": str(review_manifest_path),
        "sha256": sha256_path(review_manifest_path),
        "review_file_origin": origin,
        "review_status": review["review_status"],
        "capture_sha256": expected_capture["capture_sha256"],
        "capture_file_sha256": expected_capture["capture_file_sha256"],
        "readiness_manifest_sha256": expected_readiness["manifest_sha256"],
        "readiness_source_tree_sha256": expected_readiness["source_tree_sha256"],
        "review": {field: review_fields[field] for field in REQUIRED_REVIEW_DIGEST_FIELDS},
        "checks": {field: checks[field] for field in REQUIRED_REVIEW_CHECKS},
    }


def readiness_summary(readiness_path, readiness, request_sha256):
    """Return readiness metadata for handoff and attempt manifests."""
    backend = readiness["backend"]
    return {
        "schema": readiness["schema"],
        "path": str(readiness_path),
        "sha256": sha256_path(readiness_path),
        "readiness_status": readiness["readiness_status"],
        "package_name": backend.get("package_name", "unknown"),
        "source_tree_sha256": backend["source_tree_sha256"],
        "request_sha256": request_sha256,
    }


def build_capture_manifest(
    capture,
    request_sha256,
    capture_file,
    capture_file_origin_value,
    capture_json,
    review_report,
    metadata,
    generated_at,
):
    """Build a capture manifest for a staged external capture file."""
    command = [CAPTURE_COMMAND, str(capture_file)]
    manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": HANDOFF_STATUS,
        "capture_schema": CAPTURE_SCHEMA,
        "request_schema": REQUEST_SCHEMA,
        "request_name": capture["request"]["name"],
        "request_sha256": request_sha256,
        "request_path": None,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "capture_source_profile": CAPTURE_SOURCE_PROFILE_EXTERNAL,
        "capture_file_path": str(capture_file),
        "capture_file_sha256": sha256_path(capture_file),
        "capture_file_origin": capture_file_origin_value,
        "backend_command": command,
        "backend_execution_mode": BACKEND_EXECUTION_MODE,
        "command_duration_seconds": 0,
        "exit_code": 0,
        "quarantine": {
            "quarantined": False,
            "reason": None,
            "allowed_use": "preexisting external backend capture file gated by admissible readiness",
        },
        "metadata": metadata,
        "capture_sha256": sha256_text(capture_json),
        "external_capture_review": review_report,
    }
    manifest["external_capture_provenance"] = {
        "schema": EXTERNAL_CAPTURE_PROVENANCE_SCHEMA,
        "request_schema": capture["request"]["schema"],
        "request_name": capture["request"]["name"],
        "request_sha256": manifest["request_sha256"],
        "capture_schema": manifest["capture_schema"],
        "capture_sha256": manifest["capture_sha256"],
        "backend_command_sha256": sha256_text(canonical_json(command)),
        "evidence_class": manifest["producer_evidence"],
        "runner_status": HANDOFF_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "expected_digest_fields": sorted(capture["expected"]),
        "metadata_fields": sorted(metadata),
        "capture_file_sha256": manifest["capture_file_sha256"],
        "capture_file_origin": capture_file_origin_value,
        "review_manifest_sha256": review_report["sha256"],
        "review_status": review_report["review_status"],
    }
    return manifest


def build_handoff_manifest(
    request,
    request_sha256,
    capture_manifest,
    readiness_report,
    review_report,
    generated_at,
):
    """Build the handoff manifest consumed by the actual-external gate."""
    return {
        "schema": HANDOFF_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "handoff_status": HANDOFF_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "handoff_source_profile": CAPTURE_SOURCE_PROFILE_EXTERNAL,
        "quarantine": {
            "quarantined": False,
            "reason": None,
            "allowed_use": "preexisting external backend capture file gated by admissible readiness",
        },
        "request_schema": REQUEST_SCHEMA,
        "capture_schema": CAPTURE_SCHEMA,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "request_name": request["name"],
        "request_sha256": request_sha256,
        "capture_sha256": capture_manifest["capture_sha256"],
        "capture_manifest_sha256": sha256_text(canonical_json(capture_manifest)),
        "backend_command": capture_manifest["backend_command"],
        "backend_execution_mode": BACKEND_EXECUTION_MODE,
        "backend_readiness": readiness_report,
        "external_capture_review": review_report,
        "predecessors": request["predecessors"],
        "request_dir": "request",
        "capture_dir": "capture",
        "external_capture_provenance": capture_manifest[
            "external_capture_provenance"
        ],
        "closure_boundary": (
            "External capture-file intake only; proof review, "
            "rejection-distribution preservation, and theorem closure remain open."
        ),
    }


def build_attempt_manifest(
    request,
    request_sha256,
    readiness,
    readiness_path,
    readiness_report,
    capture_file,
    capture_manifest,
    review_report,
    generated_at,
):
    """Build the attempt manifest consumed by verify_actual_nonce_producer_capture."""
    return {
        "schema": ATTEMPT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "attempt_status": ATTEMPT_STATUS_PROMOTED,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "request_schema": REQUEST_SCHEMA,
        "request_name": request["name"],
        "request_path": "request/request.json",
        "request_sha256": request_sha256,
        "readiness_schema": READINESS_SCHEMA,
        "readiness_status": readiness["readiness_status"],
        "readiness_manifest_path": "readiness/manifest.json",
        "readiness_manifest_sha256": sha256_path(readiness_path),
        "admissible_for_p1_nonce_handoff": True,
        "detected_blockers": [],
        "backend_package_name": readiness_report["package_name"],
        "backend_source_tree_sha256": readiness_report["source_tree_sha256"],
        "backend_command_template": [CAPTURE_COMMAND, "{capture_file}"],
        "backend_command": [CAPTURE_COMMAND, str(capture_file)],
        "backend_command_executed": True,
        "backend_execution_mode": BACKEND_EXECUTION_MODE,
        "capture_file_path": str(capture_file),
        "capture_file_sha256": capture_manifest["capture_file_sha256"],
        "external_review_manifest_path": "review/manifest.json",
        "external_review_manifest_sha256": review_report["sha256"],
        "external_capture_review": review_report,
        "capture_failure": None,
        "handoff_manifest_path": "handoff/manifest.json",
        "handoff_manifest_sha256": None,
        "handoff_source_profile": CAPTURE_SOURCE_PROFILE_EXTERNAL,
        "handoff_quarantine": {
            "quarantined": False,
            "reason": None,
            "allowed_use": "preexisting external backend capture file gated by admissible readiness",
        },
        "closure_boundary": (
            "External capture-file intake only; actual theorem closure still "
            "requires rejection-distribution proof and reviewed theorem linkage."
        ),
    }


def render_summary(attempt_manifest):
    """Render a concise intake summary."""
    return "\n".join(
        [
            "# P1 External Nonce-Producer Capture File Intake",
            "",
            "This artifact stages a preexisting external nonce-producer capture "
            "file for the actual-external handoff gate. It is "
            "conformance/proof-review evidence only.",
            "",
            f"- Status: `{attempt_manifest['attempt_status']}`",
            f"- Backend execution mode: `{attempt_manifest['backend_execution_mode']}`",
            f"- Handoff source profile: `{attempt_manifest['handoff_source_profile']}`",
            f"- Capture file SHA-256: `{attempt_manifest['capture_file_sha256']}`",
            f"- External review SHA-256: `{attempt_manifest['external_review_manifest_sha256']}`",
            "",
            "This intake does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )


def build_intake(
    root,
    request_path,
    readiness_path,
    capture_file,
    review_manifest_path=None,
    generated_at=None,
    metadata_provider=None,
):
    """Validate and stage an outside-repo external nonce-producer capture file."""
    root = Path(root)
    request_path = Path(request_path)
    readiness_path = Path(readiness_path)
    capture_file = Path(capture_file)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    capture_file_origin_value = require_outside_repo_capture_file(root, capture_file)

    runner = load_script_module(
        "run_nonce_producer_capture.py",
        "run_nonce_producer_capture_for_file_intake",
    )
    request = runner.load_request(request_path)
    request_sha256 = sha256_text(canonical_json(request))
    readiness = validate_readiness(readiness_path, request, request_sha256)
    raw_capture_json = capture_file.read_text(encoding="utf-8")
    capture = runner.parse_capture_json(raw_capture_json)
    request_sha256 = runner.validate_capture_matches_request(capture, request)
    capture_json = canonical_json(capture)
    review_report = validate_external_review_manifest(
        root,
        review_manifest_path,
        request,
        request_sha256,
        readiness,
        readiness_path,
        capture,
        capture_json,
        capture_file,
    )
    metadata_provider = metadata_provider or runner.collect_metadata
    metadata = runner.metadata_from_provider(metadata_provider, root)
    readiness_report = readiness_summary(readiness_path, readiness, request_sha256)

    capture_manifest = build_capture_manifest(
        capture,
        request_sha256,
        capture_file,
        capture_file_origin_value,
        capture_json,
        review_report,
        metadata,
        generated_at,
    )
    handoff_manifest = build_handoff_manifest(
        request,
        request_sha256,
        capture_manifest,
        readiness_report,
        review_report,
        generated_at,
    )
    attempt_manifest = build_attempt_manifest(
        request,
        request_sha256,
        readiness,
        readiness_path,
        readiness_report,
        capture_file,
        capture_manifest,
        review_report,
        generated_at,
    )
    return {
        "manifest": attempt_manifest,
        "summary_md": render_summary(attempt_manifest),
        "request_json": canonical_json(request),
        "readiness_json": canonical_json(readiness),
        "capture_json": capture_json,
        "capture_manifest": capture_manifest,
        "capture_summary_md": render_capture_summary(capture_manifest),
        "review_json": canonical_json(load_json(review_manifest_path)),
        "review_summary_md": render_review_summary(review_report),
        "handoff_manifest": handoff_manifest,
        "handoff_summary_md": render_handoff_summary(handoff_manifest),
    }


def render_capture_summary(manifest):
    """Render a concise capture-file summary."""
    return "\n".join(
        [
            "# P1 External Nonce-Producer Capture File",
            "",
            f"- Capture source profile: `{manifest['capture_source_profile']}`",
            f"- Capture file origin: `{manifest['capture_file_origin']}`",
            f"- Capture SHA-256: `{manifest['capture_sha256']}`",
            f"- External review SHA-256: `{manifest['external_capture_review']['sha256']}`",
            "",
            "This capture file remains conformance/proof-review evidence only.",
            "",
        ]
    )


def render_review_summary(report):
    """Render a concise external review summary."""
    return "\n".join(
        [
            "# P1 External Nonce-Producer Capture Review",
            "",
            f"- Review status: `{report['review_status']}`",
            f"- Review file origin: `{report['review_file_origin']}`",
            f"- Review SHA-256: `{report['sha256']}`",
            f"- Capture SHA-256: `{report['capture_sha256']}`",
            "",
            "This review dossier remains conformance/proof-review evidence only.",
            "",
        ]
    )


def render_handoff_summary(manifest):
    """Render a concise handoff summary."""
    return "\n".join(
        [
            "# P1 External Nonce-Producer Capture File Handoff",
            "",
            f"- Handoff source profile: `{manifest['handoff_source_profile']}`",
            f"- Backend execution mode: `{manifest['backend_execution_mode']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            f"- Capture SHA-256: `{manifest['capture_sha256']}`",
            "",
            "This handoff does not prove Criterion 2 or theorem closure.",
            "",
        ]
    )


def artifact_files(report):
    """Return relative artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
        "request/request.json": report["request_json"],
        "readiness/manifest.json": report["readiness_json"],
        "review/manifest.json": report["review_json"],
        "review/summary.md": report["review_summary_md"],
        "handoff/manifest.json": canonical_json(report["handoff_manifest"]),
        "handoff/summary.md": report["handoff_summary_md"],
        "handoff/capture/capture.json": report["capture_json"],
        "handoff/capture/manifest.json": canonical_json(report["capture_manifest"]),
        "handoff/capture/summary.md": report["capture_summary_md"],
    }


def render_checksums(out_dir):
    """Render checksums for all generated intake files."""
    out_dir = Path(out_dir)
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    return "\n".join(lines) + "\n"


def write_artifacts(report, out_dir):
    """Write staged external capture intake artifacts."""
    out_dir = Path(out_dir)
    files = artifact_files(report)
    for name, content in files.items():
        path = out_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    handoff_path = out_dir / "handoff" / "manifest.json"
    manifest = dict(report["manifest"])
    manifest["handoff_manifest_sha256"] = sha256_path(handoff_path)
    (out_dir / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    (out_dir / "summary.md").write_text(render_summary(manifest), encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(render_checksums(out_dir), encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Stage a preexisting external P1 nonce-producer capture file"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--request",
        default="artifacts/nonce-producer-handoff/latest/request/request.json",
        help="repo-generated nonce-producer request JSON",
    )
    parser.add_argument(
        "--readiness",
        default="artifacts/nonce-producer-backend-readiness/latest/manifest.json",
        help="admissible backend-readiness manifest",
    )
    parser.add_argument(
        "--capture-file",
        required=True,
        help="external capture JSON file produced outside the repository",
    )
    parser.add_argument(
        "--review-manifest",
        required=True,
        help="external review manifest binding the capture, request, and readiness evidence",
    )
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-external-capture-intake/latest",
        help="output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_intake(
        Path(args.root),
        Path(args.request),
        Path(args.readiness),
        Path(args.capture_file),
        Path(args.review_manifest),
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote external nonce-producer capture intake artifacts to {args.out}")


if __name__ == "__main__":
    raise SystemExit(main())
