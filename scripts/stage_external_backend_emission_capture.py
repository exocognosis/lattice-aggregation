#!/usr/bin/env python3
"""Stage a preexisting external real-threshold backend-emission capture file."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
EXTERNAL_BACKEND_EVIDENCE = "real_threshold_mldsa_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
RUNNER_STATUS = "evidence_present_unclosed"
CAPTURE_FILE_ORIGIN_EXTERNAL = "outside_repo_capture_file"
CAPTURE_FILE_ORIGIN_REPO_LOCAL = "repo_local_capture_file"
BACKEND_EXECUTION_MODE = "preexisting_external_capture_file"
CAPTURE_COMMAND = "external-backend-capture-file"
EXTERNAL_CAPTURE_PROVENANCE_SCHEMA = (
    "lattice-aggregation:external-capture-provenance:v1"
)
EXTERNAL_CAPTURE_REVIEW_SCHEMA = (
    "lattice-aggregation:p1-external-backend-emission-capture-review:v1"
)
EXTERNAL_CAPTURE_REVIEW_STATUS = "reviewed_external_backend_emission_capture_ready"
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
    "backend_material_digests_reviewed",
    "mutation_rejection_reviewed",
    "standard_verifier_acceptance_reviewed",
    "centralized_standard_provider_output_disclosed",
    "threshold_core_limitations_reviewed",
    "no_localnet_or_deterministic_simulation",
    "no_fixture_harness",
    "no_undisclosed_single_key_standard_provider_output",
)
OPTIONAL_REVIEW_CHECKS = (
    "real_distributed_threshold_core_verified",
    "no_single_key_standard_provider_output",
)
SMOKE_CORE_MODES = {
    "centralized_mldsa65_provider_with_threshold_evidence_envelope",
}
SMOKE_SIGNATURE_ORIGINS = {
    "single_seed_standard_mldsa65_provider",
}


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
    """Reject repo-local capture files before actual-external staging."""
    capture_file = Path(capture_file)
    if not capture_file.exists():
        raise ValueError("external backend capture file not found")
    origin = capture_file_origin(root, capture_file)
    if origin != CAPTURE_FILE_ORIGIN_EXTERNAL:
        raise ValueError(
            "repo-local capture file cannot be staged as actual external "
            "backend-emission evidence"
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
    """Reject missing or repo-local review manifests before staging."""
    if review_manifest is None:
        raise ValueError("external review manifest is required")
    review_manifest = Path(review_manifest)
    if not review_manifest.exists():
        raise ValueError("external review manifest not found")
    origin = review_file_origin(root, review_manifest)
    if origin != REVIEW_FILE_ORIGIN_EXTERNAL:
        raise ValueError(
            "repo-local external review manifest cannot be staged as actual "
            "external backend-emission evidence"
        )
    return origin


def require_hex_digest(value, field):
    """Validate a lowercase hex SHA-256 digest string."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        or value == "00" * 32
    ):
        raise ValueError(f"external review digest field invalid: {field}")


def validate_external_review_manifest(
    root,
    review_manifest_path,
    request,
    request_sha256,
    capture,
    capture_json,
    capture_file,
):
    """Validate review dossier binding for an outside-repo backend capture."""
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
        "backend_evidence": EXTERNAL_BACKEND_EVIDENCE,
        "request_schema": REQUEST_SCHEMA,
        "request_name": request["name"],
        "request_sha256": request_sha256,
        "capture_sha256": sha256_text(capture_json),
        "capture_file_sha256": sha256_path(capture_file),
    }
    for field, expected in expected_capture.items():
        if capture_binding.get(field) != expected:
            raise ValueError(f"external review capture binding mismatch: {field}")

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
    if checks.get("real_distributed_threshold_core_verified") is not False:
        raise ValueError("external review must not claim verified distributed threshold core")

    returned_checks = {field: checks[field] for field in REQUIRED_REVIEW_CHECKS}
    for field in OPTIONAL_REVIEW_CHECKS:
        if field in checks:
            returned_checks[field] = checks[field]

    return {
        "schema": review["schema"],
        "path": str(review_manifest_path),
        "sha256": sha256_path(review_manifest_path),
        "review_file_origin": origin,
        "review_status": review["review_status"],
        "capture_sha256": expected_capture["capture_sha256"],
        "capture_file_sha256": expected_capture["capture_file_sha256"],
        "review": {field: review_fields[field] for field in REQUIRED_REVIEW_DIGEST_FIELDS},
        "checks": returned_checks,
    }


def backend_core_admissibility(capture, review_report):
    """Classify whether a capture can feed the strict threshold-core slot."""
    core = capture.get("cryptographic_core") if isinstance(capture, dict) else None
    checks = review_report.get("checks") if isinstance(review_report, dict) else None
    reasons = []
    core_mode = None
    signature_origin = None
    distributed_core = None
    if isinstance(core, dict):
        core_mode = core.get("core_mode")
        signature_origin = core.get("signature_origin")
        distributed_core = core.get("distributed_threshold_core")
    else:
        reasons.append("missing cryptographic_core accounting")
    if core_mode in SMOKE_CORE_MODES:
        reasons.append("centralized ML-DSA smoke core mode")
    if signature_origin in SMOKE_SIGNATURE_ORIGINS:
        reasons.append("single-seed standard-provider signature origin")
    if isinstance(checks, dict):
        if checks.get("real_distributed_threshold_core_verified") is not True:
            reasons.append("real distributed threshold core not externally verified")
        if checks.get("no_single_key_standard_provider_output") is not True:
            reasons.append("single-key standard-provider output disclosed")
    if isinstance(distributed_core, dict):
        required_flags = (
            "distributed_keygen_vss",
            "partial_signing_over_secret_shares",
            "partial_z_i_hint_aggregation",
            "fips204_rejection_loop_over_threshold_partials",
        )
        for flag in required_flags:
            if distributed_core.get(flag) is not True:
                reasons.append(f"distributed threshold core flag false: {flag}")
    return {
        "strict_threshold_core_admissible": not reasons,
        "quarantined": bool(reasons),
        "core_mode": core_mode,
        "signature_origin": signature_origin,
        "reasons": reasons,
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
    """Build a capture manifest for a staged external backend capture file."""
    payload = capture["capture"]
    command = [CAPTURE_COMMAND, str(capture_file)]
    manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": RUNNER_STATUS,
        "capture_schema": CAPTURE_SCHEMA,
        "request_schema": REQUEST_SCHEMA,
        "request_name": capture["request"]["name"],
        "request_sha256": request_sha256,
        "request_path": None,
        "backend_evidence": EXTERNAL_BACKEND_EVIDENCE,
        "backend_command": command,
        "backend_execution_mode": BACKEND_EXECUTION_MODE,
        "command_duration_seconds": 0,
        "exit_code": 0,
        "metadata": metadata,
        "validator_count": payload["validator_count"],
        "threshold": payload["threshold"],
        "aggregate_signature_len": payload["aggregate_signature_len"],
        "capture_sha256": sha256_text(capture_json),
        "capture_file_path": str(capture_file),
        "capture_file_sha256": sha256_path(capture_file),
        "capture_file_origin": capture_file_origin_value,
        "external_capture_review": review_report,
    }
    manifest["backend_core_admissibility"] = backend_core_admissibility(
        capture,
        review_report,
    )
    manifest["external_capture_provenance"] = {
        "schema": EXTERNAL_CAPTURE_PROVENANCE_SCHEMA,
        "request_schema": capture["request"]["schema"],
        "request_name": capture["request"]["name"],
        "request_sha256": manifest["request_sha256"],
        "capture_schema": manifest["capture_schema"],
        "capture_sha256": manifest["capture_sha256"],
        "backend_command_sha256": sha256_text(canonical_json(command)),
        "evidence_class": manifest["backend_evidence"],
        "runner_status": RUNNER_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "expected_digest_fields": sorted(capture["expected"]),
        "metadata_fields": sorted(metadata),
        "capture_file_sha256": manifest["capture_file_sha256"],
        "capture_file_origin": capture_file_origin_value,
        "review_manifest_sha256": review_report["sha256"],
        "review_status": review_report["review_status"],
    }
    return manifest


def render_summary(manifest):
    """Render a concise backend-capture file-intake summary."""
    return "\n".join(
        [
            "# Real-Threshold Backend Capture File Intake",
            "",
            "This artifact stages a preexisting external backend-emission "
            "capture file for the Batch 8 real-threshold evidence slot. It is "
            f"{RUNNER_STATUS} conformance/proof-review evidence only.",
            "",
            f"- Status: `{manifest['runner_status']}`",
            f"- Backend execution mode: `{manifest['backend_execution_mode']}`",
            f"- Capture file origin: `{manifest['capture_file_origin']}`",
            f"- Capture SHA-256: `{manifest['capture_sha256']}`",
            f"- External review SHA-256: `{manifest['external_capture_review']['sha256']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            "",
            "This intake does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )


def render_review_summary(report):
    """Render a concise external review summary."""
    return "\n".join(
        [
            "# Real-Threshold Backend Capture Review",
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


def build_intake(
    root,
    request_path,
    capture_file,
    review_manifest_path=None,
    generated_at=None,
    metadata_provider=None,
):
    """Validate and stage an outside-repo external backend-emission capture file."""
    root = Path(root)
    request_path = Path(request_path)
    capture_file = Path(capture_file)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    capture_file_origin_value = require_outside_repo_capture_file(root, capture_file)

    runner = load_script_module(
        "run_backend_emission_capture.py",
        "run_backend_emission_capture_for_file_intake",
    )
    request = runner.load_request(request_path)
    raw_capture_json = capture_file.read_text(encoding="utf-8")
    capture = runner.parse_capture_json(raw_capture_json)
    request_sha256 = runner.validate_capture_matches_request(capture, request)
    capture_json = runner.canonical_json(capture)
    review_report = validate_external_review_manifest(
        root,
        review_manifest_path,
        request,
        request_sha256,
        capture,
        capture_json,
        capture_file,
    )
    metadata_provider = metadata_provider or runner.collect_metadata
    metadata = runner.metadata_from_provider(metadata_provider, root)

    manifest = build_capture_manifest(
        capture,
        request_sha256,
        capture_file,
        capture_file_origin_value,
        capture_json,
        review_report,
        metadata,
        generated_at,
    )
    return {
        "manifest": manifest,
        "capture": capture,
        "capture_json": capture_json,
        "summary_md": render_summary(manifest),
        "review_json": canonical_json(load_json(review_manifest_path)),
        "review_summary_md": render_review_summary(review_report),
        "stdout": "",
        "stderr": "",
    }


def artifact_files(report):
    """Return relative artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "capture.json": report["capture_json"],
        "summary.md": report["summary_md"],
        "review/manifest.json": report["review_json"],
        "review/summary.md": report["review_summary_md"],
        "command.stdout.log": report["stdout"],
        "command.stderr.log": report["stderr"],
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
    """Write staged external backend-emission capture artifacts."""
    out_dir = Path(out_dir)
    files = artifact_files(report)
    for name, content in files.items():
        path = out_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(render_checksums(out_dir), encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Stage a preexisting external real-threshold backend capture file"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--request",
        default="artifacts/backend-emission-request/latest/request.json",
        help="repo-generated backend-emission request JSON",
    )
    parser.add_argument(
        "--capture-file",
        required=True,
        help="external capture JSON file produced outside the repository",
    )
    parser.add_argument(
        "--review-manifest",
        required=True,
        help="external review manifest binding the capture and request evidence",
    )
    parser.add_argument(
        "--out",
        default="artifacts/backend-emission-capture/latest",
        help="output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_intake(
        Path(args.root),
        Path(args.request),
        Path(args.capture_file),
        Path(args.review_manifest),
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote external backend-emission capture artifacts to {args.out}")


if __name__ == "__main__":
    raise SystemExit(main())
