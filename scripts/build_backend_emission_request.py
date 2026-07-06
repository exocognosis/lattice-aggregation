#!/usr/bin/env python3
"""Build a P1 external backend emission request manifest."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
EXTERNAL_BACKEND_EVIDENCE = "real_threshold_mldsa_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
REQUEST_STATUS = "evidence_present_unclosed"
VALIDATOR_COUNT = 10_000
THRESHOLD = 6_667
MLDSA65_SIGNATURE_BYTES = 3309
FORBIDDEN_REQUEST_NAME_TOKENS = (
    "localnet",
    "validator_localnet",
    "run_simulation_benchmarks",
    "deterministic",
    "simulation",
    "simulated",
    "fixture",
)


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def validate_name(name):
    """Validate the request name cannot masquerade as simulation evidence."""
    if not name or not name.strip():
        raise ValueError("backend emission request name is required")
    lowered = name.lower()
    for token in FORBIDDEN_REQUEST_NAME_TOKENS:
        if token in lowered:
            raise ValueError(
                "forbidden request name for actual real-threshold capture: " + token
            )
    return name.strip()


def validate_digest(value, field):
    """Validate a nonzero 32-byte hex digest."""
    validate_hex(value, 32, field)
    if value.lower() == "00" * 32:
        raise ValueError(f"backend emission request rejects all-zero {field}")
    return value.lower()


def validate_hex(value, expected_bytes, field):
    """Validate fixed-length hex."""
    if not isinstance(value, str):
        raise ValueError(f"backend emission request requires hex string for {field}")
    if len(value) != expected_bytes * 2:
        raise ValueError(f"backend emission request invalid {field} length")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"backend emission request invalid {field} hex") from exc


def validate_message_hex(value):
    """Validate application message hex for the external backend request."""
    if not isinstance(value, str) or len(value) == 0 or len(value) % 2 != 0:
        raise ValueError("backend emission request invalid message_hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("backend emission request invalid message_hex") from exc
    return value.lower()


def build_request(
    name,
    message_hex,
    selected_profile_binding_digest_hex,
    threshold_output_certificate_digest_hex,
    standard_verifier_compatibility_artifact_digest_hex,
    generated_at=None,
):
    """Build an in-memory request manifest for an external P1 threshold backend."""
    request = {
        "schema": REQUEST_SCHEMA,
        "name": validate_name(name),
        "generated_at": generated_at
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "claim_boundary": CLAIM_BOUNDARY,
        "request_status": REQUEST_STATUS,
        "selected_profile": SELECTED_PROFILE,
        "validator_count": VALIDATOR_COUNT,
        "threshold": THRESHOLD,
        "aggregate_signature_len": MLDSA65_SIGNATURE_BYTES,
        "message": {
            "encoding": "hex",
            "value": validate_message_hex(message_hex),
        },
        "predecessors": {
            "selected_profile_binding_digest_hex": validate_digest(
                selected_profile_binding_digest_hex,
                "selected_profile_binding_digest_hex",
            ),
            "threshold_output_certificate_digest_hex": validate_digest(
                threshold_output_certificate_digest_hex,
                "threshold_output_certificate_digest_hex",
            ),
            "standard_verifier_compatibility_artifact_digest_hex": validate_digest(
                standard_verifier_compatibility_artifact_digest_hex,
                "standard_verifier_compatibility_artifact_digest_hex",
            ),
        },
        "required_capture": {
            "schema": CAPTURE_SCHEMA,
            "backend_evidence": EXTERNAL_BACKEND_EVIDENCE,
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "aggregate_signature_len": MLDSA65_SIGNATURE_BYTES,
            "mutated_message_rejected": True,
            "mutated_public_key_rejected": True,
            "mutated_signature_rejected": True,
            "reviewed": True,
        },
        "forbidden_capture_sources": [
            "localnet",
            "deterministic simulation",
            "fixture harness",
            "ordinary single-key standard-provider output",
        ],
    }
    request_json = canonical_json(request)
    manifest = {
        "schema_version": 1,
        "request_schema": REQUEST_SCHEMA,
        "capture_schema": CAPTURE_SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "request_status": REQUEST_STATUS,
        "request_sha256": sha256_text(request_json),
    }
    return {
        "request": request,
        "request_json": request_json,
        "manifest": manifest,
        "summary_md": render_summary(request, manifest),
    }


def render_summary(request, manifest):
    """Render a concise request summary."""
    return "\n".join(
        [
            "# Real-Threshold Backend Emission Request",
            "",
            "This request is the repo-generated challenge contract for an "
            "external P1 real-threshold backend capture. It is "
            f"{REQUEST_STATUS} conformance/proof-review evidence.",
            "",
            f"- Request: `{request['name']}`",
            f"- Request schema: `{manifest['request_schema']}`",
            f"- Required capture schema: `{manifest['capture_schema']}`",
            f"- Validator target: `{request['validator_count']}`",
            f"- Threshold target: `{request['threshold']}`",
            f"- Signature length: `{request['aggregate_signature_len']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            "",
            "This request requires Criterion 2 proof review, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )


def artifact_contents(report):
    """Build final artifact file contents."""
    return {
        "request.json": report["request_json"],
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }


def render_checksums(contents):
    """Render deterministic SHA-256 checksums for artifact files."""
    lines = []
    for name in sorted(contents):
        lines.append(f"{sha256_text(contents[name])}  {name}")
    return "\n".join(lines) + "\n"


def write_artifacts(report, out_dir):
    """Write request artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build an external threshold backend emission request"
    )
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--name", required=True, help="request name")
    parser.add_argument("--message-hex", required=True, help="application message hex")
    parser.add_argument(
        "--selected-profile-binding-digest-hex",
        required=True,
        help="selected profile binding digest hex",
    )
    parser.add_argument(
        "--threshold-output-certificate-digest-hex",
        required=True,
        help="threshold-output certificate digest hex",
    )
    parser.add_argument(
        "--standard-verifier-compatibility-artifact-digest-hex",
        required=True,
        help="standard-verifier compatibility artifact digest hex",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_request(
        name=args.name,
        message_hex=args.message_hex,
        selected_profile_binding_digest_hex=args.selected_profile_binding_digest_hex,
        threshold_output_certificate_digest_hex=(
            args.threshold_output_certificate_digest_hex
        ),
        standard_verifier_compatibility_artifact_digest_hex=(
            args.standard_verifier_compatibility_artifact_digest_hex
        ),
    )
    write_artifacts(report, args.out)
    print(f"wrote backend emission request artifacts to {args.out}")


if __name__ == "__main__":
    main()
