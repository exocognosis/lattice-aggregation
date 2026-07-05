#!/usr/bin/env python3
"""Run an external real-threshold backend capture command and write artifacts."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path


CAPTURE_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-real-threshold-backend-emission-request:v1"
EXTERNAL_BACKEND_EVIDENCE = "real_threshold_mldsa_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
RUNNER_STATUS = "evidence_present_unclosed"
EXTERNAL_CAPTURE_PROVENANCE_SCHEMA = (
    "lattice-aggregation:external-capture-provenance:v1"
)
MLDSA65_PUBLIC_KEY_BYTES = 1952
MLDSA65_SIGNATURE_BYTES = 3309
FORBIDDEN_BACKEND_COMMAND_TOKENS = (
    "localnet",
    "validator_localnet",
    "run_simulation_benchmarks",
    "deterministic",
    "simulation",
    "simulated",
)
COMMAND_ORIGIN_EXTERNAL = "outside_repo_executable_or_script"
COMMAND_ORIGIN_REPO_LOCAL = "repo_local_executable_or_script"
TOP_LEVEL_FIELDS = {
    "name",
    "schema",
    "claim_boundary",
    "selected_profile",
    "backend_evidence",
    "note",
    "cryptographic_core",
    "request",
    "predecessors",
    "capture",
    "expected",
}
REQUEST_BINDING_FIELDS = {
    "schema",
    "name",
    "request_sha256",
}
PREDECESSOR_DIGEST_FIELDS = {
    "selected_profile_binding_digest_hex",
    "threshold_output_certificate_digest_hex",
    "standard_verifier_compatibility_artifact_digest_hex",
}
EXPECTED_DIGEST_FIELDS = {
    "backend_evidence_digest_hex",
    "backend_source_package_digest_hex",
    "backend_implementation_digest_hex",
    "backend_transcript_digest_hex",
    "threshold_core_accounting_digest_hex",
    "artifact_digest_hex",
    "public_key_digest_hex",
    "message_digest_hex",
    "accepted_signature_digest_hex",
}
CAPTURE_PAYLOAD_FIELDS = {
    "validator_count",
    "threshold",
    "aggregate_signature_len",
    "public_key_hex",
    "message",
    "aggregate_signature_hex",
    "backend_source_package",
    "backend_implementation",
    "backend_transcript",
    "mutated_message_rejected",
    "mutated_public_key_rejected",
    "mutated_signature_rejected",
    "reviewed",
}
CAPTURE_BYTE_FIELDS = {"encoding", "value"}


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    """Return the SHA-256 digest for a file, or unknown if absent."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def run_command(command, root, env):
    """Run an external backend command and capture stdout/stderr."""
    merged_env = None
    if env:
        import os

        merged_env = os.environ.copy()
        merged_env.update(env)

    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=root,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def validate_backend_command(root, command):
    """Reject known non-cryptographic capture sources before execution."""
    command_text = " ".join(command).lower()
    for token in FORBIDDEN_BACKEND_COMMAND_TOKENS:
        if token in command_text:
            raise ValueError(
                "forbidden backend command source for actual real-threshold capture: "
                + token
            )
    origin = backend_command_origin(root, command)
    if origin == COMMAND_ORIGIN_REPO_LOCAL:
        raise ValueError(
            "repo-local backend command cannot be used as actual "
            "external real-threshold capture"
        )
    return origin


def is_python_executable(value):
    """Return true when a command path names a Python interpreter."""
    name = Path(value).name.lower()
    return name == "python" or name.startswith("python3")


def looks_like_path(value):
    """Return true when a command token should be interpreted as a path."""
    return (
        value.startswith(("/", "./", "../", "~"))
        or "/" in value
        or "\\" in value
    )


def backend_command_path_candidates(command):
    """Return executable/script path tokens that can identify command origin."""
    command = list(command)
    if not command:
        return []
    if is_python_executable(command[0]):
        for arg in command[1:]:
            if arg in {"-c", "-m"}:
                return []
            if arg.startswith("-"):
                continue
            return [arg] if looks_like_path(arg) else []
        return []
    return [command[0]] if looks_like_path(command[0]) else []


def resolve_command_path(root, token):
    """Resolve a command path token without requiring it to exist."""
    path = Path(token).expanduser()
    if not path.is_absolute():
        path = Path(root) / path
    return path.resolve(strict=False)


def path_is_within(child, parent):
    """Return true when child resolves inside parent."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def backend_command_origin(root, command):
    """Classify whether the command path is outside the repository."""
    repo_root = Path(root).resolve(strict=False)
    for token in backend_command_path_candidates(command):
        if path_is_within(resolve_command_path(repo_root, token), repo_root):
            return COMMAND_ORIGIN_REPO_LOCAL
    return COMMAND_ORIGIN_EXTERNAL


def capture_value(command, root, fallback="unknown"):
    """Capture a small metadata command without failing artifact generation."""
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return fallback
    if completed.returncode != 0:
        return fallback
    value = completed.stdout.strip()
    return value if value else fallback


def collect_metadata(root):
    """Collect local capture-runner provenance metadata."""
    root = Path(root)
    return {
        "commit": capture_value(["git", "rev-parse", "HEAD"], root),
        "branch": capture_value(["git", "branch", "--show-current"], root),
        "dirty": bool(capture_value(["git", "status", "--short"], root, fallback="")),
        "cargo_version": capture_value(["cargo", "--version"], root),
        "rustc_version": capture_value(["rustc", "--version"], root),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
    }


def metadata_from_provider(provider, root):
    """Call metadata providers from tests or production code."""
    try:
        return provider(root)
    except TypeError:
        return provider()


def build_external_capture_provenance(capture, manifest, metadata):
    """Build durable provenance for an externally emitted capture."""
    return {
        "schema": EXTERNAL_CAPTURE_PROVENANCE_SCHEMA,
        "request_schema": capture["request"]["schema"],
        "request_name": capture["request"]["name"],
        "request_sha256": manifest["request_sha256"],
        "capture_schema": manifest["capture_schema"],
        "capture_sha256": manifest["capture_sha256"],
        "backend_command_sha256": sha256_text(
            canonical_json(manifest["backend_command"])
        ),
        "backend_command_origin": manifest["backend_command_origin"],
        "evidence_class": manifest["backend_evidence"],
        "runner_status": RUNNER_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "expected_digest_fields": sorted(EXPECTED_DIGEST_FIELDS),
        "metadata_fields": sorted(metadata),
    }


def parse_capture_json(stdout):
    """Parse and validate canonical real-threshold backend capture JSON."""
    text = stdout.strip()
    if not text.startswith("{"):
        raise ValueError("backend capture runner requires canonical capture JSON")
    try:
        capture = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("backend capture runner requires canonical capture JSON") from exc

    validate_no_unknown_fields(capture, TOP_LEVEL_FIELDS, "top-level")
    if capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("backend capture runner requires canonical capture JSON")
    if capture.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("backend capture runner requires proof-review-only claim boundary")
    if capture.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("backend capture runner selected profile mismatch")
    if capture.get("backend_evidence") != EXTERNAL_BACKEND_EVIDENCE:
        raise ValueError(
            "backend capture runner requires actual external real-threshold evidence"
        )
    validate_request_binding(capture.get("request"))
    if "predecessors" not in capture or "expected" not in capture:
        raise ValueError("backend capture runner requires predecessor and expected digests")
    validate_digest_object(
        capture["predecessors"],
        PREDECESSOR_DIGEST_FIELDS,
        "predecessor",
    )
    validate_digest_object(
        capture["expected"],
        EXPECTED_DIGEST_FIELDS,
        "expected",
    )

    payload = capture.get("capture")
    if not isinstance(payload, dict):
        raise ValueError("backend capture runner requires capture payload")
    validate_no_unknown_fields(payload, CAPTURE_PAYLOAD_FIELDS, "capture")
    if payload.get("validator_count") != 10_000 or payload.get("threshold") != 6_667:
        raise ValueError("backend capture runner requires the 10,000 validator P1 target")
    if payload.get("aggregate_signature_len") != 3309:
        raise ValueError("backend capture runner requires a standard-size ML-DSA-65 signature")
    for field in [
        "public_key_hex",
        "message",
        "aggregate_signature_hex",
        "backend_source_package",
        "backend_implementation",
        "backend_transcript",
    ]:
        if field not in payload:
            raise ValueError(f"backend capture runner missing capture field: {field}")
    validate_hex_field(
        payload["public_key_hex"],
        MLDSA65_PUBLIC_KEY_BYTES,
        "public_key_hex",
    )
    validate_hex_field(
        payload["aggregate_signature_hex"],
        MLDSA65_SIGNATURE_BYTES,
        "aggregate_signature_hex",
    )
    for field in [
        "message",
        "backend_source_package",
        "backend_implementation",
        "backend_transcript",
    ]:
        validate_capture_bytes(payload[field], field)
    for field in [
        "mutated_message_rejected",
        "mutated_public_key_rejected",
        "mutated_signature_rejected",
        "reviewed",
    ]:
        if payload.get(field) is not True:
            raise ValueError(f"backend capture runner requires true {field}")

    return capture


def load_request(path):
    """Load and validate the repo-generated backend emission request manifest."""
    try:
        request = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("backend capture runner requires request JSON") from exc

    validate_no_unknown_fields(
        request,
        {
            "schema",
            "name",
            "generated_at",
            "claim_boundary",
            "request_status",
            "selected_profile",
            "validator_count",
            "threshold",
            "aggregate_signature_len",
            "message",
            "predecessors",
            "required_capture",
            "forbidden_capture_sources",
        },
        "request",
    )
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("backend capture runner request schema mismatch")
    if not isinstance(request.get("name"), str) or not request["name"].strip():
        raise ValueError("backend capture runner requires request name")
    if request.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("backend capture runner request claim boundary mismatch")
    if request.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("backend capture runner request selected profile mismatch")
    if request.get("validator_count") != 10_000 or request.get("threshold") != 6_667:
        raise ValueError("backend capture runner requires the 10,000 validator request")
    if request.get("aggregate_signature_len") != MLDSA65_SIGNATURE_BYTES:
        raise ValueError("backend capture runner request signature length mismatch")
    validate_capture_bytes(request.get("message"), "request message")
    validate_digest_object(
        request.get("predecessors"),
        PREDECESSOR_DIGEST_FIELDS,
        "request predecessor",
    )
    required_capture = request.get("required_capture")
    validate_no_unknown_fields(
        required_capture,
        {
            "schema",
            "backend_evidence",
            "claim_boundary",
            "selected_profile",
            "validator_count",
            "threshold",
            "aggregate_signature_len",
            "mutated_message_rejected",
            "mutated_public_key_rejected",
            "mutated_signature_rejected",
            "reviewed",
        },
        "request required_capture",
    )
    if required_capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("backend capture runner request required capture schema mismatch")
    if required_capture.get("backend_evidence") != EXTERNAL_BACKEND_EVIDENCE:
        raise ValueError("backend capture runner request required evidence mismatch")
    return request


def validate_request_binding(binding):
    """Validate the capture carries a repo request digest binding."""
    if not isinstance(binding, dict):
        raise ValueError("backend capture runner requires request binding")
    validate_no_unknown_fields(binding, REQUEST_BINDING_FIELDS, "request binding")
    if binding.get("schema") != REQUEST_SCHEMA:
        raise ValueError("backend capture runner request binding schema mismatch")
    if not isinstance(binding.get("name"), str) or not binding["name"].strip():
        raise ValueError("backend capture runner requires request binding name")
    validate_hex_field(binding.get("request_sha256"), 32, "request_sha256")
    if binding["request_sha256"].lower() == "00" * 32:
        raise ValueError("backend capture runner rejects all-zero request digest")


def validate_capture_matches_request(capture, request):
    """Require backend stdout to answer the exact request JSON supplied by the repo."""
    request_digest = sha256_text(canonical_json(request))
    binding = capture["request"]
    if binding["name"] != request["name"] or binding["schema"] != REQUEST_SCHEMA:
        raise ValueError("backend capture runner request binding mismatch")
    if binding["request_sha256"].lower() != request_digest:
        raise ValueError("backend capture runner request digest mismatch")
    if capture["selected_profile"] != request["selected_profile"]:
        raise ValueError("backend capture runner request selected profile mismatch")
    if capture["predecessors"] != request["predecessors"]:
        raise ValueError("backend capture runner request predecessor digest mismatch")
    if capture["capture"]["message"] != request["message"]:
        raise ValueError("backend capture runner request message mismatch")

    required_capture = request["required_capture"]
    for field in [
        "validator_count",
        "threshold",
        "aggregate_signature_len",
        "mutated_message_rejected",
        "mutated_public_key_rejected",
        "mutated_signature_rejected",
        "reviewed",
    ]:
        if capture["capture"][field] != required_capture[field]:
            raise ValueError(f"backend capture runner request capture field mismatch: {field}")
    return request_digest


def validate_digest_object(value, required_fields, label):
    """Validate required nonzero SHA-256-style digest hex fields."""
    if not isinstance(value, dict):
        raise ValueError(f"backend capture runner requires {label} digests")
    validate_no_unknown_fields(value, set(required_fields), label)
    for field in required_fields:
        if field not in value:
            raise ValueError(f"backend capture runner missing {label} digest: {field}")
        validate_hex_field(value[field], 32, field)
        if value[field].lower() == "00" * 32:
            raise ValueError(f"backend capture runner rejects all-zero {label} digest: {field}")


def validate_hex_field(value, expected_bytes, field):
    """Validate fixed-length lowercase-or-uppercase hex."""
    if not isinstance(value, str):
        raise ValueError(f"backend capture runner requires hex string for {field}")
    if len(value) != expected_bytes * 2:
        raise ValueError(f"backend capture runner invalid {field} length")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"backend capture runner invalid {field} hex") from exc


def validate_capture_bytes(value, field):
    """Validate a capture byte object supported by the Rust importer."""
    if not isinstance(value, dict):
        raise ValueError(f"backend capture runner requires byte object for {field}")
    validate_no_unknown_fields(value, CAPTURE_BYTE_FIELDS, field)
    encoding = value.get("encoding")
    raw_value = value.get("value")
    if encoding not in {"hex", "utf8"} or not isinstance(raw_value, str):
        raise ValueError(f"backend capture runner invalid byte encoding for {field}")
    if encoding == "hex":
        if len(raw_value) % 2 != 0:
            raise ValueError(f"backend capture runner invalid byte hex for {field}")
        try:
            bytes.fromhex(raw_value)
        except ValueError as exc:
            raise ValueError(f"backend capture runner invalid byte hex for {field}") from exc


def validate_no_unknown_fields(value, allowed_fields, label):
    """Mirror Rust deny_unknown_fields before artifact write."""
    if not isinstance(value, dict):
        raise ValueError(f"backend capture runner requires object for {label}")
    unknown = sorted(set(value) - set(allowed_fields))
    if unknown:
        raise ValueError(
            f"backend capture runner unknown {label} field: {unknown[0]}"
        )


def render_summary(generated_at, metadata, manifest):
    """Render a concise backend-capture summary."""
    return "\n".join(
        [
            "# Real-Threshold Backend Capture Runner Summary",
            "",
            "This artifact records externally generated backend capture material "
            "for the canonical P1 importer. It is "
            f"{RUNNER_STATUS} conformance/proof-review evidence only.",
            "",
            f"- Generated at: `{generated_at}`",
            f"- Commit: `{metadata['commit']}`",
            f"- Branch: `{metadata['branch']}`",
            f"- Capture schema: `{manifest['capture_schema']}`",
            f"- Request schema: `{manifest['request_schema']}`",
            f"- Request: `{manifest['request_name']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            f"- Backend evidence: `{manifest['backend_evidence']}`",
            f"- Backend command origin: `{manifest['backend_command_origin']}`",
            f"- Validator target: `{manifest['validator_count']}`",
            f"- Threshold target: `{manifest['threshold']}`",
            f"- Signature length: `{manifest['aggregate_signature_len']}`",
            f"- Runner status: `{RUNNER_STATUS}`",
            f"- Claim boundary: `{manifest['claim_boundary']}`",
            "",
            "This runner does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )


def build_report(
    root,
    backend_command,
    request_path=None,
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
):
    """Run an external backend command and build in-memory artifact content."""
    if not backend_command:
        raise ValueError("backend capture runner requires a backend command")

    root = Path(root)
    command_origin = validate_backend_command(root, list(backend_command))
    result = command_runner(list(backend_command), root, {})
    if result["exit_code"] != 0:
        raise RuntimeError(
            "backend capture command failed: "
            + " ".join(backend_command)
            + "\n"
            + result.get("stderr", "")
        )

    capture = parse_capture_json(result["stdout"])
    request = load_request(request_path) if request_path else None
    request_sha256 = (
        validate_capture_matches_request(capture, request)
        if request is not None
        else capture["request"]["request_sha256"].lower()
    )
    metadata = metadata_from_provider(metadata_provider, root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = capture["capture"]
    capture_json = canonical_json(capture)

    manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": RUNNER_STATUS,
        "capture_schema": CAPTURE_SCHEMA,
        "request_schema": REQUEST_SCHEMA,
        "request_name": capture["request"]["name"],
        "request_sha256": request_sha256,
        "request_path": str(request_path) if request_path else None,
        "backend_evidence": EXTERNAL_BACKEND_EVIDENCE,
        "backend_command_origin": command_origin,
        "backend_command": list(backend_command),
        "command_duration_seconds": result["duration_seconds"],
        "exit_code": result["exit_code"],
        "metadata": metadata,
        "validator_count": payload["validator_count"],
        "threshold": payload["threshold"],
        "aggregate_signature_len": payload["aggregate_signature_len"],
        "capture_sha256": sha256_text(capture_json),
    }
    manifest["external_capture_provenance"] = build_external_capture_provenance(
        capture,
        manifest,
        metadata,
    )
    summary_md = render_summary(generated_at, metadata, manifest)

    return {
        "manifest": manifest,
        "capture": capture,
        "capture_json": capture_json,
        "summary_md": summary_md,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }


def artifact_contents(report):
    """Build final artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "capture.json": report["capture_json"],
        "summary.md": report["summary_md"],
        "command.stdout.log": report["stdout"],
        "command.stderr.log": report["stderr"],
    }


def render_checksums(contents):
    """Render deterministic SHA-256 checksums for artifact files."""
    lines = []
    for name in sorted(contents):
        lines.append(f"{sha256_text(contents[name])}  {name}")
    return "\n".join(lines) + "\n"


def write_artifacts(report, out_dir):
    """Write capture artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        path = out_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run an external threshold backend capture command"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--out",
        default="artifacts/backend-emission-capture/latest",
        help="output directory",
    )
    parser.add_argument(
        "--request",
        required=True,
        help="repo-generated backend emission request JSON answered by the capture",
    )
    parser.add_argument(
        "--backend-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="external command that writes canonical capture JSON to stdout",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(Path(args.root), args.backend_command, request_path=args.request)
    write_artifacts(report, Path(args.out))
    print(f"wrote backend capture artifacts to {args.out}")


if __name__ == "__main__":
    main()
