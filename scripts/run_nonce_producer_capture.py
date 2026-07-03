#!/usr/bin/env python3
"""Run an external distributed nonce-producer capture command and write artifacts."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path


CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
EXTERNAL_PRODUCER_EVIDENCE = "p1_shamir_nonce_dkg_tee_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
RUNNER_STATUS = "evidence_present_unclosed"
EXTERNAL_CAPTURE_PROVENANCE_SCHEMA = (
    "lattice-aggregation:external-capture-provenance:v1"
)
CAPTURE_SOURCE_PROFILE_EXTERNAL = "admissible_external_backend_capture"
CAPTURE_SOURCE_PROFILE_QUARANTINED_REPLAY = "quarantined_local_schema_replay"
QUARANTINED_LOCAL_REPLAY_TOKENS = (
    "emit_reviewed_nonce_producer_capture.py",
    "emit_reviewed_nonce_producer_capture",
)
FORBIDDEN_BACKEND_COMMAND_TOKENS = (
    "localnet",
    "validator_localnet",
    "run_simulation_benchmarks",
    "deterministic",
    "simulation",
    "simulated",
    "fixture",
    "hazmat",
    "centralized",
    "expanded-secret-key",
    "standard-provider",
    "single-key",
)
TOP_LEVEL_FIELDS = {
    "name",
    "schema",
    "claim_boundary",
    "selected_profile",
    "producer_evidence",
    "note",
    "request",
    "predecessors",
    "capture",
    "expected",
}
REQUEST_FIELDS = {
    "schema",
    "name",
    "generated_at",
    "claim_boundary",
    "request_status",
    "selected_profile",
    "predecessors",
    "required_capture",
    "forbidden_capture_sources",
}
REQUEST_BINDING_FIELDS = {"schema", "name", "request_sha256"}
PREDECESSOR_DIGEST_FIELDS = {
    "selected_profile_binding_digest_hex",
    "threshold_output_certificate_digest_hex",
    "standard_verifier_compatibility_artifact_digest_hex",
}
EXPECTED_DIGEST_FIELDS = {
    "source_reference_digest_hex",
    "backend_implementation_digest_hex",
    "coordinator_attestation_digest_hex",
    "shamir_nonce_dkg_transcript_digest_hex",
    "pairwise_mask_seed_commitment_digest_hex",
    "nonce_share_commitment_digest_hex",
    "abort_accountability_digest_hex",
    "external_review_digest_hex",
    "distributed_nonce_producer_artifact_digest_hex",
}
CAPTURE_PAYLOAD_FIELDS = {
    "source_reference",
    "backend_implementation",
    "coordinator_attestation",
    "shamir_nonce_dkg_transcript",
    "pairwise_mask_seed_commitments",
    "nonce_share_commitments",
    "abort_accountability",
    "external_review",
    "reviewed",
}
CAPTURE_BYTE_FIELDS = {"encoding", "value"}


class NonceProducerCaptureExecutionError(RuntimeError):
    """Capture command failed before producing a usable JSON envelope."""

    phase = "execution"

    def __init__(self, message, result):
        super().__init__(message)
        self.result = result


class NonceProducerCaptureValidationError(ValueError):
    """Capture command ran, but stdout failed request/capture validation."""

    phase = "validation"

    def __init__(self, message, result):
        super().__init__(message)
        self.result = result


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
    """Run an external nonce-producer command and capture stdout/stderr."""
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


def validate_backend_command(command):
    """Reject known scaffold/hazmat nonce-producer sources before execution."""
    command_text = " ".join(command).lower()
    for token in FORBIDDEN_BACKEND_COMMAND_TOKENS:
        if token in command_text:
            raise ValueError(
                "forbidden backend command source for actual nonce-producer capture: "
                + token
            )


def is_quarantined_local_replay_command(command):
    """Return true for the checked local replay emitter used only as a fixture."""
    command_text = " ".join(command).lower()
    return any(token in command_text for token in QUARANTINED_LOCAL_REPLAY_TOKENS)


def validate_capture_source_profile(command, allow_quarantined_replay=False):
    """Classify command source as external or quarantined local schema replay."""
    if is_quarantined_local_replay_command(command):
        if not allow_quarantined_replay:
            raise ValueError(
                "quarantined local replay source cannot be used as actual "
                "external nonce-producer capture"
            )
        return CAPTURE_SOURCE_PROFILE_QUARANTINED_REPLAY
    return CAPTURE_SOURCE_PROFILE_EXTERNAL


def quarantine_record(capture_source_profile):
    """Return capture quarantine metadata for the runner manifest."""
    quarantined = capture_source_profile == CAPTURE_SOURCE_PROFILE_QUARANTINED_REPLAY
    return {
        "quarantined": quarantined,
        "reason": (
            "local checked replay emitter exercises the request/capture/import "
            "schema but is not an independently generated backend capture"
            if quarantined
            else None
        ),
        "allowed_use": (
            "schema/importer replay only; not actual backend evidence; not "
            "Criterion 2 closure evidence"
            if quarantined
            else "explicit external backend capture gated by admissible readiness"
        ),
    }


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
        "evidence_class": manifest["producer_evidence"],
        "runner_status": RUNNER_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "expected_digest_fields": sorted(EXPECTED_DIGEST_FIELDS),
        "metadata_fields": sorted(metadata),
    }


def parse_capture_json(stdout):
    """Parse and validate canonical distributed nonce-producer capture JSON."""
    text = stdout.strip()
    if not text.startswith("{"):
        raise ValueError("nonce-producer capture runner requires canonical capture JSON")
    try:
        capture = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "nonce-producer capture runner requires canonical capture JSON"
        ) from exc

    validate_no_unknown_fields(capture, TOP_LEVEL_FIELDS, "top-level")
    if capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("nonce-producer capture runner requires canonical capture JSON")
    if capture.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError(
            "nonce-producer capture runner requires proof-review-only claim boundary"
        )
    if capture.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("nonce-producer capture runner selected profile mismatch")
    if capture.get("producer_evidence") != EXTERNAL_PRODUCER_EVIDENCE:
        raise ValueError(
            "nonce-producer capture runner requires actual external nonce-producer evidence"
        )
    validate_request_binding(capture.get("request"))
    if "predecessors" not in capture or "expected" not in capture:
        raise ValueError(
            "nonce-producer capture runner requires predecessor and expected digests"
        )
    validate_digest_object(capture["predecessors"], PREDECESSOR_DIGEST_FIELDS, "predecessor")
    validate_digest_object(capture["expected"], EXPECTED_DIGEST_FIELDS, "expected")

    payload = capture.get("capture")
    validate_no_unknown_fields(payload, CAPTURE_PAYLOAD_FIELDS, "capture")
    for field in CAPTURE_PAYLOAD_FIELDS - {"reviewed"}:
        validate_capture_bytes(payload.get(field), field)
    if payload.get("reviewed") is not True:
        raise ValueError("nonce-producer capture runner requires true reviewed")
    return capture


def load_request(path):
    """Load and validate the repo-generated nonce-producer request manifest."""
    try:
        request = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("nonce-producer capture runner requires request JSON") from exc

    validate_no_unknown_fields(request, REQUEST_FIELDS, "request")
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer capture runner request schema mismatch")
    if not isinstance(request.get("name"), str) or not request["name"].strip():
        raise ValueError("nonce-producer capture runner requires request name")
    if request.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("nonce-producer capture runner request claim boundary mismatch")
    if request.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("nonce-producer capture runner request selected profile mismatch")
    validate_digest_object(
        request.get("predecessors"),
        PREDECESSOR_DIGEST_FIELDS,
        "request predecessor",
    )
    required_capture = request.get("required_capture")
    validate_no_unknown_fields(
        required_capture,
        {"schema", "producer_evidence", "claim_boundary", "selected_profile", "material", "reviewed"},
        "request required_capture",
    )
    if required_capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError(
            "nonce-producer capture runner request required capture schema mismatch"
        )
    if required_capture.get("producer_evidence") != EXTERNAL_PRODUCER_EVIDENCE:
        raise ValueError("nonce-producer capture runner request required evidence mismatch")
    if required_capture.get("reviewed") is not True:
        raise ValueError("nonce-producer capture runner request requires reviewed capture")
    material = required_capture.get("material")
    if not isinstance(material, list) or set(material) != (CAPTURE_PAYLOAD_FIELDS - {"reviewed"}):
        raise ValueError("nonce-producer capture runner request material mismatch")
    return request


def validate_request_binding(binding):
    """Validate the capture carries a repo request digest binding."""
    if not isinstance(binding, dict):
        raise ValueError("nonce-producer capture runner requires request binding")
    validate_no_unknown_fields(binding, REQUEST_BINDING_FIELDS, "request binding")
    if binding.get("schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer capture runner request binding schema mismatch")
    if not isinstance(binding.get("name"), str) or not binding["name"].strip():
        raise ValueError("nonce-producer capture runner requires request binding name")
    validate_hex_field(binding.get("request_sha256"), 32, "request_sha256")
    if binding["request_sha256"].lower() == "00" * 32:
        raise ValueError("nonce-producer capture runner rejects all-zero request digest")


def validate_capture_matches_request(capture, request):
    """Require backend stdout to answer the exact request JSON supplied by the repo."""
    request_digest = sha256_text(canonical_json(request))
    binding = capture["request"]
    if binding["name"] != request["name"] or binding["schema"] != REQUEST_SCHEMA:
        raise ValueError("nonce-producer capture runner request binding mismatch")
    if binding["request_sha256"].lower() != request_digest:
        raise ValueError("nonce-producer capture runner request digest mismatch")
    if capture["selected_profile"] != request["selected_profile"]:
        raise ValueError("nonce-producer capture runner request selected profile mismatch")
    if capture["predecessors"] != request["predecessors"]:
        raise ValueError(
            "nonce-producer capture runner request predecessor digest mismatch"
        )
    if capture["capture"]["reviewed"] != request["required_capture"]["reviewed"]:
        raise ValueError("nonce-producer capture runner request reviewed mismatch")
    return request_digest


def validate_digest_object(value, required_fields, label):
    """Validate required nonzero SHA-256-style digest hex fields."""
    if not isinstance(value, dict):
        raise ValueError(f"nonce-producer capture runner requires {label} digests")
    validate_no_unknown_fields(value, set(required_fields), label)
    for field in required_fields:
        if field not in value:
            raise ValueError(f"nonce-producer capture runner missing {label} digest: {field}")
        validate_hex_field(value[field], 32, field)
        if value[field].lower() == "00" * 32:
            raise ValueError(
                f"nonce-producer capture runner rejects all-zero {label} digest: {field}"
            )


def validate_hex_field(value, expected_bytes, field):
    """Validate fixed-length lowercase-or-uppercase hex."""
    if not isinstance(value, str):
        raise ValueError(f"nonce-producer capture runner requires hex string for {field}")
    if len(value) != expected_bytes * 2:
        raise ValueError(f"nonce-producer capture runner invalid {field} length")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"nonce-producer capture runner invalid {field} hex") from exc


def validate_capture_bytes(value, field):
    """Validate a capture byte object supported by the Rust importer."""
    if not isinstance(value, dict):
        raise ValueError(f"nonce-producer capture runner requires byte object for {field}")
    validate_no_unknown_fields(value, CAPTURE_BYTE_FIELDS, field)
    encoding = value.get("encoding")
    raw_value = value.get("value")
    if encoding not in {"hex", "utf8"} or not isinstance(raw_value, str):
        raise ValueError(f"nonce-producer capture runner invalid byte encoding for {field}")
    if raw_value == "":
        raise ValueError(f"nonce-producer capture runner empty byte material for {field}")
    if encoding == "hex":
        if len(raw_value) % 2 != 0:
            raise ValueError(f"nonce-producer capture runner invalid byte hex for {field}")
        try:
            bytes.fromhex(raw_value)
        except ValueError as exc:
            raise ValueError(f"nonce-producer capture runner invalid byte hex for {field}") from exc


def validate_no_unknown_fields(value, allowed_fields, label):
    """Mirror Rust deny_unknown_fields before artifact write."""
    if not isinstance(value, dict):
        raise ValueError(f"nonce-producer capture runner requires object for {label}")
    unknown = sorted(set(value) - set(allowed_fields))
    if unknown:
        raise ValueError(f"nonce-producer capture runner unknown {label} field: {unknown[0]}")


def render_summary(generated_at, metadata, manifest):
    """Render a concise nonce-producer capture summary."""
    lines = [
            "# Distributed Nonce-Producer Capture Runner Summary",
            "",
            "This artifact records externally generated nonce-producer capture "
            "material for the canonical P1 importer. It is "
            f"{RUNNER_STATUS} conformance/proof-review evidence only.",
            "",
            f"- Generated at: `{generated_at}`",
            f"- Commit: `{metadata['commit']}`",
            f"- Branch: `{metadata['branch']}`",
            f"- Capture schema: `{manifest['capture_schema']}`",
            f"- Request schema: `{manifest['request_schema']}`",
            f"- Request: `{manifest['request_name']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            f"- Producer evidence: `{manifest['producer_evidence']}`",
            f"- Capture source profile: `{manifest['capture_source_profile']}`",
            f"- Runner status: `{RUNNER_STATUS}`",
            f"- Claim boundary: `{manifest['claim_boundary']}`",
        ]
    if manifest["quarantine"]["quarantined"]:
        lines.append(
            "- Quarantine: `quarantined local schema/importer replay only`"
        )
    lines.extend(
        [
            "",
            "This runner does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )
    return "\n".join(lines)


def build_report(
    root,
    backend_command,
    request_path=None,
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
    allow_quarantined_replay=False,
):
    """Run an external nonce-producer command and build in-memory artifacts."""
    if not backend_command:
        raise ValueError("nonce-producer capture runner requires a backend command")

    root = Path(root)
    validate_backend_command(list(backend_command))
    capture_source_profile = validate_capture_source_profile(
        list(backend_command),
        allow_quarantined_replay=allow_quarantined_replay,
    )
    result = command_runner(list(backend_command), root, {})
    if result["exit_code"] != 0:
        raise NonceProducerCaptureExecutionError(
            (
                "nonce-producer capture command failed: "
                + " ".join(backend_command)
                + "\n"
                + result.get("stderr", "")
            ),
            result,
        )

    try:
        capture = parse_capture_json(result["stdout"])
        request = load_request(request_path) if request_path else None
        request_sha256 = (
            validate_capture_matches_request(capture, request)
            if request is not None
            else capture["request"]["request_sha256"].lower()
        )
    except ValueError as exc:
        raise NonceProducerCaptureValidationError(str(exc), result) from exc
    metadata = metadata_from_provider(metadata_provider, root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
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
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "capture_source_profile": capture_source_profile,
        "quarantine": quarantine_record(capture_source_profile),
        "backend_command": list(backend_command),
        "command_duration_seconds": result["duration_seconds"],
        "exit_code": result["exit_code"],
        "metadata": metadata,
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
        description="Run an external distributed nonce-producer capture command"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-capture/latest",
        help="output directory",
    )
    parser.add_argument(
        "--request",
        required=True,
        help="repo-generated nonce-producer request JSON answered by the capture",
    )
    parser.add_argument(
        "--backend-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="external command that writes canonical nonce-producer capture JSON to stdout",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(Path(args.root), args.backend_command, request_path=args.request)
    write_artifacts(report, Path(args.out))
    print(f"wrote nonce-producer capture artifacts to {args.out}")


if __name__ == "__main__":
    main()
