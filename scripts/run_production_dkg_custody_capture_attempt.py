#!/usr/bin/env python3
"""Run the production DKG/custody capture acquisition gate.

This runner prepares the exact request for a production 10,000-validator,
6,667-threshold DKG/custody backend. It accepts only an external capture that
proves the production DKG/custody path needed by the strict campaign runner.
It records every weaker result as a blocked attempt.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path


RUN_SCHEMA = "lattice-aggregation:production-dkg-custody-capture-attempt:v1"
REQUEST_SCHEMA = "lattice-aggregation:production-dkg-custody-request:v1"
INTERNAL_REQUEST_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-dkg-custody-capture:v1"
PROVIDER_MANIFEST_SCHEMA = (
    "lattice-threshold-backend-p1:production-dkg-custody-provider-manifest:v1"
)
PROVIDER_MANIFEST_REVIEW_DOMAIN = (
    "lattice-threshold-backend-p1:production-dkg-custody-provider-manifest-review:v1"
)
READY_STATUS = "production_dkg_custody_capture_ready"
MISSING_COMMAND_STATUS = "blocked_production_dkg_custody_backend_unavailable"
COMMAND_FAILED_STATUS = "blocked_production_dkg_custody_command_failed"
CAPTURE_INVALID_STATUS = "blocked_production_dkg_custody_capture_invalid"
DEFAULT_INTERNAL_REQUEST = "artifacts/internal-aggregation-campaign/latest/request.json"
DEFAULT_OUT = "artifacts/production-dkg-custody-capture-attempt/latest"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
VALIDATOR_COUNT = 10_000
THRESHOLD = 6_667
CLAIM_BOUNDARY = (
    "production DKG/custody acquisition gate only; theorem closure remains "
    "pending exact campaign, proof, validation, and independent review evidence"
)
FORBIDDEN_COMMAND_TOKENS = (
    "fixture",
    "hazmat",
    "localnet",
    "seed-reconstruction",
    "seed_reconstruction",
    "single-key",
    "single_key",
    "simulation",
    "simulated",
    "smoke",
    "test-vector",
    "test_vector",
)
REQUIRED_TRUE_EVIDENCE_FIELDS = (
    "commit_before_reveal",
    "no_seed_dealer_dkg",
    "multiple_independent_dealers",
    "distributed_dkg_vss_transcript_present",
    "encrypted_receiver_custody_seam_executed",
    "process_isolated_receiver_custody",
    "per_receiver_private_share_custody",
    "receiver_vault_imports_verified",
    "signer_consumes_custody_output",
    "production_profile_executed",
    "production_dkg_no_single_secret_ready",
)
REQUIRED_FALSE_EVIDENCE_FIELDS = (
    "coordinator_observed_clear_dkg_shares_before_custody",
    "secret_material_exported_to_json",
    "raw_seed_exported_to_json",
    "expanded_key_exported_to_json",
)
REQUIRED_TRANSCRIPT_DIGEST_FIELDS = (
    "session_id_hex",
    "rho_digest_hex",
    "public_key_digest_hex",
    "dkg_transcript_digest_hex",
    "custody_bundle_digest_hex",
    "custody_commitments_digest_hex",
    "receiver_vault_root_hex",
    "commitment_key_digest_hex",
)
CLAIM_FLAG_KEYS = (
    "claims_theorem_closure",
    "claims_production_threshold_mldsa_security",
    "claims_production_dkg_custody_closure",
    "claims_no_single_exposed_secret_key",
    "claims_standard_verifier_threshold_signature_closure",
    "claims_rejection_distribution_preservation",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)
COMMAND_ORIGIN_EXTERNAL = "outside_repo_executable_or_script"
COMMAND_ORIGIN_REPO_LOCAL = "repo_local_executable_or_script"


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_text(value):
    return sha256_bytes(value.encode("utf-8"))


def sha256_path(path):
    path = Path(path)
    try:
        return sha256_bytes(path.read_bytes()) if path.is_file() else None
    except OSError:
        return None


def load_json(path):
    path = Path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"unavailable or invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def is_sha256(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        and value != "00" * 32
    )


def false_claim_flags():
    return {key: False for key in CLAIM_FLAG_KEYS}


def file_record(path):
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
        "size_bytes": path.stat().st_size if path.is_file() else None,
    }


def absent_file_record(path=None):
    return {
        "path": str(path) if path is not None else None,
        "present": False,
        "sha256": None,
        "size_bytes": None,
    }


def capture_value(command, root, fallback="unknown", timeout_seconds=10):
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return fallback
    if completed.returncode != 0:
        return fallback
    value = completed.stdout.strip()
    return value if value else fallback


def collect_metadata(root):
    root = Path(root)
    dirty_output = capture_value(
        ["git", "status", "--short"],
        root,
        fallback="__status_unavailable__",
        timeout_seconds=5,
    )
    return {
        "commit": capture_value(["git", "rev-parse", "HEAD"], root),
        "branch": capture_value(["git", "branch", "--show-current"], root),
        "dirty": dirty_output != "",
        "dirty_status_unavailable": dirty_output == "__status_unavailable__",
        "cargo_version": capture_value(["cargo", "--version"], root),
        "rustc_version": capture_value(["rustc", "--version"], root),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cargo_lock_sha256": sha256_path(root / "Cargo.lock"),
    }


def metadata_from_provider(provider, root):
    try:
        return provider(root)
    except TypeError:
        return provider()


def validate_internal_campaign_request(request):
    blockers = []
    if request.get("schema") != INTERNAL_REQUEST_SCHEMA:
        blockers.append("internal campaign request schema mismatch")
    topology = request.get("topology")
    if not isinstance(topology, dict):
        blockers.append("internal campaign request topology missing")
    else:
        if topology.get("validator_count") != VALIDATOR_COUNT:
            blockers.append("internal campaign request validator_count mismatch")
        if topology.get("threshold") != THRESHOLD:
            blockers.append("internal campaign request threshold mismatch")
    capture_requirements = request.get("capture_requirements")
    if not isinstance(capture_requirements, dict):
        blockers.append("internal campaign capture requirements missing")
    else:
        if capture_requirements.get("no_secret_or_seed_reconstruction") is not True:
            blockers.append("internal campaign request must forbid secret or seed reconstruction")
        if capture_requirements.get("execution_mode") != "actual_distributed_threshold_backend":
            blockers.append("internal campaign execution mode mismatch")
    return blockers


def build_capture_request(internal_request_path, internal_request, generated_at):
    internal_request_path = Path(internal_request_path)
    return {
        "schema": REQUEST_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "claim_boundary": CLAIM_BOUNDARY,
        "request_status": "production_dkg_custody_capture_requested",
        "source_internal_campaign_request": file_record(internal_request_path),
        "target_profile": {
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
        },
        "mldsa_profile": internal_request.get("mldsa_profile", {}),
        "required_capture": {
            "schema": CAPTURE_SCHEMA,
            "capture_status": READY_STATUS,
            "selected_profile": SELECTED_PROFILE,
            "target_validator_count": VALIDATOR_COUNT,
            "target_threshold": THRESHOLD,
            "execution_validator_count": VALIDATOR_COUNT,
            "execution_threshold": THRESHOLD,
        },
        "required_external_cli_contract": {
            "command": "threshold-backend-p1 emit-production-dkg-custody-capture",
            "runner_appends_arguments": [
                "--provider-manifest",
                "<provider-manifest.json>",
                "--request",
                "<request.json>",
                "--out",
                "<capture.json>",
            ],
            "capture_output": "canonical JSON file at --out",
            "stdout_contract": "diagnostic text only",
        },
        "required_provider_manifest_contract": {
            "schema": PROVIDER_MANIFEST_SCHEMA,
            "review_status": "production_dkg_custody_provider_review_ready",
            "review_signature": {
                "scheme": "Ed25519",
                "signed_payload": "canonical provider manifest without review_signature",
                "domain": PROVIDER_MANIFEST_REVIEW_DOMAIN,
            },
            "target_profile": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "selected_profile": SELECTED_PROFILE,
            },
            "required_true_evidence_fields": list(REQUIRED_TRUE_EVIDENCE_FIELDS),
            "required_false_evidence_fields": list(REQUIRED_FALSE_EVIDENCE_FIELDS),
            "required_transcript_digest_fields": list(REQUIRED_TRANSCRIPT_DIGEST_FIELDS),
            "required_provider_properties": [
                "no seed dealer",
                "multiple independent dealers",
                "commit-before-reveal DKG transcript",
                "process-isolated receiver custody",
                "per-receiver private share custody",
                "signer consumes custody output",
                "no clear-share observation by coordinator",
                "no raw seed or expanded key export",
                "empty provider blockers",
            ],
        },
        "required_true_evidence_fields": list(REQUIRED_TRUE_EVIDENCE_FIELDS),
        "required_false_evidence_fields": list(REQUIRED_FALSE_EVIDENCE_FIELDS),
        "required_transcript_digest_fields": list(REQUIRED_TRANSCRIPT_DIGEST_FIELDS),
        "required_claim_flags": false_claim_flags(),
    }


def is_python_executable(value):
    name = Path(value).name.lower()
    return name == "python" or name.startswith("python3")


def looks_like_path(value):
    return (
        isinstance(value, str)
        and (
            value.startswith(("/", "./", "../", "~"))
            or "/" in value
            or "\\" in value
        )
    )


def command_path_candidates(command):
    command = list(command)
    if not command:
        return []
    if is_python_executable(command[0]):
        for argument in command[1:]:
            if argument in {"-c", "-m"}:
                return []
            if argument.startswith("-"):
                continue
            return [argument] if looks_like_path(argument) else []
        return []
    return [command[0]] if looks_like_path(command[0]) else []


def resolve_command_path(root, token):
    path = Path(token).expanduser()
    if not path.is_absolute():
        path = Path(root) / path
    return path.resolve(strict=False)


def path_is_within(child, parent):
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def command_origin(root, command):
    repo_root = Path(root).resolve(strict=False)
    for token in command_path_candidates(command):
        if path_is_within(resolve_command_path(repo_root, token), repo_root):
            return COMMAND_ORIGIN_REPO_LOCAL
    return COMMAND_ORIGIN_EXTERNAL


def validate_backend_command(root, command):
    if not command:
        return None
    lowered = " ".join(command).lower()
    for token in FORBIDDEN_COMMAND_TOKENS:
        if token in lowered:
            raise ValueError("forbidden production DKG/custody backend command token: " + token)
    origin = command_origin(root, command)
    if origin == COMMAND_ORIGIN_REPO_LOCAL:
        raise ValueError("repo-local command cannot be used as production DKG/custody backend")
    return origin


def command_sha256(command):
    return sha256_text(canonical_json(list(command)))


def run_command(command, root, env):
    merged_env = os.environ.copy()
    merged_env.update(env or {})
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
        "command": list(command),
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def summarize_command_result(command_result):
    if not isinstance(command_result, dict):
        return None
    stdout = command_result.get("stdout", "")
    stderr = command_result.get("stderr", "")
    return {
        "exit_code": command_result.get("exit_code"),
        "duration_seconds": command_result.get("duration_seconds"),
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
    }


def check_equal(blockers, actual, expected, label):
    if actual != expected:
        blockers.append(f"{label} mismatch: expected {expected!r}, observed {actual!r}")


def require_true(blockers, mapping, field, label):
    if not isinstance(mapping, dict) or mapping.get(field) is not True:
        blockers.append(f"{label} must be true: {field}")


def require_false(blockers, mapping, field, label):
    if not isinstance(mapping, dict) or mapping.get(field) is not False:
        blockers.append(f"{label} must be false: {field}")


def validate_capture(capture, request):
    blockers = []
    check_equal(blockers, capture.get("schema"), CAPTURE_SCHEMA, "capture schema")
    check_equal(
        blockers,
        capture.get("selected_profile"),
        SELECTED_PROFILE,
        "capture selected_profile",
    )
    check_equal(blockers, capture.get("capture_status"), READY_STATUS, "capture status")
    target = capture.get("target_profile")
    if not isinstance(target, dict):
        blockers.append("target_profile missing")
    else:
        check_equal(blockers, target.get("validator_count"), VALIDATOR_COUNT, "target validator_count")
        check_equal(blockers, target.get("threshold"), THRESHOLD, "target threshold")
    execution = capture.get("execution_profile")
    if not isinstance(execution, dict):
        blockers.append("execution_profile missing")
    else:
        check_equal(
            blockers,
            execution.get("validator_count"),
            VALIDATOR_COUNT,
            "execution validator_count",
        )
        check_equal(
            blockers,
            execution.get("threshold"),
            THRESHOLD,
            "execution threshold",
        )
        dealer_count = execution.get("dealer_count")
        if not isinstance(dealer_count, int) or isinstance(dealer_count, bool) or dealer_count < 2:
            blockers.append("execution dealer_count must be an integer >= 2")

    request_binding = capture.get("request_binding")
    if not isinstance(request_binding, dict):
        blockers.append("request_binding missing")
    else:
        check_equal(
            blockers,
            request_binding.get("schema"),
            REQUEST_SCHEMA,
            "request binding schema",
        )
        check_equal(
            blockers,
            request_binding.get("request_sha256"),
            sha256_text(canonical_json(request)),
            "request binding digest",
        )

    claim_flags = capture.get("claim_flags")
    if not isinstance(claim_flags, dict):
        blockers.append("claim_flags missing")
    else:
        for flag in CLAIM_FLAG_KEYS:
            require_false(blockers, claim_flags, flag, "claim flag")

    capture_blockers = capture.get("blockers")
    if capture_blockers not in ([], None):
        blockers.append("capture blockers must be empty for production DKG/custody readiness")

    evidence = capture.get("dkg_custody_evidence")
    if not isinstance(evidence, dict):
        blockers.append("dkg_custody_evidence missing")
        evidence = {}
    for field in REQUIRED_TRUE_EVIDENCE_FIELDS:
        require_true(blockers, evidence, field, "DKG/custody evidence")
    for field in REQUIRED_FALSE_EVIDENCE_FIELDS:
        require_false(blockers, evidence, field, "DKG/custody evidence")

    transcript = capture.get("transcript")
    if not isinstance(transcript, dict):
        blockers.append("transcript missing")
        transcript = {}
    for field in REQUIRED_TRANSCRIPT_DIGEST_FIELDS:
        if not is_sha256(transcript.get(field)):
            blockers.append(f"transcript digest invalid: {field}")
    accepted_dealers = transcript.get("accepted_dealers")
    if (
        not isinstance(accepted_dealers, list)
        or len(accepted_dealers) < 2
        or len(set(accepted_dealers)) != len(accepted_dealers)
    ):
        blockers.append("transcript accepted_dealers must contain at least two distinct dealers")
    dealer_commitments = transcript.get("dealer_commitments")
    if not isinstance(dealer_commitments, list) or len(dealer_commitments) < 2:
        blockers.append("transcript dealer_commitments must contain at least two commitments")
    else:
        for index, commitment in enumerate(dealer_commitments):
            if not isinstance(commitment, dict):
                blockers.append(f"dealer commitment must be an object: {index}")
                continue
            if not is_sha256(commitment.get("commitment_digest_hex")):
                blockers.append(f"dealer commitment digest invalid: {index}")

    return blockers


def build_manifest(
    *,
    root,
    out,
    request_path,
    provider_manifest_path,
    capture_request,
    backend_command,
    backend_command_origin,
    command_result,
    status,
    blockers,
    capture=None,
    metadata=None,
    generated_at=None,
):
    capture_json = canonical_json(capture) if isinstance(capture, dict) else None
    return {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": status,
        "production_dkg_custody_capture_ready": status == READY_STATUS,
        "request": file_record(request_path),
        "provider_manifest": (
            file_record(provider_manifest_path)
            if provider_manifest_path is not None
            else absent_file_record()
        ),
        "provider_manifest_contract": {
            "schema": PROVIDER_MANIFEST_SCHEMA,
            "review_signature_domain": PROVIDER_MANIFEST_REVIEW_DOMAIN,
            "required": True,
        },
        "run_out": str(out),
        "candidate_capture_path": str(Path(out) / "candidate-capture.json"),
        "backend_command": list(backend_command or []),
        "backend_command_sha256": command_sha256(backend_command or []),
        "backend_command_origin": backend_command_origin,
        "command_result": summarize_command_result(command_result),
        "metadata": metadata,
        "request_sha256": sha256_text(canonical_json(capture_request)),
        "capture_sha256": sha256_text(capture_json) if capture_json is not None else None,
        "validated_target": {
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
        },
        "required_true_evidence_fields": list(REQUIRED_TRUE_EVIDENCE_FIELDS),
        "required_false_evidence_fields": list(REQUIRED_FALSE_EVIDENCE_FIELDS),
        "required_transcript_digest_fields": list(REQUIRED_TRANSCRIPT_DIGEST_FIELDS),
        "blockers": sorted(set(blocker for blocker in blockers if blocker)),
        "claim_flags": false_claim_flags(),
    }


def render_summary(manifest):
    def render_value(value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)

    lines = [
        "# Production DKG/Custody Capture Attempt",
        "",
        f"- Runner status: `{manifest['runner_status']}`",
        f"- Capture ready: `{render_value(manifest['production_dkg_custody_capture_ready'])}`",
        f"- Target validators: `{manifest['validated_target']['validator_count']}`",
        f"- Target threshold: `{manifest['validated_target']['threshold']}`",
        f"- Command origin: `{render_value(manifest['backend_command_origin'])}`",
        f"- Request SHA-256: `{manifest['request_sha256']}`",
        f"- Capture SHA-256: `{render_value(manifest['capture_sha256'])}`",
        "",
        "## Blockers",
        "",
    ]
    if manifest["blockers"]:
        lines.extend(f"- {blocker}" for blocker in manifest["blockers"])
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            CLAIM_BOUNDARY + ".",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    manifest = report["manifest"]
    contents = {
        "request.json": report["request_json"],
        "manifest.json": canonical_json(manifest),
        "summary.md": render_summary(manifest),
        "command.stdout.log": report.get("stdout", ""),
        "command.stderr.log": report.get("stderr", ""),
    }
    if report.get("capture_json") is not None:
        name = "capture.json" if manifest["production_dkg_custody_capture_ready"] else "rejected-capture.json"
        contents[name] = report["capture_json"]
    return contents


def render_checksums(contents):
    return "".join(
        f"{sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )


def write_attempt_artifacts(report, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out / name).write_text(content, encoding="utf-8")


def build_report(
    root,
    *,
    internal_request_path,
    out,
    backend_command=None,
    provider_manifest=None,
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
):
    root = Path(root)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata = metadata_from_provider(metadata_provider, root)
    internal_request_path = Path(internal_request_path)
    provider_manifest = Path(provider_manifest) if provider_manifest is not None else None
    internal_request = load_json(internal_request_path)
    request_blockers = validate_internal_campaign_request(internal_request)
    capture_request = build_capture_request(
        internal_request_path,
        internal_request,
        generated_at,
    )
    request_json = canonical_json(capture_request)
    request_path = out / "request.json"
    request_path.write_text(request_json, encoding="utf-8")
    backend_command = list(backend_command or [])
    origin = validate_backend_command(root, backend_command)

    if request_blockers:
        manifest = build_manifest(
            root=root,
            out=out,
            request_path=request_path,
            provider_manifest_path=provider_manifest,
            capture_request=capture_request,
            backend_command=backend_command,
            backend_command_origin=origin,
            command_result=None,
            status=MISSING_COMMAND_STATUS,
            blockers=[f"production DKG/custody request invalid: {item}" for item in request_blockers],
            metadata=metadata,
            generated_at=generated_at,
        )
        return {"manifest": manifest, "request_json": request_json}

    if not backend_command:
        manifest = build_manifest(
            root=root,
            out=out,
            request_path=request_path,
            provider_manifest_path=provider_manifest,
            capture_request=capture_request,
            backend_command=backend_command,
            backend_command_origin=None,
            command_result=None,
            status=MISSING_COMMAND_STATUS,
            blockers=["production DKG/custody backend command not supplied"],
            metadata=metadata,
            generated_at=generated_at,
        )
        return {"manifest": manifest, "request_json": request_json}

    capture_path = out / "candidate-capture.json"
    full_command = list(backend_command)
    if provider_manifest is not None:
        full_command += [
            "--provider-manifest",
            str(provider_manifest),
        ]
    full_command += [
        "--request",
        str(request_path),
        "--out",
        str(capture_path),
    ]
    result = command_runner(full_command, root, {})
    if result.get("exit_code") != 0:
        manifest = build_manifest(
            root=root,
            out=out,
            request_path=request_path,
            provider_manifest_path=provider_manifest,
            capture_request=capture_request,
            backend_command=full_command,
            backend_command_origin=origin,
            command_result=result,
            status=COMMAND_FAILED_STATUS,
            blockers=[
                "production DKG/custody backend command failed",
                (result.get("stderr") or "").strip()[:500],
            ],
            metadata=metadata,
            generated_at=generated_at,
        )
        return {
            "manifest": manifest,
            "request_json": request_json,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }

    try:
        capture = load_json(capture_path)
    except ValueError as error:
        manifest = build_manifest(
            root=root,
            out=out,
            request_path=request_path,
            provider_manifest_path=provider_manifest,
            capture_request=capture_request,
            backend_command=full_command,
            backend_command_origin=origin,
            command_result=result,
            status=CAPTURE_INVALID_STATUS,
            blockers=[str(error)],
            metadata=metadata,
            generated_at=generated_at,
        )
        return {
            "manifest": manifest,
            "request_json": request_json,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        }

    blockers = validate_capture(capture, capture_request)
    status = READY_STATUS if not blockers else CAPTURE_INVALID_STATUS
    manifest = build_manifest(
        root=root,
        out=out,
        request_path=request_path,
        provider_manifest_path=provider_manifest,
        capture_request=capture_request,
        backend_command=full_command,
        backend_command_origin=origin,
        command_result=result,
        status=status,
        blockers=blockers,
        capture=capture,
        metadata=metadata,
        generated_at=generated_at,
    )
    return {
        "manifest": manifest,
        "request_json": request_json,
        "capture_json": canonical_json(capture),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
    }


def parse_args(argv):
    backend_command = None
    if "--backend-command" in argv:
        index = argv.index("--backend-command")
        backend_command = argv[index + 1 :]
        argv = argv[:index]
    parser = argparse.ArgumentParser(
        description="Run the production DKG/custody capture acquisition gate"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--internal-request",
        default=DEFAULT_INTERNAL_REQUEST,
        help="preregistered internal aggregation campaign request JSON",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help="production DKG/custody capture attempt artifact directory",
    )
    parser.add_argument(
        "--provider-manifest",
        default=None,
        help="signed external production DKG/custody provider manifest JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 unless production DKG/custody capture readiness is true",
    )
    parsed = parser.parse_args(argv)
    parsed.backend_command = backend_command
    return parsed


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(
        Path(args.root),
        internal_request_path=Path(args.internal_request),
        out=Path(args.out),
        backend_command=args.backend_command,
        provider_manifest=Path(args.provider_manifest) if args.provider_manifest else None,
    )
    write_attempt_artifacts(report, Path(args.out))
    print(f"runner_status={report['manifest']['runner_status']}")
    print(f"blockers={len(report['manifest']['blockers'])}")
    if args.strict and report["manifest"]["runner_status"] != READY_STATUS:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
