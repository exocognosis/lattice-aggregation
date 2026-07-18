#!/usr/bin/env python3
"""Run an exact distributed ML-DSA internal campaign capture command.

The official campaign capture path is intentionally strict:

``artifacts/internal-aggregation-campaign/latest/capture.json`` is written only
after a backend command emits a capture that the repository's fail-closed
validator accepts.  Failed commands, malformed output, smoke captures, and
captures that retain proof or authorization blockers are recorded under the run
artifact directory instead.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath


RUN_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-run:v1"
CAPTURE_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-capture:v1"
READY_STATUS = "internal_campaign_capture_ready"
BLOCKED_STATUS = "blocked_exact_distributed_backend_unavailable"
REJECTED_STATUS = "blocked_capture_validation_failed"
COMMAND_FAILED_STATUS = "blocked_backend_command_failed"
PARSE_FAILED_STATUS = "blocked_backend_output_not_canonical_capture"
DEFAULT_CAMPAIGN_OUT = "artifacts/internal-aggregation-campaign/latest"
DEFAULT_RUN_OUT = "artifacts/internal-aggregation-campaign-run/latest"
CLAIM_BOUNDARY = (
    "exact distributed ML-DSA internal campaign capture runner; theorem closure "
    "remains pending five substantive criteria and independent review"
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
)
COMMAND_ORIGIN_EXTERNAL = "outside_repo_executable_or_script"
COMMAND_ORIGIN_REPO_LOCAL = "repo_local_executable_or_script"


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    if not path.is_file():
        return None
    return sha256_bytes(path.read_bytes())


def load_campaign_validator():
    path = Path(__file__).with_name("validate_internal_aggregation_campaign_capture.py")
    spec = importlib.util.spec_from_file_location(
        "internal_aggregation_campaign_validator_for_runner", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("campaign validator module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_record(path):
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "sha256": sha256_path(path),
    }


def is_python_executable(value):
    name = Path(value).name.lower()
    return name == "python" or name.startswith("python3")


def looks_like_path(value):
    return (
        value.startswith(("/", "./", "../", "~"))
        or "/" in value
        or "\\" in value
    )


def command_path_candidates(command):
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
        raise ValueError("internal campaign runner requires a backend command")
    lowered = " ".join(command).lower()
    for token in FORBIDDEN_COMMAND_TOKENS:
        if token in lowered:
            raise ValueError(
                "forbidden exact campaign backend command token: " + token
            )
    origin = command_origin(root, command)
    if origin == COMMAND_ORIGIN_REPO_LOCAL:
        raise ValueError(
            "repo-local command cannot be used as exact distributed campaign backend"
        )
    return origin


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


def capture_value(command, root, fallback="unknown"):
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
    root = Path(root)
    return {
        "commit": capture_value(["git", "rev-parse", "HEAD"], root),
        "branch": capture_value(["git", "branch", "--show-current"], root),
        "dirty": bool(capture_value(["git", "status", "--short"], root, fallback="")),
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


def load_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"unavailable or invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def parse_capture_json(stdout):
    text = stdout.strip()
    if not text.startswith("{"):
        raise ValueError("backend output is not canonical campaign capture JSON")
    try:
        capture = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("backend output is not canonical campaign capture JSON") from error
    if not isinstance(capture, dict):
        raise ValueError("backend output campaign capture root must be an object")
    if capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("backend output campaign capture schema mismatch")
    return capture


def validate_evidence_paths_contained(capture, evidence_base):
    records = capture.get("evidence_files")
    if not isinstance(records, list):
        return
    base = Path(evidence_base).resolve(strict=False)
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            continue
        pure = PurePosixPath(record["path"])
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError("campaign evidence path is not safely relative")
        (base / Path(*pure.parts)).resolve(strict=False).relative_to(base)


def command_sha256(command):
    return sha256_text(canonical_json(list(command)))


def build_blocked_report(
    *,
    root,
    request_path,
    campaign_out,
    run_out,
    backend_command,
    command_origin_value,
    command_result=None,
    status,
    blockers,
    capture=None,
    validation=None,
    metadata=None,
    generated_at=None,
):
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata = metadata or collect_metadata(root)
    capture_json = canonical_json(capture) if isinstance(capture, dict) else None
    manifest = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": status,
        "official_capture_written": False,
        "official_validation_written": False,
        "request": file_record(request_path),
        "campaign_out": str(campaign_out),
        "run_out": str(run_out),
        "backend_command": list(backend_command),
        "backend_command_sha256": command_sha256(backend_command),
        "backend_command_origin": command_origin_value,
        "command_result": summarize_command_result(command_result),
        "metadata": metadata,
        "capture_sha256": sha256_text(capture_json) if capture_json is not None else None,
        "validation_sha256": (
            sha256_text(canonical_json(validation))
            if isinstance(validation, dict)
            else None
        ),
        "validation_status": (
            validation.get("campaign_status") if isinstance(validation, dict) else None
        ),
        "validated_execution_count": (
            validation.get("validated_execution_count")
            if isinstance(validation, dict)
            else None
        ),
        "blockers": sorted(set(blocker for blocker in blockers if blocker)),
        "claim_flags": {
            "claims_internal_campaign_evidence_ready": False,
            "claims_internal_theorem_closure": False,
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_fips_validation": False,
        },
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
        "capture_json": capture_json,
        "validation_json": canonical_json(validation) if isinstance(validation, dict) else None,
        "stdout": command_result.get("stdout", "") if isinstance(command_result, dict) else "",
        "stderr": command_result.get("stderr", "") if isinstance(command_result, dict) else "",
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


def build_success_report(
    *,
    root,
    request_path,
    campaign_out,
    run_out,
    backend_command,
    command_origin_value,
    command_result,
    capture,
    validation,
    metadata,
    generated_at=None,
):
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    capture_json = canonical_json(capture)
    manifest = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "runner_status": READY_STATUS,
        "official_capture_written": True,
        "official_validation_written": True,
        "request": file_record(request_path),
        "campaign_out": str(campaign_out),
        "run_out": str(run_out),
        "backend_command": list(backend_command),
        "backend_command_sha256": command_sha256(backend_command),
        "backend_command_origin": command_origin_value,
        "command_result": summarize_command_result(command_result),
        "metadata": metadata,
        "capture_sha256": sha256_text(capture_json),
        "validation_sha256": sha256_text(canonical_json(validation)),
        "validation_status": validation.get("campaign_status"),
        "validated_execution_count": validation.get("validated_execution_count"),
        "blockers": [],
        "claim_flags": {
            "claims_internal_campaign_evidence_ready": True,
            "claims_internal_theorem_closure": False,
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_fips_validation": False,
        },
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
        "capture_json": capture_json,
        "validation_json": canonical_json(validation),
        "stdout": command_result.get("stdout", ""),
        "stderr": command_result.get("stderr", ""),
    }


def render_manifest_value(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def render_summary(manifest):
    lines = [
        "# Internal Aggregation Campaign Runner",
        "",
        f"- Runner status: `{manifest['runner_status']}`",
        f"- Official capture written: `{render_manifest_value(manifest['official_capture_written'])}`",
        f"- Official validation written: `{render_manifest_value(manifest['official_validation_written'])}`",
        f"- Command origin: `{manifest['backend_command_origin']}`",
        f"- Capture SHA-256: `{render_manifest_value(manifest['capture_sha256'])}`",
        f"- Validation status: `{render_manifest_value(manifest['validation_status'])}`",
        f"- Validated executions: `{render_manifest_value(manifest['validated_execution_count'])}`",
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
            "This runner can promote only internal campaign evidence. It does not",
            "claim theorem closure, production threshold security, FIPS validation,",
            "or independent cryptographic review completion.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    contents = {
        "run-manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
        "command.stdout.log": report["stdout"],
        "command.stderr.log": report["stderr"],
    }
    if report.get("capture_json") is not None:
        name = (
            "capture.json"
            if report["manifest"]["official_capture_written"]
            else "rejected-capture.json"
        )
        contents[name] = report["capture_json"]
    if report.get("validation_json") is not None:
        name = (
            "validation.json"
            if report["manifest"]["official_validation_written"]
            else "rejected-validation.json"
        )
        contents[name] = report["validation_json"]
    return contents


def render_checksums(contents):
    return "".join(
        f"{sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )


def write_run_artifacts(report, run_out):
    run_out = Path(run_out)
    run_out.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (run_out / name).write_text(content, encoding="utf-8")


def write_official_campaign(capture, validation, campaign_out, validator):
    campaign_out = Path(campaign_out)
    campaign_out.mkdir(parents=True, exist_ok=True)
    (campaign_out / "capture.json").write_text(canonical_json(capture), encoding="utf-8")
    validator.write_report(validation, campaign_out)


def build_report(
    root,
    *,
    request_path,
    campaign_out,
    run_out,
    backend_command,
    evidence_base=None,
    authorization_verifier=None,
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
):
    root = Path(root)
    request_path = Path(request_path)
    campaign_out = Path(campaign_out)
    run_out = Path(run_out)
    evidence_base = Path(evidence_base or campaign_out)
    metadata = metadata_from_provider(metadata_provider, root)
    origin = validate_backend_command(root, list(backend_command))
    request = load_json(request_path)
    validator = load_campaign_validator()
    request_blockers = validator.validate_request(request)
    if request_blockers:
        return build_blocked_report(
            root=root,
            request_path=request_path,
            campaign_out=campaign_out,
            run_out=run_out,
            backend_command=backend_command,
            command_origin_value=origin,
            status=BLOCKED_STATUS,
            blockers=[f"campaign request invalid: {blocker}" for blocker in request_blockers],
            metadata=metadata,
            generated_at=generated_at,
        )

    result = command_runner(list(backend_command), root, {})
    if result.get("exit_code") != 0:
        return build_blocked_report(
            root=root,
            request_path=request_path,
            campaign_out=campaign_out,
            run_out=run_out,
            backend_command=backend_command,
            command_origin_value=origin,
            command_result=result,
            status=COMMAND_FAILED_STATUS,
            blockers=[
                "exact distributed campaign backend command failed",
                (result.get("stderr") or "").strip()[:500],
            ],
            metadata=metadata,
            generated_at=generated_at,
        )

    try:
        capture = parse_capture_json(result.get("stdout", ""))
        validate_evidence_paths_contained(capture, evidence_base)
    except ValueError as error:
        return build_blocked_report(
            root=root,
            request_path=request_path,
            campaign_out=campaign_out,
            run_out=run_out,
            backend_command=backend_command,
            command_origin_value=origin,
            command_result=result,
            status=PARSE_FAILED_STATUS,
            blockers=[str(error)],
            metadata=metadata,
            generated_at=generated_at,
        )

    validation = validator.validate_campaign(
        request,
        capture,
        evidence_base,
        authorization_verifier=authorization_verifier,
    )
    if validation.get("internal_campaign_evidence_ready") is not True:
        return build_blocked_report(
            root=root,
            request_path=request_path,
            campaign_out=campaign_out,
            run_out=run_out,
            backend_command=backend_command,
            command_origin_value=origin,
            command_result=result,
            status=REJECTED_STATUS,
            blockers=validation.get("blockers", ["campaign validation failed"]),
            capture=capture,
            validation=validation,
            metadata=metadata,
            generated_at=generated_at,
        )

    return build_success_report(
        root=root,
        request_path=request_path,
        campaign_out=campaign_out,
        run_out=run_out,
        backend_command=backend_command,
        command_origin_value=origin,
        command_result=result,
        capture=capture,
        validation=validation,
        metadata=metadata,
        generated_at=generated_at,
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run an exact distributed ML-DSA internal campaign capture command"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--request",
        default=f"{DEFAULT_CAMPAIGN_OUT}/request.json",
        help="preregistered internal campaign request JSON",
    )
    parser.add_argument(
        "--campaign-out",
        default=DEFAULT_CAMPAIGN_OUT,
        help="official campaign artifact directory",
    )
    parser.add_argument(
        "--run-out",
        default=DEFAULT_RUN_OUT,
        help="runner attempt artifact directory",
    )
    parser.add_argument(
        "--evidence-base",
        default=None,
        help="directory containing capture-relative evidence files; defaults to campaign-out",
    )
    parser.add_argument(
        "--backend-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="external exact backend command that writes canonical campaign capture JSON to stdout",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 unless the official campaign capture is written",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(
        Path(args.root),
        request_path=Path(args.request),
        campaign_out=Path(args.campaign_out),
        run_out=Path(args.run_out),
        evidence_base=Path(args.evidence_base) if args.evidence_base else None,
        backend_command=args.backend_command,
    )
    if report["manifest"]["runner_status"] == READY_STATUS:
        validator = load_campaign_validator()
        write_official_campaign(
            json.loads(report["capture_json"]),
            json.loads(report["validation_json"]),
            Path(args.campaign_out),
            validator,
        )
    write_run_artifacts(report, Path(args.run_out))
    print(f"runner_status={report['manifest']['runner_status']}")
    print(f"blockers={len(report['manifest']['blockers'])}")
    if args.strict and report["manifest"]["runner_status"] != READY_STATUS:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
