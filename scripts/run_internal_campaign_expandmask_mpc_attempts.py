#!/usr/bin/env python3
"""Produce exact MP-SPDZ ExpandMask attempts for the internal campaign.

The strict internal campaign backend consumes this directory shape:

  <attempt-root>/<case_id>/counter-<NNN>/manifest.json
  <attempt-root>/<case_id>/counter-<NNN>/kappa-<KKKKK>/Player-Data/Binary-Output-P0-0

This script prepares the exact case inputs, runs MP-SPDZ MAMA for each required
kappa, and writes the attempt-set manifests. It fails closed when the local
machine cannot safely run the requested party count.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:internal-campaign-expandmask-mpc-attempts:v1"
ATTEMPT_SET_SCHEMA = (
    "lattice-threshold-backend-p1:exact-expandmask-mpc-attempt-set:v1"
)
REQUEST_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-request:v1"
SEED_DOMAIN = b"lattice-threshold-backend-p1:internal-campaign-seed:v1"
DEFAULT_REQUEST = "artifacts/internal-aggregation-campaign/latest/request.json"
DEFAULT_OUT = "artifacts/internal-aggregation-campaign-expandmask-mpc-attempts/latest"
PROGRAM = "mldsa65_expandmask"
FIELD_PRIME = 8_380_417
COMPONENTS = 5
COEFFICIENTS = 256
KAPPA_STEP = 5
VALIDATOR_COUNT = 10_000
THRESHOLD = 6_667


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def domain_digest(label, seed, request_sha256, case_id):
    hasher = hashlib.sha3_256()
    hasher.update(SEED_DOMAIN)
    hasher.update(label)
    hasher.update(seed)
    hasher.update(request_sha256.encode("ascii"))
    hasher.update(case_id.encode("ascii"))
    return hasher.digest()


def decode_message(case):
    message = case.get("message", {})
    encoding = message.get("encoding")
    value = message.get("value")
    if encoding == "hex":
        return bytes.fromhex(value), value.lower()
    if encoding == "utf8":
        raw = value.encode("utf-8")
        return raw, raw.hex()
    raise ValueError(f"case {case.get('case_id')} has unsupported message encoding")


def load_request(path):
    request = json.loads(Path(path).read_text(encoding="utf-8"))
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("internal campaign request schema mismatch")
    topology = request.get("topology", {})
    if (
        topology.get("validator_count") != VALIDATOR_COUNT
        or topology.get("threshold") != THRESHOLD
    ):
        raise ValueError("internal campaign request topology mismatch")
    if len(request.get("cases", [])) != 24:
        raise ValueError("internal campaign request must contain 24 cases")
    return request


def required_cases(request, selected_case_ids=None):
    cases = [
        case
        for case in request["cases"]
        if case.get("case_kind") in {"accepted", "retry"}
    ]
    if selected_case_ids:
        selected = set(selected_case_ids)
        cases = [case for case in cases if case.get("case_id") in selected]
    return cases


def validators_csv(count):
    return ",".join(str(value) for value in range(1, count + 1))


def kappas_for_rejections(rejected_attempts):
    return [attempt * KAPPA_STEP for attempt in range(rejected_attempts + 1)]


def command_result(command, cwd, timeout_seconds, env=None):
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate()
        timed_out = True
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": process.returncode,
        "duration_seconds": time.monotonic() - started,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
    }


def small_driver_command(args, subcommand):
    if args.small_driver_bin:
        return [str(Path(args.small_driver_bin).resolve()), subcommand]
    return [
        "cargo",
        "run",
        "--quiet",
        "--features",
        "raw-real-mldsa",
        "--bin",
        "small_distributed_aggregation",
        "--",
        subcommand,
    ]


def emit_inputs(args, case, request_sha256, seed, counter, work_dir):
    case_id = case["case_id"]
    case_seed = domain_digest(b"keygen-seed", seed, request_sha256, case_id)
    rnd = domain_digest(
        b"sign-rnd", seed, request_sha256, f"{case_id}:{counter}"
    )
    _message, message_hex = decode_message(case)
    command = small_driver_command(args, "emit-inputs") + [
        "--seed",
        case_seed.hex(),
        "--rnd",
        rnd.hex(),
        "--message-hex",
        message_hex,
        "--threshold",
        str(args.signers),
        "--validators",
        validators_csv(args.validator_count),
        "--run-dir",
        str(work_dir),
    ]
    result = command_result(
        command,
        cwd=args.root,
        timeout_seconds=args.preflight_timeout_seconds,
        env=os.environ.copy(),
    )
    params_path = work_dir / "params.json"
    params = None
    if result["exit_code"] == 0 and params_path.is_file():
        params = json.loads(params_path.read_text(encoding="utf-8"))
    return result, params


def sync_mp_spdz_source(args):
    repo_source = args.root / "mpc" / "Programs" / "Source" / f"{PROGRAM}.mpc"
    mp_spdz_source = args.mp_spdz_root / "Programs" / "Source" / f"{PROGRAM}.mpc"
    if not repo_source.is_file():
        raise FileNotFoundError(f"repo MPC source missing: {repo_source}")
    mp_spdz_source.parent.mkdir(parents=True, exist_ok=True)
    copied = False
    repo_bytes = repo_source.read_bytes()
    if not mp_spdz_source.is_file() or mp_spdz_source.read_bytes() != repo_bytes:
        mp_spdz_source.write_bytes(repo_bytes)
        copied = True
    return {
        "repo_source": str(repo_source),
        "repo_source_sha256": sha256_bytes(repo_bytes),
        "mp_spdz_source": str(mp_spdz_source),
        "copied_to_mp_spdz": copied,
    }


def copy_compiled_program(args, program_name):
    copied = []
    for subdir, pattern in (
        ("Schedules", f"{program_name}.sch"),
        ("Bytecode", f"{program_name}-*.bc"),
    ):
        source_dir = args.mp_spdz_root / "Programs" / subdir
        target_dir = args.root / "mpc" / "Programs" / subdir
        target_dir.mkdir(parents=True, exist_ok=True)
        for source in sorted(source_dir.glob(pattern)):
            target = target_dir / source.name
            shutil.copy2(source, target)
            copied.append(str(target))
    return copied


def compile_program(args, kappa_base):
    program_name = (
        f"{PROGRAM}-{args.signers}-{kappa_base}-{COMPONENTS}-{COEFFICIENTS}"
    )
    schedule = (
        args.root
        / "mpc"
        / "Programs"
        / "Schedules"
        / f"{program_name}.sch"
    )
    if schedule.is_file() or not args.compile_missing:
        return {
            "program_name": program_name,
            "schedule": str(schedule),
            "schedule_present": schedule.is_file(),
            "compile_result": None,
            "source_sync": None,
            "copied_program_files": [],
        }
    source_sync = sync_mp_spdz_source(args)
    command = [
        str(args.mp_spdz_root / "compile.py"),
        "-M",
        "-X",
        "-P",
        str(FIELD_PRIME),
        PROGRAM,
        str(args.signers),
        str(kappa_base),
        str(COMPONENTS),
        str(COEFFICIENTS),
    ]
    result = command_result(
        command,
        cwd=args.mp_spdz_root,
        timeout_seconds=args.compile_timeout_seconds,
        env=os.environ.copy(),
    )
    copied_files = copy_compiled_program(args, program_name) if result["exit_code"] == 0 else []
    return {
        "program_name": program_name,
        "schedule": str(schedule),
        "schedule_present": schedule.is_file(),
        "compile_result": result,
        "source_sync": source_sync,
        "copied_program_files": copied_files,
    }


def copy_player_inputs(root, input_dir, run_dir):
    source = input_dir / "Player-Data"
    target = run_dir / "Player-Data"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    programs_link = run_dir / "Programs"
    if programs_link.exists() or programs_link.is_symlink():
        if programs_link.is_dir() and not programs_link.is_symlink():
            shutil.rmtree(programs_link)
        else:
            programs_link.unlink()
    programs_link.symlink_to(root / "mpc" / "Programs")


def launch_parties(args, run_dir, program_name, port):
    runtime = args.mp_spdz_root / args.runtime_binary
    env = os.environ.copy()
    library_paths = [str(args.mp_spdz_root), str(args.mp_spdz_root / "local/lib")]
    if env.get("DYLD_LIBRARY_PATH"):
        library_paths.append(env["DYLD_LIBRARY_PATH"])
    env["DYLD_LIBRARY_PATH"] = os.pathsep.join(library_paths)
    processes = []
    logs = []
    started = time.monotonic()
    try:
        for player in range(args.signers):
            log_path = run_dir / f"party-{player}.log"
            log = log_path.open("w", encoding="utf-8")
            logs.append(log)
            command = [
                str(runtime),
                "-N",
                str(args.signers),
                "-pn",
                str(port),
                "-S",
                str(args.security_parameter),
                "-p",
                str(player),
                program_name,
            ]
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=run_dir,
                    env=env,
                    text=True,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            )
        exit_codes = []
        for process in processes:
            remaining = max(
                1, args.mpc_timeout_seconds - (time.monotonic() - started)
            )
            exit_codes.append(process.wait(timeout=remaining))
        timed_out = False
    except subprocess.TimeoutExpired:
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        exit_codes = [process.returncode for process in processes]
        timed_out = True
    finally:
        for log in logs:
            log.close()
    return {
        "exit_codes": exit_codes,
        "timed_out": timed_out,
        "duration_seconds": time.monotonic() - started,
    }


def output_records(run_dir, signers):
    records = []
    hasher = hashlib.sha256()
    for player in range(signers):
        path = run_dir / "Player-Data" / f"Binary-Output-P{player}-0"
        if not path.is_file():
            records.append({"player": player, "present": False})
            continue
        raw = path.read_bytes()
        digest = sha256_bytes(raw)
        hasher.update(player.to_bytes(4, "little"))
        hasher.update(raw)
        records.append(
            {
                "player": player,
                "present": True,
                "byte_length": len(raw),
                "sha256": digest,
            }
        )
    return records, hasher.hexdigest()


def copy_execution_outputs(source_dir, target_dir):
    player_data = target_dir / "Player-Data"
    if player_data.exists():
        shutil.rmtree(player_data)
    shutil.copytree(source_dir / "Player-Data", player_data)
    for log_path in sorted(source_dir.glob("party-*.log")):
        shutil.copy2(log_path, target_dir / log_path.name)


def run_kappa(args, counter_dir, input_dir, kappa_base, case_index, kappa_index):
    run_dir = counter_dir / f"kappa-{kappa_base:05d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    compiled = compile_program(args, kappa_base)
    blockers = []
    runtime = args.mp_spdz_root / args.runtime_binary
    if not runtime.is_file():
        blockers.append(f"MP-SPDZ runtime missing: {runtime}")
    if not compiled["schedule_present"]:
        blockers.append(f"compiled schedule missing: {compiled['schedule']}")
    if args.signers > args.max_local_parties and not args.allow_large_local_run:
        blockers.append(
            f"local party count {args.signers} exceeds safe limit "
            f"{args.max_local_parties}; use a multi-host runner or pass "
            "--allow-large-local-run explicitly"
        )

    execution = None
    execution_attempts = []
    if not blockers:
        for launch_index in range(getattr(args, "mpc_launch_retries", 0) + 1):
            exec_root = Path(
                tempfile.mkdtemp(prefix=f"campaign-mpc-{kappa_base:05d}-")
            )
            copy_player_inputs(args.root, input_dir, exec_root)
            port = args.port_base + case_index * 100 + kappa_index * 10 + launch_index
            execution = launch_parties(args, exec_root, compiled["program_name"], port)
            execution["launch_index"] = launch_index
            execution["port"] = port
            copy_execution_outputs(exec_root, run_dir)
            if not args.keep_execution_dirs:
                shutil.rmtree(exec_root, ignore_errors=True)
            else:
                execution["execution_dir"] = str(exec_root)
            execution_attempts.append(execution)
            exited_zero = len(execution["exit_codes"]) == args.signers and all(
                code == 0 for code in execution["exit_codes"]
            )
            if not execution["timed_out"] and exited_zero:
                break
            if launch_index < getattr(args, "mpc_launch_retries", 0):
                time.sleep(getattr(args, "inter_attempt_delay_seconds", 0))
        if execution is not None and execution["timed_out"]:
            blockers.append("MP-SPDZ party execution timed out")
        if execution is None or len(execution["exit_codes"]) != args.signers or any(
            code != 0 for code in execution["exit_codes"]
        ):
            blockers.append("one or more MP-SPDZ parties exited nonzero")

    records, transcript_digest = output_records(run_dir, args.signers)
    all_outputs_present = all(record.get("present") for record in records)
    if not all_outputs_present:
        blockers.append("one or more MP-SPDZ Binary-Output files is missing")

    attempt = {
        "kappa_base": kappa_base,
        "binary_output_dir": f"kappa-{kappa_base:05d}/Player-Data",
        "transcript_digest_hex": transcript_digest,
        "malicious_mpc_verified": not blockers,
        "all_mpc_parties_exited_zero": not blockers,
        "mac_check_passed": not blockers,
        "execution": execution,
        "execution_attempts": execution_attempts,
        "execution_dir_preserved": args.keep_execution_dirs,
        "execution_dir": (
            execution.get("execution_dir")
            if execution is not None and args.keep_execution_dirs
            else None
        ),
        "compile": compiled,
        "private_output_records": records,
        "blockers": blockers,
    }
    return attempt


def sign_attempt_set(args, case, counter_dir, params, kappa_bases):
    command = small_driver_command(args, "sign") + [
        "--seed",
        params["seed_hex"],
        "--rnd",
        params["rnd_hex"],
        "--message-hex",
        case["message"]["value"],
        "--threshold",
        str(args.signers),
        "--validators",
        validators_csv(args.validator_count),
        "--run-dir",
        str(counter_dir),
        "--kappa-list",
        ",".join(str(kappa) for kappa in kappa_bases),
        "--malicious-verified",
        "true",
    ]
    result = command_result(
        command,
        cwd=args.root,
        timeout_seconds=args.signature_timeout_seconds,
        env=os.environ.copy(),
    )
    parsed = None
    blockers = []
    if result["exit_code"] != 0:
        blockers.append("small distributed signature check exited nonzero")
    try:
        parsed = json.loads(result["stdout"])
    except json.JSONDecodeError:
        blockers.append("small distributed signature check did not emit JSON")
    if parsed is not None:
        if parsed.get("result") != "accepted":
            blockers.append("small distributed signature check did not accept")
        if parsed.get("standard_verifier_accepted") is not True:
            blockers.append("standard ML-DSA verifier did not accept")
        if parsed.get("signature_len") != 3309:
            blockers.append("signature length is not 3309")
        if parsed.get("additive_mask_outputs_consumed") is not True:
            blockers.append("MPC mask outputs were not consumed")
    return {
        "command": result["command"],
        "exit_code": result["exit_code"],
        "duration_seconds": result["duration_seconds"],
        "timed_out": result["timed_out"],
        "stdout_tail": result["stdout"][-4000:],
        "stderr_tail": result["stderr"][-4000:],
        "parsed": parsed,
        "blockers": blockers,
    }


def choose_counter(args, case, request_sha256, seed):
    want_retry = case.get("case_kind") == "retry"
    probes = []
    with tempfile.TemporaryDirectory(prefix="campaign-mpc-preflight-") as temp:
        temp_root = Path(temp)
        for counter in range(args.max_counter_search):
            work_dir = temp_root / f"counter-{counter:03}"
            result, params = emit_inputs(
                args, case, request_sha256, seed, counter, work_dir
            )
            rejected = None if params is None else params.get("local_rejected_attempts")
            probes.append(
                {
                    "counter": counter,
                    "exit_code": result["exit_code"],
                    "timed_out": result["timed_out"],
                    "local_rejected_attempts": rejected,
                    "stdout_tail": result["stdout"][-1000:],
                    "stderr_tail": result["stderr"][-1000:],
                }
            )
            if result["exit_code"] != 0 or params is None:
                continue
            if (want_retry and rejected > 0) or (not want_retry and rejected == 0):
                selected = {
                    "counter": counter,
                    "params": params,
                    "kappas": kappas_for_rejections(rejected),
                    "seed_hex": domain_digest(
                        b"keygen-seed", seed, request_sha256, case["case_id"]
                    ).hex(),
                    "rnd_hex": domain_digest(
                        b"sign-rnd",
                        seed,
                        request_sha256,
                        f"{case['case_id']}:{counter}",
                    ).hex(),
                    "probes": probes,
                }
                return selected
    return {"probes": probes, "blockers": ["no matching counter found"]}


def build_attempts(args):
    request = load_request(args.request)
    request_json = canonical_json(request)
    request_sha256 = sha256_bytes(request_json.encode("utf-8"))
    seed = bytes.fromhex(args.seed_hex)
    if len(seed) != 32:
        raise ValueError("--seed-hex must decode to 32 bytes")

    out = args.out
    attempt_root = args.attempt_root or (out / "attempts")
    if attempt_root.exists():
        shutil.rmtree(attempt_root)
    attempt_root.mkdir(parents=True, exist_ok=True)

    case_reports = []
    blockers = []
    required = required_cases(request, args.case_id)
    for case_index, case in enumerate(required):
        case_id = case["case_id"]
        case_dir = attempt_root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        selected = choose_counter(args, case, request_sha256, seed)
        if selected.get("blockers"):
            blockers.extend(f"{case_id}: {item}" for item in selected["blockers"])
            case_reports.append({"case_id": case_id, **selected})
            continue

        counter = selected["counter"]
        counter_dir = case_dir / f"counter-{counter:03}"
        counter_dir.mkdir(parents=True, exist_ok=True)
        input_dir = counter_dir / "input-binding"
        input_result, params = emit_inputs(
            args, case, request_sha256, seed, counter, input_dir
        )
        if input_result["exit_code"] != 0 or params is None:
            blockers.append(
                f"{case_id}/counter-{counter:03}: durable input emission failed"
            )
            case_reports.append(
                {
                    "case_id": case_id,
                    "case_kind": case["case_kind"],
                    "counter": counter,
                    "input_emission": input_result,
                    "probes": selected["probes"],
                }
            )
            continue

        attempts = []
        for kappa_index, kappa_base in enumerate(selected["kappas"]):
            attempt = run_kappa(
                args,
                counter_dir,
                input_dir,
                kappa_base,
                case_index,
                kappa_index,
            )
            attempts.append(attempt)
            blockers.extend(
                f"{case_id}/counter-{counter:03}/kappa-{kappa_base:05d}: {item}"
                for item in attempt["blockers"]
            )
            time.sleep(args.inter_attempt_delay_seconds)

        attempt_set = {
            "schema": ATTEMPT_SET_SCHEMA,
            "case_id": case_id,
            "counter": counter,
            "signer_count": args.signers,
            "request_sha256": request_sha256,
            "case_kind": case["case_kind"],
            "kappa_bases": selected["kappas"],
            "attempts": [
                {
                    "kappa_base": attempt["kappa_base"],
                    "binary_output_dir": attempt["binary_output_dir"],
                    "transcript_digest_hex": attempt["transcript_digest_hex"],
                    "malicious_mpc_verified": attempt["malicious_mpc_verified"],
                    "all_mpc_parties_exited_zero": attempt[
                        "all_mpc_parties_exited_zero"
                    ],
                    "mac_check_passed": attempt["mac_check_passed"],
                }
                for attempt in attempts
            ],
        }
        (counter_dir / "manifest.json").write_text(
            canonical_json(attempt_set), encoding="utf-8"
        )
        signature_check = None
        if not args.skip_signature_check and not any(
            attempt["blockers"] for attempt in attempts
        ):
            signature_check = sign_attempt_set(
                args, case, counter_dir, params, selected["kappas"]
            )
            (counter_dir / "signature-check.json").write_text(
                canonical_json(signature_check), encoding="utf-8"
            )
            blockers.extend(
                f"{case_id}/counter-{counter:03}/signature-check: {item}"
                for item in signature_check["blockers"]
            )
        case_report = {
            "case_id": case_id,
            "case_kind": case["case_kind"],
            "counter": counter,
            "kappa_bases": selected["kappas"],
            "local_rejected_attempts": selected["params"][
                "local_rejected_attempts"
            ],
            "attempt_set_manifest": str(counter_dir / "manifest.json"),
            "signature_check": signature_check,
            "attempts": attempts,
            "probes": selected["probes"],
        }
        case_reports.append(case_report)

    complete = not blockers and len(case_reports) == len(required)
    manifest = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request_path": str(args.request),
        "request_sha256": request_sha256,
        "attempt_root": str(attempt_root),
        "mp_spdz": {
            "root": str(args.mp_spdz_root),
            "runtime_binary": args.runtime_binary,
            "runtime_sha256": sha256_path(args.mp_spdz_root / args.runtime_binary),
        },
        "target": {
            "validator_count": args.validator_count,
            "threshold": THRESHOLD,
            "signer_count": args.signers,
            "full_campaign_signer_count": args.signers == THRESHOLD,
        },
        "case_count": len(case_reports),
        "required_case_count": len(required),
        "cases": case_reports,
        "attempt_sets_complete": complete,
        "strict_campaign_compatible": complete and args.signers == THRESHOLD,
        "blockers": blockers,
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_distribution_compatibility_proven": False,
            "claims_production_threshold_mldsa_security": False,
        },
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    (args.out / "SHA256SUMS").write_text(
        f"{sha256_bytes(canonical_json(manifest).encode('utf-8'))}  manifest.json\n",
        encoding="utf-8",
    )
    return manifest


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run exact MP-SPDZ ExpandMask attempts for the internal campaign"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--request", default=DEFAULT_REQUEST)
    parser.add_argument(
        "--mp-spdz-root",
        default=os.environ.get("MP_SPDZ_ROOT", "/Users/rickglenn/Documents/MP-SPDZ"),
    )
    parser.add_argument("--runtime-binary", default="mama-party.x")
    parser.add_argument("--small-driver-bin", default=None)
    parser.add_argument("--seed-hex", default="71" * 32)
    parser.add_argument("--validator-count", type=int, default=VALIDATOR_COUNT)
    parser.add_argument("--signers", type=int, default=THRESHOLD)
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="restrict execution to one accepted/retry campaign case; repeatable",
    )
    parser.add_argument("--max-counter-search", type=int, default=64)
    parser.add_argument("--preflight-timeout-seconds", type=int, default=600)
    parser.add_argument("--mpc-timeout-seconds", type=int, default=1800)
    parser.add_argument("--mpc-launch-retries", type=int, default=1)
    parser.add_argument("--inter-attempt-delay-seconds", type=float, default=5.0)
    parser.add_argument("--compile-timeout-seconds", type=int, default=1800)
    parser.add_argument("--signature-timeout-seconds", type=int, default=600)
    parser.add_argument("--security-parameter", type=int, default=40)
    parser.add_argument("--port-base", type=int, default=19000)
    parser.add_argument("--max-local-parties", type=int, default=64)
    parser.add_argument("--allow-large-local-run", action="store_true")
    parser.add_argument("--compile-missing", action="store_true")
    parser.add_argument("--keep-execution-dirs", action="store_true")
    parser.add_argument("--skip-signature-check", action="store_true")
    parser.add_argument("--attempt-root", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path(DEFAULT_OUT))
    args = parser.parse_args(argv)
    args.root = Path(args.root).resolve()
    args.request = Path(args.request).resolve()
    args.mp_spdz_root = Path(args.mp_spdz_root).resolve()
    args.out = Path(args.out).resolve()
    if args.validator_count != VALIDATOR_COUNT:
        raise ValueError("--validator-count must be 10000 for this campaign")
    if args.signers < 2:
        raise ValueError("--signers must be at least 2")
    return args


def main(argv=None):
    manifest = build_attempts(parse_args(argv))
    print("attempt_sets_complete=" + str(manifest["attempt_sets_complete"]).lower())
    print(
        "strict_campaign_compatible="
        + str(manifest["strict_campaign_compatible"]).lower()
    )
    if manifest["blockers"]:
        print("blockers=" + str(len(manifest["blockers"])))
    return 0 if manifest["attempt_sets_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
