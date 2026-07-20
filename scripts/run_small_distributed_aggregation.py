#!/usr/bin/env python3
"""Run a small, genuinely-distributed threshold ML-DSA-65 aggregation.

This orchestrator drives a REAL 3-party MP-SPDZ MAMA (malicious,
dishonest-majority) `mldsa65_expandmask` circuit and feeds its real per-party
additive-mask outputs into the custody distributed Sign_internal path, then runs
the standard ML-DSA verifier on the produced signature.

Honesty boundary (all encoded in the emitted manifest):

  * N = 3 real parties, threshold 3, over validators [0,1,2,3] (signing set is
    the first 3). Real distributed masks; the threshold key is a trusted-setup
    secret DEALT then Shamir-shared. This is NOT dealerless, NOT no-single-secret,
    NOT production, NOT the 6,667-signer scale.
  * `standard_verifier_accepted` and the signature come from a real
    `verify_standard` call on the real produced signature — never fabricated.
  * `malicious_verified` is set True only when every party log is clean
    (exit 0, no abort / MAC-failure, completion marker present).

Usage:
    export MP_SPDZ_ROOT=$HOME/Documents/MP-SPDZ
    export DYLD_LIBRARY_PATH=$HOME/Documents/MP-SPDZ:$HOME/Documents/MP-SPDZ/local/lib
    python3 scripts/run_small_distributed_aggregation.py \
        --mp-spdz-root ~/Documents/MP-SPDZ --runtime-binary mama-party.x
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:real-small-distributed-aggregation:v1"
PROGRAM = "mldsa65_expandmask"
PROGRAM_SOURCE = "mpc/Programs/Source/mldsa65_expandmask.mpc"
FIELD_PRIME = 8_380_417
COMPONENTS = 5
COEFFICIENTS = 256
COEFF_COUNT = COMPONENTS * COEFFICIENTS  # 1280
BINARY_OUTPUT_BYTE_LEN = COEFF_COUNT * 8  # 10240
BINARY = "small_distributed_aggregation"

# Failure markers that must be ABSENT from a clean malicious-MPC party log.
FAILURE_MARKERS = (
    "abort",
    "mac check",
    "mac_check",
    "maccheck",
    "security violation",
    "not enough",
    "exception",
    "traceback",
    "segmentation",
    "what():",
    "terminate called",
    "assertion",
    "invalid",
)
COMPLETION_MARKER = "mldsa65_expandmask_complete"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def command_value(command, cwd):
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def run_cargo(root, subcommand_args, timeout_seconds):
    """Invoke the emit-inputs / sign subcommand via cargo run."""
    command = [
        "cargo",
        "run",
        "--quiet",
        "--features",
        "raw-real-mldsa",
        "--bin",
        BINARY,
        "--",
    ] + subcommand_args
    completed = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )
    return completed.returncode, completed.stdout, completed.stderr


def compile_circuit(root, mp_spdz_root, signers, kappa, timeout_seconds):
    """Compile mldsa65_expandmask for (signers, kappa, 5, 256) if missing.

    The compiled schedule/bytecode live under the MP-SPDZ root's own Programs
    directory (that is where the already-compiled N=3 kappa=0 circuit sits and
    where the run dir's Programs symlink points). Compiling from the MP-SPDZ
    root cwd also avoids the ambiguous-input-file error you get from the repo
    mpc dir, since both trees carry a byte-identical source copy.
    """
    program_name = f"{PROGRAM}-{signers}-{kappa}-{COMPONENTS}-{COEFFICIENTS}"
    schedule = mp_spdz_root / "Programs/Schedules" / f"{program_name}.sch"
    if schedule.is_file():
        return program_name, True, "schedule already present", 0.0
    compiler = mp_spdz_root / "compile.py"
    command = [
        str(compiler),
        "-M",
        "-X",
        "-P",
        str(FIELD_PRIME),
        PROGRAM,
        str(signers),
        str(kappa),
        str(COMPONENTS),
        str(COEFFICIENTS),
    ]
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=mp_spdz_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout_seconds)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        output, _ = process.communicate()
        exit_code = 124
    duration = time.monotonic() - started
    return program_name, (exit_code == 0 and schedule.is_file()), output, duration


def stop_processes(processes):
    for process in processes:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for process in processes:
        if process.poll() is None:
            process.wait()


def run_parties(runtime, run_dir, program_name, signers, port, timeout_seconds,
                security_parameter, direct, batch_size):
    """Reuse run_exact_expandmask_mpc_equivalence.run_parties' shape.

    `direct=True` uses point-to-point (`--direct`) rather than star-shaped
    communication routed through party 0. On macOS the star topology relays
    party-i<->party-j OT traffic through party 0 and desyncs the base OT under
    buffer pressure for N>=3, so direct communication is the reliable path here.
    """
    environment = os.environ.copy()
    library_paths = [str(runtime.parent), str(runtime.parent / "local/lib")]
    if environment.get("DYLD_LIBRARY_PATH"):
        library_paths.append(environment["DYLD_LIBRARY_PATH"])
    environment["DYLD_LIBRARY_PATH"] = os.pathsep.join(library_paths)
    processes = []
    logs = []
    started = time.monotonic()
    try:
        for player in range(signers):
            log = (run_dir / f"party-{player}.log").open("w", encoding="utf-8")
            logs.append(log)
            command = [str(runtime), "-N", str(signers), "-pn", str(port)]
            if security_parameter is not None:
                command.extend(["-S", str(security_parameter)])
            if direct:
                command.append("--direct")
            if batch_size is not None:
                command.extend(["-b", str(batch_size)])
            command.extend(["-p", str(player), program_name])
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=run_dir,
                    env=environment,
                    text=True,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            )
        exit_codes = []
        for process in processes:
            remaining = max(1, timeout_seconds - (time.monotonic() - started))
            exit_codes.append(process.wait(timeout=remaining))
        timed_out = False
    except subprocess.TimeoutExpired:
        stop_processes(processes)
        exit_codes = [process.returncode for process in processes]
        timed_out = True
    except KeyboardInterrupt:
        stop_processes(processes)
        raise
    finally:
        for log in logs:
            log.close()
    return exit_codes, timed_out, time.monotonic() - started


def setup_run_dir(root, mp_spdz_root, staging_player_data, kappa_dir, signers):
    """Create a per-kappa run dir: Programs symlink, Player-Data with the
    emit-inputs Input files plus the SSL certs from the MP-SPDZ root."""
    player_data = kappa_dir / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    programs_link = kappa_dir / "Programs"
    if not programs_link.exists():
        os.symlink(mp_spdz_root / "Programs", programs_link)
    # Copy the per-player Input files produced by emit-inputs.
    for player in range(signers):
        src = staging_player_data / f"Input-P{player}-0"
        shutil.copyfile(src, player_data / f"Input-P{player}-0")
    # Copy the generated SSL certs (keys, pems) and re-create the OpenSSL hash
    # symlinks exactly as they exist in the MP-SPDZ Player-Data directory.
    src_player_data = mp_spdz_root / "Player-Data"
    for entry in sorted(src_player_data.iterdir()):
        name = entry.name
        if entry.is_symlink():
            target = os.readlink(entry)
            dst = player_data / name
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            os.symlink(target, dst)
        elif entry.is_file() and (name.endswith(".pem") or name.endswith(".key")):
            shutil.copyfile(entry, player_data / name)
    return player_data


def collect_outputs(player_data, signers):
    records = []
    shares = []
    all_present = True
    for player in range(signers):
        path = player_data / f"Binary-Output-P{player}-0"
        raw = path.read_bytes() if path.is_file() else b""
        present = path.is_file() and len(raw) == BINARY_OUTPUT_BYTE_LEN
        all_present = all_present and present
        records.append(
            {
                "player": player,
                "present": path.is_file(),
                "byte_length": len(raw),
                "sha256": sha256_bytes(raw) if raw else None,
            }
        )
        if len(raw) == BINARY_OUTPUT_BYTE_LEN:
            shares.append(struct.unpack("<" + "q" * COEFF_COUNT, raw))
    reconstructed_ok = None
    if len(shares) == signers:
        reconstructed = [sum(values) % FIELD_PRIME for values in zip(*shares)]
        reconstructed_ok = len(reconstructed) == COEFF_COUNT
    return records, all_present, reconstructed_ok


def log_is_clean(log_path):
    """A party log is clean iff it has no malicious-abort / MAC-failure marker.

    The `mldsa65_expandmask_complete` completion line is emitted by MP-SPDZ
    `print_ln` on party 0 ONLY, so it is checked once at the run level
    (`completion_seen`), not per party.
    """
    if not log_path.is_file():
        return False, "log missing", ""
    text = log_path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    for marker in FAILURE_MARKERS:
        if marker in lowered:
            return False, f"failure marker '{marker}' present", text[-2000:]
    return True, "clean", text[-2000:]


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def build_and_run(args):
    started_wall = time.monotonic()
    root = Path(args.root).resolve()
    mp_spdz_root = Path(args.mp_spdz_root).expanduser().resolve()
    runtime = mp_spdz_root / args.runtime_binary
    out_dir = root / "artifacts/real-small-distributed-aggregation" / args.out_name
    out_dir.mkdir(parents=True, exist_ok=True)

    steps = []

    def note(stage, **fields):
        entry = {"stage": stage, **fields}
        steps.append(entry)
        print(f"[{stage}] " + " ".join(f"{k}={v}" for k, v in fields.items()), flush=True)

    if not runtime.is_file():
        note("preflight", error=f"runtime binary missing: {runtime}")
        return finalize(args, root, mp_spdz_root, out_dir, steps, None, started_wall, failure="runtime missing")

    # --- Step 1: emit-inputs, selecting a seed that accepts at kappa_base=0 ---
    staging = out_dir
    candidate_seeds = [args.seed] + [f"{n:064x}" for n in range(1, args.seed_pool)]
    candidate_rnd = args.rnd
    chosen = None
    for seed_hex in candidate_seeds:
        emit_args = [
            "emit-inputs",
            "--seed", seed_hex,
            "--rnd", candidate_rnd,
            "--message", args.message,
            "--threshold", str(args.threshold),
            "--validators", args.validators,
            "--run-dir", str(staging),
        ]
        code, stdout, stderr = run_cargo(root, emit_args, args.cargo_timeout_seconds)
        if code != 0:
            note("emit-inputs", seed=seed_hex[:8], exit_code=code, error=stderr.strip()[-400:])
            continue
        params = json.loads((staging / "params.json").read_text())
        accepted = params["local_accepted_kappa_base"]
        note("emit-inputs", seed=seed_hex[:8], local_rejected=params["local_rejected_attempts"],
             local_accepted_kappa_base=accepted)
        if args.min_accepted_kappa <= accepted <= args.max_accepted_kappa:
            chosen = (seed_hex, params)
            break
    if chosen is None:
        return finalize(args, root, mp_spdz_root, out_dir, steps, None, started_wall,
                        failure="no seed accepted within [min_accepted_kappa, max_accepted_kappa]")
    seed_hex, params = chosen
    step = params["kappa_step"]
    accepted_kappa = params["local_accepted_kappa_base"]
    kappa_list = list(range(0, accepted_kappa + 1, step))
    note("plan", chosen_seed=seed_hex[:8], accepted_kappa=accepted_kappa, kappa_list=kappa_list)

    staging_player_data = staging / "Player-Data"

    # --- Step 2: per-kappa compile + real 3-party MPC run ---
    per_kappa = []
    all_clean = True
    for index, kappa in enumerate(kappa_list):
        program_name, compiled, compile_log, compile_duration = compile_circuit(
            root, mp_spdz_root, args.threshold, kappa, args.compile_timeout_seconds
        )
        note("compile", kappa=kappa, program=program_name, compiled=compiled,
             duration_s=round(compile_duration, 1))
        if not compiled:
            (out_dir / f"compile-kappa-{kappa}.log").write_text(compile_log, encoding="utf-8")
            all_clean = False
            per_kappa.append({"kappa": kappa, "program": program_name, "compiled": False})
            break

        kappa_dir = out_dir / f"kappa-{kappa}"
        if kappa_dir.exists():
            shutil.rmtree(kappa_dir)
        player_data = setup_run_dir(root, mp_spdz_root, staging_player_data, kappa_dir, args.threshold)

        port = args.port + index * 10
        exit_codes, timed_out, duration = run_parties(
            runtime, kappa_dir, program_name, args.threshold, port,
            args.run_timeout_seconds, args.security_parameter,
            args.direct, args.batch_size,
        )
        records, all_present, reconstructed_ok = collect_outputs(player_data, args.threshold)

        clean_flags = []
        log_tails = {}
        completion_seen = False
        for player in range(args.threshold):
            log_path = kappa_dir / f"party-{player}.log"
            ok, reason, tail = log_is_clean(log_path)
            clean_flags.append(ok)
            log_tails[str(player)] = {"clean": ok, "reason": reason}
            if log_path.is_file() and COMPLETION_MARKER in log_path.read_text(
                encoding="utf-8", errors="replace"
            ):
                completion_seen = True
        exits_zero = len(exit_codes) == args.threshold and all(code == 0 for code in exit_codes)
        kappa_clean = (
            exits_zero and (not timed_out) and all_present
            and all(clean_flags) and completion_seen
        )
        all_clean = all_clean and kappa_clean

        note("mpc-run", kappa=kappa, exit_codes=exit_codes, timed_out=timed_out,
             all_outputs_present=all_present, logs_clean=all(clean_flags),
             completion_seen=completion_seen, reconstruct_ok=reconstructed_ok,
             duration_s=round(duration, 1))

        per_kappa.append({
            "kappa": kappa,
            "program": program_name,
            "compiled": True,
            "port": port,
            "exit_codes": exit_codes,
            "timed_out": timed_out,
            "duration_seconds": duration,
            "all_outputs_present": all_present,
            "reconstructed_coefficient_count_ok": reconstructed_ok,
            "party_logs_clean": clean_flags,
            "completion_marker_seen": completion_seen,
            "party_log_status": log_tails,
            "clean": kappa_clean,
            "binary_output_sha256": [r["sha256"] for r in records],
            "private_outputs": records,
        })
        if not kappa_clean:
            break

    malicious_verified = all_clean and len(per_kappa) == len(kappa_list) and all(
        entry.get("clean") for entry in per_kappa
    )
    note("malicious-verified", value=malicious_verified,
         basis="all party logs clean, exits 0, outputs present, no abort/MAC")

    if not all(entry.get("clean") for entry in per_kappa) or len(per_kappa) != len(kappa_list):
        return finalize(args, root, mp_spdz_root, out_dir, steps, {
            "per_kappa": per_kappa, "seed_hex": seed_hex, "kappa_list": kappa_list,
            "params": params, "malicious_verified": malicious_verified,
        }, started_wall, failure="one or more MPC runs were not clean")

    # --- Step 3: sign, consuming the real MPC outputs ---
    kappa_arg = ",".join(str(k) for k in kappa_list)
    sign_args = [
        "sign",
        "--seed", seed_hex,
        "--rnd", candidate_rnd,
        "--message", args.message,
        "--threshold", str(args.threshold),
        "--validators", args.validators,
        "--run-dir", str(out_dir),
        "--kappa-list", kappa_arg,
        "--malicious-verified", "true" if malicious_verified else "false",
    ]
    code, stdout, stderr = run_cargo(root, sign_args, args.cargo_timeout_seconds)
    (out_dir / "sign-stdout.json").write_text(stdout, encoding="utf-8")
    if stderr.strip():
        (out_dir / "sign-stderr.log").write_text(stderr, encoding="utf-8")
    sign_json = None
    try:
        # The JSON object is the last brace-delimited block on stdout.
        first = stdout.index("{")
        last = stdout.rindex("}")
        sign_json = json.loads(stdout[first:last + 1])
    except (ValueError, json.JSONDecodeError):
        sign_json = None
    note("sign", exit_code=code, parsed=sign_json is not None,
         result=(sign_json or {}).get("result"),
         standard_verifier_accepted=(sign_json or {}).get("standard_verifier_accepted"))

    return finalize(args, root, mp_spdz_root, out_dir, steps, {
        "per_kappa": per_kappa, "seed_hex": seed_hex, "kappa_list": kappa_list,
        "params": params, "malicious_verified": malicious_verified,
        "sign_exit_code": code, "sign_json": sign_json, "sign_stderr": stderr.strip()[-1000:],
    }, started_wall, failure=None if code == 0 else "sign subcommand returned non-zero")


def finalize(args, root, mp_spdz_root, out_dir, steps, payload, started_wall, failure):
    wall_seconds = time.monotonic() - started_wall
    runtime = mp_spdz_root / args.runtime_binary
    payload = payload or {}
    sign_json = payload.get("sign_json") or {}
    per_kappa = payload.get("per_kappa") or []
    malicious_verified = payload.get("malicious_verified", False)

    standard_verifier_accepted = bool(sign_json.get("standard_verifier_accepted")) and \
        sign_json.get("result") == "accepted"
    accepted_kappa = sign_json.get("accepted_kappa")
    signature_sha256 = sign_json.get("signature_sha256")
    no_single_secret = sign_json.get("no_single_secret_signing_path", False)

    real_distributed_mpc_masks = (
        args.runtime_binary in {"mama-party.x", "mascot-party.x"}
        and bool(per_kappa)
        and all(entry.get("clean") for entry in per_kappa)
        and malicious_verified
    )

    manifest = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "topology": {
            "real_parties_N": args.threshold,
            "threshold": args.threshold,
            "validators": [int(v) for v in args.validators.split(",")],
            "signing_set": "first 3 validators (party p <-> signing_set[p])",
            "components": COMPONENTS,
            "coefficients_per_component": COEFFICIENTS,
            "coefficient_count": COEFF_COUNT,
            "security_parameter": args.security_parameter,
        },
        "execution": {
            "runtime": str(runtime),
            "runtime_binary": args.runtime_binary,
            "runtime_profile": (
                "mama_multiple_mac_malicious_dishonest_majority_test_scale"
                if args.runtime_binary == "mama-party.x"
                else "other"
            ),
            "message": args.message,
            "chosen_seed_hex": payload.get("seed_hex"),
            "rnd_hex": args.rnd,
            "kappa_list": payload.get("kappa_list"),
            "mpc_runs": len(per_kappa),
            "wall_time_seconds": round(wall_seconds, 2),
        },
        "mp_spdz": {
            "root": str(mp_spdz_root),
            "commit": command_value(["git", "rev-parse", "HEAD"], mp_spdz_root),
        },
        "source": {
            "path": str(root / PROGRAM_SOURCE),
            "sha256": sha256_path(root / PROGRAM_SOURCE),
        },
        "per_kappa_mpc": [
            {
                "kappa": entry["kappa"],
                "program": entry.get("program"),
                "compiled": entry.get("compiled"),
                "exit_codes": entry.get("exit_codes"),
                "timed_out": entry.get("timed_out"),
                "all_outputs_present": entry.get("all_outputs_present"),
                "reconstructed_coefficient_count_ok": entry.get("reconstructed_coefficient_count_ok"),
                "party_logs_clean": entry.get("party_logs_clean"),
                "clean": entry.get("clean"),
                "binary_output_sha256": entry.get("binary_output_sha256"),
                "duration_seconds": round(entry.get("duration_seconds", 0.0), 2),
            }
            for entry in per_kappa
        ],
        "params": payload.get("params"),
        "sign": sign_json,
        "result": {
            "malicious_verified": malicious_verified,
            "accepted_kappa": accepted_kappa,
            "standard_verifier_accepted": standard_verifier_accepted,
            "signature_sha256": signature_sha256,
            "signature_len": sign_json.get("signature_len"),
            "end_to_end_linkage_digest_hex": sign_json.get("end_to_end_linkage_digest_hex"),
            "no_single_secret_signing_path": no_single_secret,
            "failure": failure,
        },
        "claim_flags": {
            # Honest FALSE flags — none of these are established by this run.
            "no_single_secret_signing_path": False,
            "dealerless_dkg": False,
            "production_custody": False,
            "theorem_closure": False,
            "6667_scale": False,
            # Honest TRUE flags — only when actually achieved this run.
            "real_distributed_mpc_masks": real_distributed_mpc_masks,
            "standard_verifier_accepted": standard_verifier_accepted,
            "dealt_then_shared_trusted_setup": True,
        },
        "claim_boundary": (
            "small-scale (3-party) real distributed masks + "
            "trusted-setup-dealt-then-shared threshold key; "
            "NOT dealerless, NOT no-single-secret, NOT production, NOT 6667-scale."
        ),
        "steps": steps,
    }

    content = canonical_json(manifest)
    (out_dir / "manifest.json").write_text(content, encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(
        f"{sha256_bytes(content.encode())}  manifest.json\n", encoding="utf-8"
    )

    print("\n==== SUMMARY ====", flush=True)
    print(f"real_distributed_mpc_masks   = {real_distributed_mpc_masks}")
    print(f"malicious_verified           = {malicious_verified}")
    print(f"accepted_kappa               = {accepted_kappa}")
    print(f"standard_verifier_accepted   = {standard_verifier_accepted}")
    print(f"signature_sha256             = {signature_sha256}")
    print(f"no_single_secret_signing_path= {no_single_secret}")
    print(f"wall_time_seconds            = {round(wall_seconds, 2)}")
    print(f"manifest                     = {out_dir / 'manifest.json'}")
    if failure:
        print(f"FAILURE                      = {failure}")

    ok = failure is None and standard_verifier_accepted and real_distributed_mpc_masks
    return 0 if ok else 2


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--mp-spdz-root",
        default=os.environ.get("MP_SPDZ_ROOT", str(Path.home() / "Documents/MP-SPDZ")),
    )
    parser.add_argument("--runtime-binary", default="mama-party.x")
    parser.add_argument("--seed", default="0" * 64)
    parser.add_argument("--rnd", default="0" * 64)
    parser.add_argument("--message", default="small distributed aggregation demo")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--validators", default="0,1,2,3")
    parser.add_argument("--security-parameter", type=int, default=40)
    parser.add_argument("--port", type=int, default=15300)
    parser.add_argument("--direct", dest="direct", action="store_true", default=True,
                        help="point-to-point comms (default; reliable for N>=3 on macOS)")
    parser.add_argument("--star", dest="direct", action="store_false",
                        help="star-shaped comms routed through party 0")
    parser.add_argument("--batch-size", type=int, default=None,
                        help="MP-SPDZ preprocessing batch size (-b); default unset")
    parser.add_argument("--out-name", default="latest",
                        help="artifact subdir under real-small-distributed-aggregation/")
    parser.add_argument("--seed-pool", type=int, default=32,
                        help="number of candidate seeds to sweep for the target rejection count")
    parser.add_argument("--min-accepted-kappa", type=int, default=0,
                        help="lower bound on accepted kappa_base; raise to force real rejections")
    parser.add_argument("--max-accepted-kappa", type=int, default=0,
                        help="max kappa_base the chosen seed may accept at (0 = first attempt)")
    parser.add_argument("--compile-timeout-seconds", type=int, default=2400)
    parser.add_argument("--run-timeout-seconds", type=int, default=2400)
    parser.add_argument("--cargo-timeout-seconds", type=int, default=1200)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    return build_and_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
