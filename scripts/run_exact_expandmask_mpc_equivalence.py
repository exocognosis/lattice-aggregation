#!/usr/bin/env python3
"""Run fail-closed functional equivalence evidence for MPC ExpandMask."""

import argparse
import hashlib
import json
import os
import signal
import struct
import subprocess
import tempfile
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:exact-expandmask-mpc-equivalence:v1"
DEFAULT_OUT = "artifacts/exact-distributed-expandmask-mpc/equivalence-latest"
PROGRAM = "mldsa65_expandmask"
PROGRAM_SOURCE = "mpc/Programs/Source/mldsa65_expandmask.mpc"
Q = 8_380_417
GAMMA1 = 1 << 19


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def command_value(command, cwd):
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def xor_shares(secret, count, label):
    shares = []
    aggregate = bytearray(len(secret))
    for player in range(count - 1):
        share = hashlib.shake_256(
            label + player.to_bytes(4, "little")
        ).digest(len(secret))
        shares.append(share)
        for index, value in enumerate(share):
            aggregate[index] ^= value
    shares.append(bytes(a ^ b for a, b in zip(secret, aggregate)))
    return shares


def fixture(signers):
    key = bytes(range(32))
    rnd = bytes(range(32, 64))
    mu = bytes(range(64, 128))
    key_shares = xor_shares(key, signers, b"mldsa-expandmask-key-share")
    rnd_shares = xor_shares(rnd, signers, b"mldsa-expandmask-rnd-share")
    return key, rnd, mu, key_shares, rnd_shares


def expected_expandmask(key, rnd, mu, kappa_base, components, coefficients):
    rhopp = hashlib.shake_256(key + rnd + mu).digest(64)
    expected = []
    packed_bytes = (coefficients * 20 + 7) // 8
    for component in range(components):
        nonce = kappa_base + component
        packed = hashlib.shake_256(
            rhopp + nonce.to_bytes(2, "little")
        ).digest(packed_bytes)
        packed_int = int.from_bytes(packed, "little")
        for coefficient in range(coefficients):
            encoded = (packed_int >> (20 * coefficient)) & ((1 << 20) - 1)
            expected.append((GAMMA1 - encoded) % Q)
    return rhopp, expected


def write_inputs(player_data, signers, key_shares, rnd_shares, mu):
    for player in range(signers):
        values = key_shares[player] + rnd_shares[player]
        if player == 0:
            values += mu
        (player_data / f"Input-P{player}-0").write_text(
            " ".join(str(value) for value in values) + "\n",
            encoding="ascii",
        )


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


def run_parties(
    runtime,
    run_dir,
    program_name,
    signers,
    port,
    timeout_seconds,
    security_parameter,
):
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
            log = (run_dir / f"party-{player}.log").open(
                "w", encoding="utf-8"
            )
            logs.append(log)
            command = [
                str(runtime),
                "-N",
                str(signers),
                "-pn",
                str(port),
            ]
            if security_parameter is not None:
                command.extend(["-S", str(security_parameter)])
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


def read_outputs(player_data, signers, expected_count):
    output_records = []
    shares = []
    for player in range(signers):
        path = player_data / f"Binary-Output-P{player}-0"
        raw = path.read_bytes() if path.is_file() else b""
        output_records.append(
            {
                "player": player,
                "present": path.is_file(),
                "byte_length": len(raw),
                "sha256": sha256_bytes(raw) if raw else None,
            }
        )
        if len(raw) == expected_count * 8:
            shares.append(struct.unpack("<" + "q" * expected_count, raw))
    if len(shares) != signers:
        return output_records, None
    return output_records, [sum(values) % Q for values in zip(*shares)]


def build_manifest(args):
    root = Path(args.root).resolve()
    mp_spdz_root = Path(args.mp_spdz_root).resolve()
    runtime = mp_spdz_root / args.runtime_binary
    malicious_runtime = args.runtime_binary in {
        "mascot-party.x",
        "mama-party.x",
    }
    effective_security_parameter = (
        args.security_parameter if args.security_parameter is not None else 40
    ) if malicious_runtime else None
    program_name = (
        f"{PROGRAM}-{args.signers}-{args.kappa_base}-"
        f"{args.components}-{args.coefficients}"
    )
    schedule = root / "mpc/Programs/Schedules" / f"{program_name}.sch"
    source = root / PROGRAM_SOURCE
    key, rnd, mu, key_shares, rnd_shares = fixture(args.signers)
    rhopp, expected = expected_expandmask(
        key,
        rnd,
        mu,
        args.kappa_base,
        args.components,
        args.coefficients,
    )
    with tempfile.TemporaryDirectory(prefix="mldsa-expandmask-equivalence-") as tmp:
        run_dir = Path(tmp)
        player_data = run_dir / "Player-Data"
        player_data.mkdir()
        os.symlink(root / "mpc/Programs", run_dir / "Programs")
        write_inputs(player_data, args.signers, key_shares, rnd_shares, mu)
        if runtime.is_file() and schedule.is_file():
            exit_codes, timed_out, duration = run_parties(
                runtime,
                run_dir,
                program_name,
                args.signers,
                args.port,
                args.timeout_seconds,
                args.security_parameter,
            )
        else:
            exit_codes, timed_out, duration = [], False, 0.0
        output_records, actual = read_outputs(
            player_data,
            args.signers,
            len(expected),
        )
        log_tails = {}
        for player in range(args.signers):
            log_path = run_dir / f"party-{player}.log"
            if log_path.is_file():
                log_tails[str(player)] = log_path.read_text(
                    encoding="utf-8", errors="replace"
                )[-4000:]

    actual_bytes = (
        b"".join(value.to_bytes(4, "little") for value in actual)
        if actual is not None
        else b""
    )
    expected_bytes = b"".join(
        value.to_bytes(4, "little") for value in expected
    )
    checks = {
        "runtime_present": runtime.is_file(),
        "compiled_schedule_present": schedule.is_file(),
        "all_parties_exited_zero": (
            len(exit_codes) == args.signers and all(code == 0 for code in exit_codes)
        ),
        "execution_did_not_time_out": not timed_out,
        "all_private_outputs_present": all(
            record["present"] for record in output_records
        ),
        "output_coefficient_count_matches": actual is not None,
        "all_coefficients_match_fips204_oracle": actual == expected,
        "full_mldsa65_dimensions": (
            args.components == 5 and args.coefficients == 256
        ),
    }
    functional_equivalence_passed = all(checks.values())
    malicious_test_scale_execution_passed = (
        malicious_runtime and functional_equivalence_passed
    )
    blockers = [
        "6,667-signer distributed execution is absent",
        "threshold DKG K-share input binding is absent",
        "production private-share custody evidence is absent",
        "independent equivalence and security review are absent",
    ]
    if not malicious_test_scale_execution_passed:
        blockers.insert(0, "malicious MASCOT/SPDZ execution is absent")
    if (
        malicious_test_scale_execution_passed
        and effective_security_parameter < 40
    ):
        blockers.insert(
            0,
            "40-bit statistical-security MASCOT execution over the ML-DSA q field is absent",
        )
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution": {
            "runtime": str(runtime),
            "runtime_profile": (
                "mama_multiple_mac_malicious_dishonest_majority_test_scale"
                if args.runtime_binary == "mama-party.x"
                else (
                    "mascot_malicious_dishonest_majority_test_scale"
                    if malicious_runtime
                    else "semi_honest_functional_equivalence_only"
                )
            ),
            "program": program_name,
            "signers": args.signers,
            "port_base": args.port,
            "timeout_seconds": args.timeout_seconds,
            "statistical_security_parameter": effective_security_parameter,
            "duration_seconds": duration,
            "exit_codes": exit_codes,
            "timed_out": timed_out,
            "log_tails": log_tails,
        },
        "source": {
            "path": str(source),
            "sha256": sha256_path(source),
            "schedule": str(schedule),
            "schedule_sha256": sha256_path(schedule),
        },
        "mp_spdz": {
            "root": str(mp_spdz_root),
            "commit": command_value(["git", "rev-parse", "HEAD"], mp_spdz_root),
        },
        "fixture": {
            "key_sha256": sha256_bytes(key),
            "rnd_sha256": sha256_bytes(rnd),
            "mu_sha256": sha256_bytes(mu),
            "rhopp_sha256": sha256_bytes(rhopp),
        },
        "result": {
            "coefficient_count": len(expected),
            "actual_sha256": sha256_bytes(actual_bytes) if actual is not None else None,
            "expected_sha256": sha256_bytes(expected_bytes),
            "private_outputs": output_records,
        },
        "checks": checks,
        "functional_equivalence_passed": functional_equivalence_passed,
        "malicious_test_scale_execution_passed": (
            malicious_test_scale_execution_passed
        ),
        "exact_distributed_expand_mask": False,
        "exact_expand_mask_mpc": False,
        "blockers": blockers,
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_malicious_mpc_execution_at_test_scale": (
                malicious_test_scale_execution_passed
            ),
            "claims_functional_equivalence": functional_equivalence_passed,
        },
    }


def write_manifest(manifest, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    content = canonical_json(manifest)
    (out_dir / "manifest.json").write_text(content, encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(
        f"{sha256_bytes(content.encode())}  manifest.json\n",
        encoding="utf-8",
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run functional MPC ExpandMask equivalence evidence"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--mp-spdz-root",
        default=os.environ.get("MP_SPDZ_ROOT"),
        required=os.environ.get("MP_SPDZ_ROOT") is None,
    )
    parser.add_argument("--runtime-binary", default="semi-party.x")
    parser.add_argument("--signers", type=int, default=2)
    parser.add_argument("--kappa-base", type=int, default=0)
    parser.add_argument("--components", type=int, default=5)
    parser.add_argument("--coefficients", type=int, default=256)
    parser.add_argument("--port", type=int, default=15000)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--security-parameter", type=int)
    parser.add_argument("--out", default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    manifest = build_manifest(args)
    write_manifest(manifest, args.out)
    print(
        "functional_equivalence_passed="
        + str(manifest["functional_equivalence_passed"]).lower()
    )
    return 0 if manifest["functional_equivalence_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
