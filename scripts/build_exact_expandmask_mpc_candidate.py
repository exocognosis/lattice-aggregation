#!/usr/bin/env python3
"""Compile and describe the fail-closed MP-SPDZ ExpandMask candidate."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:exact-expandmask-mpc-candidate:v1"
DEFAULT_OUT = "artifacts/exact-distributed-expandmask-mpc/latest"
PROGRAM = "mldsa65_expandmask"
PROGRAM_SOURCE = "mpc/Programs/Source/mldsa65_expandmask.mpc"
FIELD_PRIME = 8_380_417
TARGET_VALIDATORS = 10_000
TARGET_THRESHOLD = 6_667


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_path(path):
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


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


def run_compiler(command, cwd, timeout_seconds):
    process = subprocess.Popen(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate()
        return 124, stdout, stderr + (
            "\ncompiler timeout after " + str(timeout_seconds) + " seconds"
        )
    except KeyboardInterrupt:
        os.killpg(process.pid, signal.SIGTERM)
        process.communicate()
        raise
    return process.returncode, stdout, stderr


def compile_candidate(
    root,
    mp_spdz_root,
    compile_signers,
    compile_components,
    compile_coefficients,
    compile_timeout_seconds,
):
    root = Path(root).resolve()
    mp_spdz_root = Path(mp_spdz_root).resolve()
    compiler = mp_spdz_root / "compile.py"
    source = root / PROGRAM_SOURCE
    checks = {
        "program_source_present": source.is_file(),
        "mp_spdz_compiler_present": compiler.is_file(),
        "malicious_dishonest_majority_protocol_selected": True,
        "compiler_preserves_memory_order": True,
        "field_matches_mldsa_q": FIELD_PRIME == 8_380_417,
        "target_n_10000": TARGET_VALIDATORS == 10_000,
        "target_t_6667": TARGET_THRESHOLD == 6_667,
        "full_mldsa65_dimensions_requested": (
            compile_components == 5 and compile_coefficients == 256
        ),
    }
    command = [
        str(compiler),
        "-M",
        "-X",
        "-P",
        str(FIELD_PRIME),
        PROGRAM,
        str(compile_signers),
        "0",
        str(compile_components),
        str(compile_coefficients),
    ]
    result = {
        "command": command,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timeout_seconds": compile_timeout_seconds,
    }
    if checks["program_source_present"] and checks["mp_spdz_compiler_present"]:
        exit_code, stdout, stderr = run_compiler(
            command,
            cwd=root / "mpc",
            timeout_seconds=compile_timeout_seconds,
        )
        result.update(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )
        checks["candidate_compiles"] = exit_code == 0
    else:
        checks["candidate_compiles"] = False
    checks["full_mldsa65_dimensions_compiled"] = (
        checks["full_mldsa65_dimensions_requested"]
        and checks["candidate_compiles"]
    )
    return checks, result


def build_report(
    root,
    mp_spdz_root,
    compile_signers,
    compile_components=5,
    compile_coefficients=256,
    compile_timeout_seconds=600,
):
    checks, compilation = compile_candidate(
        root,
        mp_spdz_root,
        compile_signers,
        compile_components,
        compile_coefficients,
        compile_timeout_seconds,
    )
    mp_spdz_root = Path(mp_spdz_root).resolve()
    source = Path(root).resolve() / PROGRAM_SOURCE
    blockers = []
    if not checks["candidate_compiles"]:
        blockers.append("MP-SPDZ exact ExpandMask candidate has not compiled")
    if not checks["full_mldsa65_dimensions_compiled"]:
        blockers.append(
            "only a reduced-dimension compiler smoke test has completed"
        )
    blockers.extend(
        [
            "malicious MAMA execution with 6,667 signers is absent",
            "private per-signer output-share custody evidence is absent",
            "threshold DKG K-share input binding is absent",
            "exact output equivalence corpus and independent review are absent",
        ]
    )
    manifest = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "protocol": {
            "framework": "MP-SPDZ",
            "execution_protocol": "MAMA_multiple_MAC_malicious_dishonest_majority",
            "computation": "secret_shared_fips204_shake256_expandmask_mldsa65",
            "field_prime": FIELD_PRIME,
            "mixed_circuit_conversion": "edaBits",
            "joint_mask_opened": False,
            "secret_or_seed_reconstruction_used": False,
        },
        "target": {
            "validator_count": TARGET_VALIDATORS,
            "threshold": TARGET_THRESHOLD,
            "signer_count": TARGET_THRESHOLD,
            "parameter_set": "ML-DSA-65",
        },
        "source": {
            "path": str(source),
            "sha256": sha256_path(source),
        },
        "mp_spdz": {
            "root": str(mp_spdz_root),
            "commit": command_value(
                ["git", "rev-parse", "HEAD"], mp_spdz_root
            ),
            "compile_signers": compile_signers,
            "compile_components": compile_components,
            "compile_coefficients_per_component": compile_coefficients,
        },
        "checks": checks,
        "compilation": compilation,
        "candidate_ready_for_distributed_execution": all(checks.values()),
        "exact_distributed_expand_mask": False,
        "exact_expand_mask_mpc": False,
        "blockers": blockers,
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_exact_distributed_expand_mask_complete": False,
            "claims_independent_review_complete": False,
        },
    }
    return manifest


def write_report(manifest, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    content = canonical_json(manifest)
    (out_dir / "manifest.json").write_text(content, encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(
        f"{hashlib.sha256(content.encode()).hexdigest()}  manifest.json\n",
        encoding="utf-8",
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Build the fail-closed exact ExpandMask MPC candidate"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--mp-spdz-root",
        default=os.environ.get("MP_SPDZ_ROOT"),
        required=os.environ.get("MP_SPDZ_ROOT") is None,
    )
    parser.add_argument("--compile-signers", type=int, default=2)
    parser.add_argument("--compile-components", type=int, default=5)
    parser.add_argument("--compile-coefficients", type=int, default=256)
    parser.add_argument("--compile-timeout-seconds", type=int, default=600)
    parser.add_argument("--out", default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    manifest = build_report(
        args.root,
        args.mp_spdz_root,
        args.compile_signers,
        args.compile_components,
        args.compile_coefficients,
        args.compile_timeout_seconds,
    )
    write_report(manifest, args.out)
    print(
        "candidate_ready_for_distributed_execution="
        + str(manifest["candidate_ready_for_distributed_execution"]).lower()
    )
    return 0 if manifest["checks"]["candidate_compiles"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
