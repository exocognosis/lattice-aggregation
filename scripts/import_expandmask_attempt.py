#!/usr/bin/env python3
"""Import exact-ExpandMask MPC Binary-Output shares and verify FIPS equivalence.

Reads ``Binary-Output-P{p}-0`` for each signer from a run's ``Player-Data``
directory, reconstructs ``sum_p y_p mod q``, recomputes the FIPS 204
ML-DSA-65 ExpandMask oracle for ``(rhopp, kappa_base)``, and reports byte-exact
equivalence as JSON for the eventual orchestrator.

This mirrors the Rust importer in ``src/backend/mpc_import.rs`` and the oracle
``expected_expandmask`` in ``scripts/run_exact_expandmask_mpc_equivalence.py``.

CRITICAL HONESTY: ``exact_expandmask_equivalence_verified`` is the *real*
byte-exact comparison result, never a hard-coded true. ``malicious_mpc_verified``
must be supplied by the caller from real MAC-check evidence (clean malicious-MPC
party logs); it defaults to false and is passed through verbatim.

Each ``Binary-Output-P{p}-0`` file holds exactly ``components * coefficients``
(5 * 256 = 1280) little-endian signed int64 values: party p's additive share
``y_p`` of the mask, flattened component-major.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


Q = 8_380_417
GAMMA1 = 1 << 19


def fixture_rhopp(signers):
    """Recompute rhopp from the equivalence harness's deterministic fixture.

    Matches ``fixture`` + ``expected_expandmask`` in
    ``run_exact_expandmask_mpc_equivalence.py``: key/rnd/mu are fixed test
    vectors and ``rhopp = SHAKE256(key || rnd || mu)`` (64 bytes).
    """
    key = bytes(range(32))
    rnd = bytes(range(32, 64))
    mu = bytes(range(64, 128))
    return hashlib.shake_256(key + rnd + mu).digest(64)


def fips_expandmask_oracle(rhopp, kappa_base, components, coefficients):
    """Pure-Python FIPS 204 ML-DSA-65 ExpandMask oracle (component-major)."""
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
    return expected


def read_binary_output_share(path, coeff_count):
    """Parse one Binary-Output-P{p}-0 file into ``coeff_count`` values mod q."""
    raw = path.read_bytes()
    if len(raw) != coeff_count * 8:
        raise ValueError(
            f"{path.name}: expected {coeff_count * 8} bytes "
            f"({coeff_count} int64), got {len(raw)}"
        )
    values = struct.unpack("<" + "q" * coeff_count, raw)
    return [value % Q for value in values]


def reconstruct(shares, coeff_count):
    """Sum per-party shares component-wise mod q."""
    return [
        sum(share[index] for share in shares) % Q for index in range(coeff_count)
    ]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Import MPC ExpandMask Binary-Output shares and verify FIPS"
        " equivalence"
    )
    parser.add_argument(
        "--player-data",
        required=True,
        help="Directory containing Binary-Output-P{p}-0 files",
    )
    parser.add_argument("--signers", type=int, required=True)
    parser.add_argument("--kappa-base", type=int, default=0)
    parser.add_argument("--components", type=int, default=5)
    parser.add_argument("--coefficients", type=int, default=256)
    parser.add_argument(
        "--rhopp-hex",
        default=None,
        help="128-hex-char (64-byte) rhopp; if omitted, derived from the "
        "equivalence harness fixture for --signers",
    )
    parser.add_argument(
        "--malicious-mpc-verified",
        action="store_true",
        help="Set only when clean malicious-MPC MAC-check evidence exists; "
        "passed through verbatim, never inferred",
    )
    parser.add_argument("--out", default=None, help="Write JSON here (else stdout)")
    return parser.parse_args(argv)


def build_report(args):
    player_data = Path(args.player_data)
    coeff_count = args.components * args.coefficients

    if args.rhopp_hex is not None:
        rhopp = bytes.fromhex(args.rhopp_hex)
        if len(rhopp) != 64:
            raise ValueError("--rhopp-hex must decode to exactly 64 bytes")
        rhopp_source = "supplied"
    else:
        rhopp = fixture_rhopp(args.signers)
        rhopp_source = "harness_fixture"

    share_records = []
    shares = []
    all_present = True
    parse_ok = True
    for player in range(args.signers):
        path = player_data / f"Binary-Output-P{player}-0"
        present = path.is_file()
        all_present &= present
        record = {"player": player, "present": present}
        if present:
            raw = path.read_bytes()
            record["byte_length"] = len(raw)
            record["sha256"] = hashlib.sha256(raw).hexdigest()
            try:
                shares.append(read_binary_output_share(path, coeff_count))
            except ValueError as error:
                parse_ok = False
                record["error"] = str(error)
        share_records.append(record)

    oracle = fips_expandmask_oracle(
        rhopp, args.kappa_base, args.components, args.coefficients
    )
    oracle_bytes = b"".join(value.to_bytes(4, "little") for value in oracle)

    equivalence = False
    reconstructed_sha256 = None
    if all_present and parse_ok and len(shares) == args.signers:
        reconstructed = reconstruct(shares, coeff_count)
        reconstructed_bytes = b"".join(
            value.to_bytes(4, "little") for value in reconstructed
        )
        reconstructed_sha256 = hashlib.sha256(reconstructed_bytes).hexdigest()
        equivalence = reconstructed_bytes == oracle_bytes

    return {
        "schema": "lattice-aggregation:expandmask-attempt-import:v1",
        "player_data": str(player_data),
        "signers": args.signers,
        "kappa_base": args.kappa_base,
        "components": args.components,
        "coefficients": args.coefficients,
        "coefficient_count": coeff_count,
        "rhopp_source": rhopp_source,
        "rhopp_sha256": hashlib.sha256(rhopp).hexdigest(),
        "private_outputs": share_records,
        "all_private_outputs_present": all_present,
        "output_parse_ok": parse_ok,
        "oracle_sha256": hashlib.sha256(oracle_bytes).hexdigest(),
        "reconstructed_sha256": reconstructed_sha256,
        # The single load-bearing honesty flag: a real byte-exact comparison.
        "exact_expandmask_equivalence_verified": equivalence,
        # Passed through verbatim from the caller's real MAC-check evidence.
        "malicious_mpc_verified": bool(args.malicious_mpc_verified),
    }


def main(argv=None):
    args = parse_args(argv)
    report = build_report(args)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        Path(args.out).write_text(content, encoding="utf-8")
    else:
        print(content, end="")
    return 0 if report["exact_expandmask_equivalence_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
