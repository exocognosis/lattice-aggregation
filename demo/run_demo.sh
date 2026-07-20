#!/usr/bin/env bash
#
# One-command demo for the threshold ML-DSA-65 distributed signing pipeline.
#
# Default (verify-only): builds nothing heavy. It takes the signature from a
# real, committed distributed run and asks a THIRD PARTY library (RustCrypto
# ml-dsa) to verify it. This is the "check our claim yourself" path and needs
# only a Rust toolchain.
#
#   ./demo/run_demo.sh
#
# Full run: regenerates the signature live by running the real N-party
# malicious-secure MPC, then verifies the fresh artifact. This needs a built
# MP-SPDZ (see README.md, "Full run prerequisites").
#
#   ./demo/run_demo.sh --full
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="verify-only"
[ "${1:-}" = "--full" ] && MODE="full"

ARTIFACT="$REPO_ROOT/artifacts/real-small-distributed-aggregation/latest"

echo "=============================================================="
echo " Dytallix threshold ML-DSA-65 demo  (mode: $MODE)"
echo "=============================================================="

if [ "$MODE" = "full" ]; then
    : "${MP_SPDZ_ROOT:=$HOME/Documents/MP-SPDZ}"
    if [ ! -x "$MP_SPDZ_ROOT/mama-party.x" ]; then
        echo "ERROR: MP-SPDZ runtime not found at $MP_SPDZ_ROOT/mama-party.x"
        echo "Build it first (see demo/README.md), or run without --full to verify the committed signature."
        exit 2
    fi
    export MP_SPDZ_ROOT
    export DYLD_LIBRARY_PATH="$MP_SPDZ_ROOT:$MP_SPDZ_ROOT/local/lib:${DYLD_LIBRARY_PATH:-}"
    echo "[1/2] Running the real 3-of-4 distributed signing (this takes ~90s and moves ~12 GB)..."
    python3 "$REPO_ROOT/scripts/run_small_distributed_aggregation.py" \
        --mp-spdz-root "$MP_SPDZ_ROOT" \
        --message "dytallix live demo run" \
        --out-name latest
    echo
fi

echo "[$([ "$MODE" = full ] && echo 2/2 || echo 1/1)] Verifying the signature with a third party library (RustCrypto ml-dsa)..."
echo
( cd "$REPO_ROOT/demo/verify_signature" && cargo run --quiet -- "$ARTIFACT" )

echo
echo "Done. The signature above was produced by a distributed threshold run and"
echo "accepted by an unmodified, third party FIPS 204 verifier."
