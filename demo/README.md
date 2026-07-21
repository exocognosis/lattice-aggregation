# Threshold ML-DSA-65 distributed signing: reproducible demo

This demo lets you check our central claim yourself: several parties jointly
produce one standard post-quantum signature (ML-DSA-65, FIPS 204), no single
party ever holds the whole key or the joint nonce, and the result is accepted
by an ordinary, third party FIPS 204 verifier.

We do not ask you to trust our verifier. The demo verifies the signature with
the independent RustCrypto `ml-dsa` crate, and confirms a tampered message is
rejected so a constant "true" stub cannot pass.

## Quick start (verify our real signature, no MPC build needed)

Requires only a Rust toolchain (`rustup`).

```
./demo/run_demo.sh
```

This reads a signature from a real, committed distributed run
(`artifacts/real-small-distributed-aggregation/latest/`) and verifies it with a
third party library. Expected output:

```
public key   : 1952 bytes
signature    : 3309 bytes
signature valid          : true
tampered message rejected : true
PASS: a third party library accepts this threshold-produced ML-DSA-65 signature.
```

3,309 bytes is the standard ML-DSA-65 signature size. 1,952 bytes is the
standard public key size. Nothing here is a custom format.

## Full run (regenerate the signature live)

This runs the real N-party malicious-secure MPC end to end, then verifies the
fresh output.

```
./demo/run_demo.sh --full
```

A 3-of-4 run takes about 90 seconds and moves roughly 12 GB of network traffic
on one machine. See the honest scaling numbers below.

### Full run prerequisites

You need a built MP-SPDZ with the `mama-party.x` runtime. On Apple Silicon with
recent clang, two fixes are required:

1. In `CONFIG.mine`, add `BREW_CFLAGS += -Wno-deprecated-literal-operator -Wno-format`.
2. In `Protocols/ReplicatedInput.hpp`, change `G.get<...>()` to `G.template get<...>()`
   (the compiler needs the `template` disambiguator on the dependent type).

Then `make -j4 mama-party.x`, and generate TLS certs with `Scripts/setup-ssl.sh 8`.
Point the demo at it with `MP_SPDZ_ROOT=/path/to/MP-SPDZ`. Note that N of 6 or
more will exhaust the OS network buffers on a 16 GiB machine; that is expected
(see below).

## What is real, and what is not

Real, and checked:

- The nonce is generated inside a malicious, dishonest-majority MPC (MP-SPDZ
  MAMA, statistical security 40), byte for byte identical to the FIPS 204
  ExpandMask reference across all 1,280 coefficients.
- Each party signs with only a sealed, non-exportable share of the key.
- Every signature is re-verified with a third party library. Tampered messages
  are rejected.
- The rejection-sampling retry loop, single-use masks, and the scaling limits
  were all exercised on real runs.

Not yet, stated plainly:

- Key sharing here uses a trusted setup (dealt then shared), not a dealerless
  DKG. `no_single_secret_signing_path` is hard-coded `false`.
- It runs at small party counts only. On one 16 GiB laptop the cost was 12 GB
  of traffic at 3 parties, 28 GB at 4, 55 GB at 5, and a hard failure at 6.
- It has not had an external audit.
- This reproduces published schemes (for example Quorus, and "Efficient
  Threshold ML-DSA up to 6 Parties"). It is an engineering reproduction and
  evaluation, not a new cryptographic result.

## Files

- `run_demo.sh` runs the demo (verify-only by default, `--full` to regenerate).
- `verify_signature/` a small Rust project that verifies a run artifact using
  the third party RustCrypto `ml-dsa` crate.
- `../scripts/run_small_distributed_aggregation.py` the orchestrator that drives
  the live MPC and the distributed signer.
- `../artifacts/real-small-distributed-aggregation/latest/` a committed real run
  (signature, public key, per-party MPC outputs, party logs, manifest).
