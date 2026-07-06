# Simulation Benchmark Results

This document indexes the checked-in deterministic simulation benchmark
artifacts for the current research scaffold. These results are deterministic research telemetry, requires security evidence review, requires real-world validator performance evidence, and requires production-readiness evidence.

The latest checked-in run uses the large deterministic profile:

```sh
cargo run -- --profile large --format csv --no-wall-sleep
```

The large profile covers bounded, reproducible scenarios for 3, 64, 512, and
10,000 validators. The 10,000-validator row is a simulation-scale stress
profile for harness shape, bandwidth accounting, and reproducible artifact
generation only.

## Latest Artifacts

- Checked-in artifact root: `docs/benchmarks/generated/latest-simulation/`;
  manifest path: `docs/benchmarks/generated/latest-simulation/manifest.json`.
- [Manifest](generated/latest-simulation/manifest.json): command, commit,
  toolchain, OS, artifact paths, and SHA-256 checksums.
- [Trial CSV](generated/latest-simulation/trials.csv): per-trial profile,
  threshold, validator count, malicious-validator setting, wall time, logical
  latency, abort/retry count, bandwidth, and ML-DSA-65 size constants.
- [Summary](generated/latest-simulation/summary.md): grouped scenario means
  rendered from the checked-in CSV.

## Claim Boundary

The benchmark harness exercises the default deterministic simulation backend.
It does not produce real ML-DSA signatures, does not validate a production
threshold backend, does not show FIPS validation, and does not measure an
external validator deployment.

Real-world benchmark claims require the separate
[Real-World Benchmark Protocol](real-world-benchmark-protocol.md), including a
production threshold backend, hardware and network topology, dependency
versions, raw logs, checksums, reviewer sign-off, and claim-boundary review.

## External Comparator Baseline

The Ethereum Research post
[Lattice-based signature aggregation](https://ethresear.ch/t/lattice-based-signature-aggregation/22282)
reports an external LaBRADOR + Falcon proof-wrapper aggregation benchmark for
10,000 Falcon-512 signatures: 74.07 KB proof size, 5.95s proof generation, and
2.65s proof verification in a single-threaded run. That result is useful as an
external baseline for proof-wrapper aggregation, but it is not a benchmark
produced by this repository and does not validate this repository's simulated
backend.

The comparison point is architectural. LaBRADOR + Falcon proves many
independent signatures behind a proof-wrapper verifier. This repository's
native threshold ML-DSA-65 target is higher-risk and not yet proven, but if its
theorem, backend, bridge-test, and audit gates close, the intended output is one
standard-sized ML-DSA-65 signature checked by a standard ML-DSA verifier.

## Regeneration

To regenerate the checked-in benchmark evidence:

```sh
python3 scripts/run_simulation_benchmarks.py --out docs/benchmarks/generated/latest-simulation
```

Use a temporary Cargo target directory when local build state is noisy:

```sh
python3 scripts/run_simulation_benchmarks.py \
  --out docs/benchmarks/generated/latest-simulation \
  --target-dir /tmp/lattice-aggregation-benchmark-script
```

Raw exploratory reruns belong under `artifacts/benchmarks/`, which is ignored
by git. Only bounded review artifacts under `docs/benchmarks/generated/` should
be checked in.
