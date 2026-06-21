# Simulation Benchmark Results

This document indexes the checked-in deterministic simulation benchmark
artifacts for the current research scaffold. These results are deterministic research telemetry, not security evidence, not real-world validator performance, and not production-readiness evidence.

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
