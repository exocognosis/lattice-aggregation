# Local Validator-Network Runner

Status: local validator orchestration telemetry, simulated backend only.

## Scope

The local validator-network runner exercises multiple local `ThresholdActor`
instances through the in-memory adapter boundary. It is designed to move beyond
single-harness peer-message injection and into validator-network-shaped
orchestration.

Exact claim boundary:

```text
local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security
```

## Runner

Run the default localnet smoke profile:

```sh
cargo run --example validator_localnet
```

The example currently runs four local validator actors with threshold three. It
uses in-memory message routing, local consensus recorders, deterministic
simulation key shares, and the simulated aggregation backend.

## Packet Layout

Generate an ignored localnet packet:

```sh
python3 scripts/run_localnet_runner.py --out artifacts/localnet/latest
```

Exploratory localnet packets should be written under ignored
`artifacts/localnet/` paths and emit:

- `manifest.json`
- `topology.json`
- `metrics.csv`
- `events.jsonl`
- `node-logs/README.md`
- `command.stdout.log`
- `command.stderr.log`
- `summary.md`
- `SHA256SUMS`

Those packets are engineering telemetry only. They must not be checked in as
real-world benchmark evidence and must not replace the
[Real-World Benchmark Protocol](real-world-benchmark-protocol.md).

## Relationship to Simulation Benchmarks

[Simulation Benchmark Results](simulation-results.md) remain the checked-in
large deterministic benchmark packet. The localnet runner is a separate
adapter-orchestration step: it verifies local actor fanout, local partial-share
broadcasts, finalization callbacks, evidence capture, and byte accounting in a
validator-network-shaped local process.

## Relationship to Real-World Benchmark Protocol

The [Real-World Benchmark Protocol](real-world-benchmark-protocol.md) is still
required before any real-world benchmark or production-validator claim. Localnet
telemetry does not supply a production threshold backend, external validator
deployment, authenticated transport, raw production logs, side-channel review,
or external reviewer sign-off.
