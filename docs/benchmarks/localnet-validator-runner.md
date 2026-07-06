# Local Validator-Network Runner

Status: local validator orchestration telemetry, simulated backend only.

## Scope

The local validator-network runner exercises multiple local `ThresholdActor`
instances through the in-memory adapter boundary. It is designed to move beyond
single-harness peer-message injection and into validator-network-shaped
orchestration.

Exact claim boundary:

```text
local validator-network engineering telemetry; requires security evidence review; requires real-world validator performance evidence; requires production-readiness evidence; requires production network liveness evidence, authenticated transport, or consensus safety; requires side-channel resistance evidence; requires CAVP/ACVTS validation evidence; requires FIPS validation evidence; requires production threshold ML-DSA security evidence
```

## Runner

Run the default localnet smoke profile:

```sh
cargo run --example validator_localnet
```

Run the local withheld-partial fault profile:

```sh
cargo run --example validator_localnet -- --profile withheld-partial --validators 4 --threshold 4 --withheld-validator 4
```

Run the local quorum-participation profile:

```sh
cargo run --example validator_localnet -- --profile honest --validators 4 --threshold 3 --triggered-validators 3
```

Run the local authenticated-envelope transport profile:

```sh
cargo run --example validator_localnet -- --transport authenticated-envelope
```

The example currently runs four local validator actors with threshold three. It
uses in-memory message routing, local consensus recorders, deterministic
simulation key shares, and the simulated aggregation backend.

Fault profiles are local fault-injection telemetry only. The `withheld-partial`
profile drops local `PartialSignature` deliveries from one validator after that
validator has broadcast its commitment. The runner records `fault_profile`,
`all_validators_finalized`, `dropped_message_count`, finalization count, and
local adapter evidence count. These fields distinguish local partial success
from the honest smoke profile and must not be used as production network
liveness, consensus-safety, slashing-soundness, or Byzantine-fault-tolerance
evidence.

Quorum-participation runs are local participation telemetry only. The
`quorum-participation` packet profile registers four validators, actively
triggers three validators, and keeps the fourth validator passive. The passive validator
did not initiate signing, is not counted as finalized, and is not
treated as slashing evidence. The runner records `triggered_validator_count`
alongside `all_validators_finalized` so reviewers can distinguish active quorum
completion from all-registered-validator completion.

Authenticated-transport runs are authenticated local envelope telemetry only. The
`authenticated-transport` packet profile still runs in one process over Tokio
MPSC channels, but wraps each local protocol wire frame in an authenticated
local envelope with a deterministic validator identity digest. The runner
records `authentication_policy`, `authenticated_envelope_count`, and
`rejected_envelope_count` so reviewers can distinguish identity-envelope
coverage from unauthenticated in-memory delivery. This is not production
authenticated transport, peer discovery, replay-resistance, network-liveness,
consensus-safety, or Byzantine-fault-tolerance evidence.

Authenticated-envelope-tamper runs are local tamper-rejection telemetry only.
The `authenticated-envelope-tamper` packet profile corrupts one validator's
tampered authenticated envelope digest in the local runner and records the
rejection through `rejected_envelope_count`. This is not production
authenticated transport, not replay-resistance, peer discovery, network
liveness, consensus-safety, Byzantine-fault-tolerance, slashing-soundness, or
cryptographic security evidence.

## Packet Layout

Generate an ignored localnet packet:

```sh
python3 scripts/run_localnet_runner.py --out artifacts/localnet/latest
```

Generate a local fault-injection packet:

```sh
python3 scripts/run_localnet_runner.py --profile withheld-partial --out artifacts/localnet/withheld-partial
```

Generate a local quorum-participation packet:

```sh
python3 scripts/run_localnet_runner.py --profile quorum-participation --out artifacts/localnet/quorum-participation
```

Generate a local authenticated-envelope transport packet:

```sh
python3 scripts/run_localnet_runner.py --profile authenticated-transport --out artifacts/localnet/authenticated-transport
```

Generate a local authenticated-envelope tamper packet:

```sh
python3 scripts/run_localnet_runner.py --profile authenticated-envelope-tamper --out artifacts/localnet/authenticated-envelope-tamper
```

Exploratory localnet packets should be written under ignored
`artifacts/localnet/` paths and emit:

- `manifest.json`
- `topology.json`
- `metrics.csv`
- `events.jsonl`
- `node-logs/README.md`
- `node-logs/validator-{id}.log`
- `command.stdout.log`
- `command.stderr.log`
- `summary.md`
- `SHA256SUMS`

`manifest.json`, `topology.json`, `metrics.csv`, and `events.jsonl` must carry
`fault_profile`, `triggered_validator_count`, `authentication_policy`,
`authenticated_envelope_count`, `rejected_envelope_count`,
`all_validators_finalized`, and `dropped_message_count` when the runner emits
those fields. Per-validator node logs are deterministic local telemetry
summaries only, not raw production logs.

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
