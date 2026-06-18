# Section V Benchmark Reproducibility

Date: 2026-05-25

## Purpose

This note records the command path for regenerating the current Section V
evaluation tables and PGFPlots CSV rows from the real hazmat ML-DSA-65 actor
simulation grid.

The output is empirical telemetry from deterministic in-memory protocol
scenarios. Wall-clock latency varies by machine load, but validator counts,
thresholds, abort/retry models, bandwidth accounting, and table layout are
fixed by the crate.

## Command

Run from the crate root:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa
```

To include the experimental VSS complaint-evidence artifacts emitted for
attributable Byzantine contribution failures, enable both feature gates:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa,experimental-vss
```

To retain the generated appendix artifacts, redirect stdout:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa \
  > /tmp/section-v-hazmat-mldsa65-output.txt
```

## Experiment Profiles

The runner emits three profiles:

```text
Small-Scale Consensus
N = 3
t = 2
network = ideal local mesh
byzantine mode = none

Mid-Scale Distributed Fabric
N = 7
t = 5
network = bounded distributed-fabric latency
byzantine mode = malformed secret contribution

Adversarial WAN Cluster
N = 15
t = 10
network = bounded WAN latency and deterministic retry pressure
byzantine mode = none
```

Implementation:

```text
src/utils/hazmat_simulation.rs
src/utils/hazmat_artifacts.rs
src/utils/exporter.rs
src/main.rs
tests/hazmat_mldsa65_simulation_grid.rs
```

## Output Format

For each profile, `src/main.rs` prints these base sections in this exact order:

```text
===== <profile label>: LaTeX =====
===== <profile label>: PGFPlots CSV =====
===== <profile label>: Transcript JSONL =====
===== <profile label>: Transcript CSV =====
```

With `experimental-vss` enabled, profiles that emit complaint evidence also
print these sections after the base transcript artifacts:

```text
===== <profile label>: Experimental VSS Complaint JSONL =====
===== <profile label>: Experimental VSS Complaint CSV =====
```

The experimental VSS complaint sections are printed only when
`experimental-vss` is enabled and the profile emits complaint evidence. They
carry canonical `ExperimentalVssComplaintEvidence` bytes plus SHA3-256 digests
for replay and structural verification. They remain research artifacts only;
they are not production VSS relation proofs or production slashing
transactions.

The LaTeX section is a `table` environment with mean latency, sample standard
deviation, average aborts, and mean bandwidth. The latency fields are measured
from the current run and must not be copied forward as stable constants.

A checksum-pinned sample bundle for manuscript structure checks is stored at
`docs/benchmarks/artifacts/section-v-sample-output.txt`, with its SHA-256
sidecar at `docs/benchmarks/artifacts/SHA256SUMS`. The sample fixture validates
the checked-in output shape; fresh runs may change wall-clock latency values.

The PGFPlots section is a CSV matrix with this header:

```text
session_id,duration_ms,aborts,bandwidth_bytes
```

The transcript JSONL section is a newline-delimited artifact with deterministic
replay metadata for each hazmat wire frame. The transcript CSV section carries
the same replay metadata for appendix tables and external plotting tools:

```text
experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest
```

Experimental complaint CSV artifacts use this header:

```text
experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex
```

Transcript artifacts bind every emitted or injected frame by SHA3-256 over the
canonical wire encoding. The current transcript rounds are:

```text
masking_commitment
masking_opening
secret_commitment
secret_opening
```

Before printing transcript artifacts, the runner verifies:

- session ID and block height consistency within each experiment/trial/attempt
- canonical 32-byte hex shape for `session_id`, `frame_digest`, and populated
  production statement digest fields
- expected encoded lengths for fixed-size commitment frames
- known direction and round labels
- immediate precommitment/opening adjacency for masking and secret openings

The smoke suite also checks that a fixed one-trial ideal-mesh spec regenerates
byte-for-byte identical transcript JSONL and CSV artifacts across repeated
runs. That invariant applies to transcript artifacts, not to wall-clock timing
or aggregate latency statistics.

## Verification Commands

The benchmark path is covered by:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_simulation_grid
```

Complaint-evidence export coverage:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa,experimental-vss \
  --test hazmat_mldsa65_simulation_grid
```

The broader reproducibility check is:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa -- --skip invalid_signing_state_calls_do_not_compile

CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo clippy -j1 --all-targets --all-features -- -D warnings
```

The type-state compile-fail check is intentionally run separately:

```bash
TYPE_STATE_BIN=$(find /tmp/dytallix-pq-threshold-target/debug/deps \
  -maxdepth 1 -type f -perm +111 -name 'type_state-*' -print \
  | xargs ls -t | head -1)

"$TYPE_STATE_BIN" --exact invalid_signing_state_calls_do_not_compile --nocapture
```

## Interpretation

The current benchmark validates implementation behavior, not production
security. It demonstrates that:

- the real hazmat actor path reaches a standard-verifying ML-DSA-65 signature
- malformed Byzantine contribution payloads are attributable
- honest quorum can still finalize when enough shares remain
- network delay and retry pressure are reflected in telemetry
- Section V tables can be regenerated from the crate

It does not prove:

- adaptive security
- production DKG soundness
- leakage resistance of raw contribution payloads
- full MPC security
- side-channel resistance

The publication readiness boundary for these results is tracked in
`docs/benchmarks/release-readiness-checklist.md`. The checklist separates
research scaffold evidence, `hazmat-real-mldsa` implementation evidence, and
production blockers that must be closed before claiming secure threshold
ML-DSA aggregation.
