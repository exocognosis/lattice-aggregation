# Proof Boundary Batch Plan

Date: 2026-05-25

## Execution Mode

Future work should be batched into larger independent tracks and executed with
parallel agents where write scopes can be separated. The coordinator owns
integration and final verification.

## Batch A: Contribution Proof Integration

Owner scope:

```text
src/adapter/actor.rs
tests/hazmat_mldsa65_wire.rs
```

Goal:

Thread `ContributionStatement`, `ContributionWitness`, and `ContributionProof`
through the hazmat secret-contribution verification boundary without changing
wire formats.

Acceptance:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_wire
```

## Batch B: Proof Boundary Documentation

Owner scope:

```text
docs/cryptography/proof-bearing-contribution-boundary.md
docs/cryptography/formal-proof-scaffold.md
```

Goal:

Document the scaffold proof API and the exact replacement path from
transcript-hash binding to a real proof or MPC verification relation.

Acceptance:

```bash
rg -n "ContributionProof|proof-bearing-contribution-boundary|transcript-hash" docs/cryptography -S
```

## Batch C: DKG Soundness Prep

Owner scope:

```text
src/crypto/vss.rs
src/crypto/interpolation.rs
tests/hazmat_mldsa65_hardening.rs
docs/cryptography/formal-proof-scaffold.md
```

Goal:

Add the next layer of deterministic DKG/VSS soundness checks: duplicate index
rejection, zero-index rejection, and reconstruction subset invariants.

Acceptance:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_hardening
```

## Batch D: Reproducibility And Review

Owner scope:

```text
docs/benchmarks/section-v-results.md
docs/benchmarks/section-v-reproducibility.md
tests/hazmat_mldsa65_simulation_grid.rs
```

Goal:

Keep benchmark artifacts and claim language synchronized with any protocol
boundary changes.

Acceptance:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_simulation_grid
```

## Final Gate

After all batches merge:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa -- --skip invalid_signing_state_calls_do_not_compile

CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo clippy -j1 --all-targets --all-features -- -D warnings
```

