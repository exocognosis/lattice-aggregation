# Fuzz and Property Test Reproducibility

Date: 2026-05-25

## Purpose

This note documents the deterministic fuzz/property layer used by the current
hazmat ML-DSA-65 research backend. It is designed to run in normal CI without
`cargo-fuzz`, libFuzzer, or extra dependencies.

The tests exercise malformed wire frames, actor event ordering, contribution
decoder strictness, and reordered honest quorum behavior. They are not a
substitute for coverage-guided fuzzing, but they provide stable regression
coverage for the protocol transcript.

## Command

Run from the crate root:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_fuzzing
```

The broader hardening set is:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa \
  --test hazmat_mldsa65_fuzzing \
  --test hazmat_mldsa65_hardening
```

## Coverage

Implemented helper module:

```text
src/utils/hazmat_fuzz.rs
```

Test target:

```text
tests/hazmat_mldsa65_fuzzing.rs
```

Current deterministic mutation corpus:

- truncate last byte
- append trailing byte
- corrupt wire version
- corrupt message type
- flip a middle bit
- truncate to a short prefix

Acceptance rule:

```text
decode(frame) either:
  - rejects deterministically, or
  - decodes to a message whose re-encoded bytes decode back to the same message
```

Actor event corpus:

- rejects secret contribution before masking quorum
- rejects finalization before quorum
- finalizes under reordered honest masking and secret contributions

## Next Fuzzing Step

The next level should add a real `cargo-fuzz` harness for:

- `PqcThresholdWireMsg::decode`
- `decode_mldsa65_masking_contribution`
- `decode_mldsa65_secret_contribution`
- `HazmatMldsa65ActorSession` event sequences

Corpus seeds should include the valid frames produced by
`tests/hazmat_mldsa65_fuzzing.rs`.
