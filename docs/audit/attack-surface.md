# Attack Surface Map

Date: 2026-05-27

## Status

This map is for research-scaffold and audit triage. It identifies where a
reviewer should look for implementation bugs, claim drift, and production
blockers. It is not a production threat model and does not certify threshold
ML-DSA-65 security.

## Feature Gates

Primary risk: code behind `hazmat-real-mldsa` and `experimental-vss` can look
production-shaped while still being explicitly non-production.

Review focus:

- `Cargo.toml`
- `src/utils.rs`
- `src/crypto/production_policy.rs`
- `tests/production_policy.rs`

Expected invariant: production-labeled configuration must fail closed for
scaffold backend families. Passing a feature gate or backend declaration is not
security proof.

## Hazmat ML-DSA Internals

Primary risk: local FIPS 204 ML-DSA-65 arithmetic, encodings, and contribution
logic may contain correctness, canonicalization, or leakage bugs.

Review focus:

- `src/low_level/mldsa65.rs`
- `src/low_level/poly.rs`
- `tests/hazmat_mldsa65.rs`
- `tests/hazmat_mldsa65_kat.rs`
- `tests/hazmat_mldsa65_differential.rs`
- `tests/hazmat_mldsa65_threshold_bridge.rs`

Current tests are regression evidence only. They do not establish FIPS
validation, constant-time behavior, or production side-channel safety.

## Actor/Network Boundaries

Primary risk: asynchronous state transitions may accept out-of-order,
cross-session, stale, duplicated, or incorrectly attributed messages.

Review focus:

- `src/adapter/actor.rs`
- `src/adapter/traits.rs`
- `tests/hazmat_mldsa65_actor.rs`
- `tests/hazmat_mldsa65_fuzzing.rs`
- `tests/hazmat_mldsa65_wire.rs`
- `tests/simulation.rs`

Current actor tests model in-memory and deterministic scenarios. They do not
prove production network liveness, authenticated transport safety, timeout
adequacy, or consensus integration safety.

## Wire Decoding

Primary risk: malformed, oversized, replayed, version-skewed, or
non-canonical frames may bypass checks or create inconsistent evidence.

Review focus:

- `src/adapter/wire.rs`
- `src/serialization.rs`
- `tests/hazmat_mldsa65_wire.rs`
- `tests/validation.rs`

Expected invariant: canonical encodings bind session, block height, attempt,
validator identity, challenge, commitments, production statement digests, and
payload lengths where applicable.

## Evidence/Slashing Artifacts

Primary risk: structured evidence may be mistaken for production slashing proof
before production VSS and contribution proof relations are implemented.

Review focus:

- `src/adapter/evidence.rs`
- `src/utils/hazmat_artifacts.rs`
- `tests/hazmat_mldsa65_wire.rs`
- `tests/section_v_sample_bundle.rs`
- `docs/cryptography/proof-obligations.md`

Current evidence is a research scaffold. It is useful for attribution,
artifact replay, and future verifier inputs. It is not production slashing
evidence and does not prove anti-framing.

## Benchmark/Export Pipeline

Primary risk: Section V outputs could be interpreted as security evidence or
could drift from the checked artifact schema.

Review focus:

- `src/utils/hazmat_simulation.rs`
- `src/utils/exporter.rs`
- `src/main.rs`
- `scripts/reproduce-section-v.sh`
- `docs/benchmarks/reproducibility-manifest.md`
- `tests/reproducibility_manifest.rs`
- `tests/section_v_sample_bundle.rs`

Expected invariant: benchmark artifacts support reproducibility and evaluation
only. They do not prove malicious security, leakage resistance, or production
readiness.

## Docs/Claim Drift

Primary risk: manuscript or documentation wording may overclaim beyond the
implemented and proven boundary.

Review focus:

- `docs/cryptography/claims-matrix.md`
- `docs/cryptography/proof-obligations.md`
- `docs/cryptography/protocol-code-crosswalk.md`
- `docs/benchmarks/release-readiness-checklist.md`
- `tests/audit_manifest.rs`
- `tests/protocol_spec_manifest.rs`
- `tests/reproducibility_manifest.rs`

Expected invariant: the repository remains described as a research scaffold
with hazmat internals until proof obligations, production backends,
side-channel review, and external cryptographic audit are complete.
