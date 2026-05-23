# Backend Selection: Local Hazmat ML-DSA-65 Internals

Date: 2026-05-23

## Decision

The crate will grow the real ML-DSA-65 implementation locally behind the
`hazmat-real-mldsa` Cargo feature.

The default feature set remains `simulated`. This keeps ordinary protocol,
actor, and consensus-adapter tests deterministic and prevents downstream users
from accidentally treating the research scaffold as a production FIPS 204
implementation.

## Scope of the First Hazmat Boundary

The first local boundary exposes:

- ML-DSA-65 parameter constants from FIPS 204.
- Fixed-size public-key and signature byte wrappers.
- `k = 6` and `l = 5` polynomial vector shapes.
- Basic modular arithmetic helpers over `q = 8380417`.
- Strict polynomial bound checks delegated to the existing low-level `Poly`
  primitive.
- Public key unpacking into `rho` and `t1`.
- Signature unpacking into `c_tilde`, `z`, and hint metadata.
- Public key and signature packing helpers for round-trip testing.
- Structural hint encoding validation and `z` norm rejection.
- Non-empty hint construction, signature round-tripping, and `UseHint`
  application over `k`-dimension vectors.
- FIPS 204 decomposition helpers: `Power2Round`, `Decompose`,
  `HighBits`, `LowBits`, `MakeHint`, and `UseHint`.
- FIPS 204 `SampleInBall(c_tilde)` challenge-polynomial expansion.
- FIPS 204 `RejNTTPoly` and `ExpandA(rho)` public matrix expansion.
- Reference coefficient-domain polynomial and vector arithmetic for verifier
  equation scaffolding.
- Canonical `O(n^2)` reference NTT and inverse NTT with pointwise
  multiplication tests.
- External pure verifier equation support: `tr = H(pk)`,
  `mu = H(tr || 0x00 || |ctx| || ctx || M)`,
  `w1 = UseHint(Az - c*t1*2^d)`, and
  `c_tilde = H(mu || w1Encode(w1))`.
- Internal verifier equation support for both `mu = H(tr || M)` and
  caller-supplied external `mu`.
- FIPS NTT-domain arithmetic for the verifier equation, including
  `Ahat * NTT(z)` and `NTT(c) * NTT(t1 * 2^d)`.
- Checked-in NIST ACVP sample groups for ML-DSA-65 external/pure,
  internal/message, and internal/external-mu `sigVer`.

This is intentionally a scaffold. It does not yet implement key generation,
secret-key packing, signing, optimized Montgomery/NTT arithmetic, context
handling beyond verification transcripts, external prehash interfaces, or
broader KAT conformance.

## Next Verifier Slices

The remaining standard-verification path should land in this order:

1. Add ACVP `sigVer` coverage for the external prehash path.
2. Differential tests against an independent implementation.
3. Montgomery/table-optimized FIPS NTT with reference-vector fixtures.

## KAT Harness

The crate includes ACVP-style fixture plumbing in
`tests/hazmat_mldsa65_kat.rs`. A NIST sample vector is checked in at the default
fixture path and runs under the `hazmat-real-mldsa` feature.

Fixture source:

- NIST ACVP ML-DSA `sigVer` JSON, `revision = "FIPS204"`.
- `parameterSet = "ML-DSA-65"`.
- External pure, internal message, and internal external-mu verification groups
  are covered. External prehash vectors are intentionally skipped until hash OID
  handling exists.
- Default path: `tests/fixtures/ml_dsa_65_sigver_acvp.json`.
- Override path: `DYTALLIX_MLDSA65_SIGVER_KAT`.

## Publication Gate

The feature must not be described as a real ML-DSA-65 backend until the local
implementation passes at least:

- FIPS 204 known-answer tests for ML-DSA-65 key generation, signing, and
  verification.
- Differential tests against an independent validated implementation.
- Packing and unpacking round-trip tests for every public and secret structure.
- Rejection-sampling tests at the ML-DSA-65 bounds.
- Constant-time review for secret-dependent arithmetic paths.

## Integration Rule

Protocol and adapter code may depend on `hazmat-real-mldsa` only through small,
audited functions. The default public API must continue to compile and test
without the feature enabled.
