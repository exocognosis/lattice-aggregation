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
- External prehash verifier equation support:
  `mu = H(tr || 0x01 || |ctx| || ctx || OID || PHM)`, covering ACVP SHA-2,
  SHA-3, and SHAKE prehash identifiers.
- Internal verifier equation support for both `mu = H(tr || M)` and
  caller-supplied external `mu`.
- FIPS NTT-domain arithmetic for the verifier equation, including
  `Ahat * NTT(z)` and `NTT(c) * NTT(t1 * 2^d)`.
- FIPS NTT regression fixtures for the Montgomery zeta table, forward NTT
  output slices, and inverse NTT round-tripping.
- Deterministic ML-DSA-65 public-key derivation from a 32-byte key-generation
  seed, covering `rho/rhoPrime/K` expansion, `ExpandS` for eta-4 secret
  vectors, `t = A*s1 + s2`, `Power2Round`, and standard public-key packing.
- Deterministic internal ML-DSA-65 signing from a 32-byte key-generation seed,
  covering `ExpandMask`, rejection sampling, `c*s1`, `c*s2`, `c*t0`, hint
  construction, and standard signature packing.
- Expanded secret-key byte derivation for the FIPS/RustCrypto layout:
  `rho || K || tr || s1 || s2 || t0`.
- Expanded secret-key decoding back into signing material, including public-key
  derivation and deterministic signing from decoded key bytes.
- Deterministic external pure signing with FIPS context binding:
  `mu = H(tr || 0x00 || |ctx| || ctx || M)`.
- Checked-in NIST ACVP sample groups for ML-DSA-65 external/pure,
  external/prehash, internal/message, and internal/external-mu `sigVer`.
- Differential verification tests against the independent RustCrypto `ml-dsa`
  implementation for the public reference paths it exposes: external/pure and
  internal/message.
- Differential public-key derivation tests against RustCrypto `ml-dsa` for
  deterministic ML-DSA-65 seed inputs.
- Differential deterministic internal signing tests against RustCrypto
  `ml-dsa`, plus local verification of locally generated signatures.
- Differential expanded secret-key and external/context signing tests against
  RustCrypto `ml-dsa`.
- ACVP-style loader groundwork for future ML-DSA-65 `keyGen` and deterministic
  `sigGen` fixtures, with env-gated official fixture runners.

This is intentionally a scaffold. It does not yet implement randomized signing
APIs, optimized Montgomery/NTT arithmetic, or full official KAT conformance with
checked-in `keyGen`/`sigGen` vectors.

## Next Verifier Slices

The remaining verification hardening should land in this order:

1. Replace the current verifier NTT internals with a reviewed optimized/table
   implementation while preserving the new fixtures.
2. Randomized signing and checked-in official keyGen/sigGen KAT fixtures before
   enabling any real threshold signing path.
3. Additional differential coverage if independent libraries expose HashML-DSA
   prehash and external-mu verification APIs.

## KAT Harness

The crate includes ACVP-style fixture plumbing in
`tests/hazmat_mldsa65_kat.rs`. A NIST sample vector is checked in at the default
fixture path and runs under the `hazmat-real-mldsa` feature.

The crate also includes `tests/hazmat_mldsa65_differential.rs`, which compares
the local verifier result against RustCrypto `ml-dsa` for external/pure and
internal/message ACVP vectors. External prehash and external-mu are still
covered by the local ACVP KAT but are not in this differential test because
the reference crate does not expose matching public verifier entry points for
those ACVP modes.

Fixture source:

- NIST ACVP ML-DSA `sigVer` JSON, `revision = "FIPS204"`.
- `parameterSet = "ML-DSA-65"`.
- External pure, external prehash, internal message, and internal external-mu
  verification groups are covered.
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

The threshold stack also has a separate combined production policy gate in
`src/crypto/production_policy.rs`. Any public production-mode configuration
constructor, including production-labeled runtime or actor setup, must call the
combined gate before constructing runtime configuration. Production-targeted
callers must require both:

- a VSS/DKG backend declaring `ProductionBindingHiding`
- a contribution-proof backend declaring `ProductionProofRelation`

This gate fails closed for deterministic scaffolds and for
`experimental-vss` candidate backends. Passing the policy gate is only a
configuration guard; it does not replace the formal proof, implementation
audit, side-channel review, or external cryptographic review required for
production-readiness claims. Production-labeled configuration must not select
scaffold VSS or scaffold contribution-proof backends, even for local runtime
smoke tests.

The hazmat actor also binds proof-bound secret-contribution frames to the
derived `ProductionContributionStatement` digest, and invalid-share evidence can
carry the derived `ProductionVssRelationStatement` digest. These bindings make
the production public inputs explicit at the adapter boundary, but they are not
backend-selection proof that the underlying VSS or contribution relation is
implemented.

## Integration Rule

Protocol and adapter code may depend on `hazmat-real-mldsa` only through small,
audited functions. The default public API must continue to compile and test
without the feature enabled.
