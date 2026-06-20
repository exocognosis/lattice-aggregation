# Side-Channel and Constant-Time Boundary

Date: 2026-05-27

## Scope

This document separates the mathematical security claims in the proof package
from implementation leakage claims. It is a boundary document, not an audit
result and not evidence that the current code is constant-time.

The current checkout contains simulation and low-level arithmetic scaffolding,
including `src/low_level/poly.rs` and interpolation helpers used by tests. The
requested real ML-DSA-65 backend path, `src/low_level/mldsa65.rs`, is not
present in this branch. Any references to that file in older audit notes should
therefore be read as future or restored-backend review targets, not as current
evidence.

Read this document with:

- [formal-security-theorem.md](formal-security-theorem.md)
- [noise-rejection-proof-plan.md](noise-rejection-proof-plan.md)
- [../audit/tcb.md](../audit/tcb.md)
- [../audit/attack-surface.md](../audit/attack-surface.md)

## Boundary Statement

The formal proof package targets threshold ML-DSA-65 security under explicit
cryptographic assumptions. Those mathematical claims do not automatically imply
side-channel resistance for Rust code, CPU execution, memory access patterns,
allocator behavior, logging, panic paths, or compiler output.

Theorem statements may assume an implementation leakage condition, such as
FST-A9 in `formal-security-theorem.md`, only as an assumption. Satisfying that
assumption requires separate implementation review, measurements, and
platform-specific evidence. Until that work is complete, the repository should
claim only that constant-time behavior is a production obligation.

## Mathematical Claims

The proof package may reason about:

- EUF-CMA or real/ideal security of a threshold ML-DSA protocol.
- Canonical transcript binding and challenge derivation.
- Share, commitment, partial-signature, aggregation, and rejection-sampling
  correctness.
- Abort distribution and public leakage defined by the formal adversary model.
- Whether accepted aggregate signatures match the standard ML-DSA-65
  distribution.

These claims are about protocol-level games and distributions. They do not
establish that a concrete implementation avoids timing, cache, branch predictor,
microarchitectural, memory lifetime, or diagnostic-channel leakage.

## Implementation Leakage Claims

Implementation leakage claims must be treated separately. A future production
backend needs evidence for at least:

- Secret-independent control flow for secret shares, masks, responses,
  challenges derived from secret-dependent intermediates, and rejection checks.
- Secret-independent memory access for polynomial, vector, matrix, NTT,
  interpolation, packing, unpacking, and comparison paths.
- Fixed-shape encodings and decodings where malformed public input does not
  create secret-dependent timing after secret state is involved.
- Error, panic, logging, evidence, and retry behavior that does not disclose
  honest secret material beyond the formal leakage model.
- Zeroization and state lifetime behavior that is reviewed as an engineering
  property, not inferred from the presence of a dependency.
- Build-profile and compiler-output review for each supported target.

The current comments in `src/low_level/poly.rs` and
`src/crypto/interpolation.rs` are local implementation notes. They are not a
formal timing proof, constant-time audit, or side-channel guarantee.

## Constant-Time Expectations

For production-labeled threshold ML-DSA code, reviewers should expect:

- Loops over secret material use public, fixed bounds such as ML-DSA parameter
  sizes, not secret-dependent lengths.
- Branches and early returns depend only on public inputs or on validation that
  happens before secret state is mixed into the computation.
- Table indices, slice offsets, and memory access patterns are independent of
  secret coefficients, shares, masks, and nonce material.
- Equality, norm, hint, and bound checks over secret-dependent values aggregate
  results without secret-dependent exits.
- Serialization length and frame shape are determined by public protocol
  parameters, not by secret-dependent values.
- Rejection sampling is analyzed both mathematically and operationally: public
  abort information, retry counts, timing, and evidence emission must fit the
  leakage model in `noise-rejection-proof-plan.md`.

These expectations are required review criteria. They are not currently
complete facts about this branch.

## Empirical Obligations

Before any production side-channel claim is made, the implementation should
ship reproducible empirical evidence. At minimum:

- dudect or equivalent Welch t-test timing suites for signing, partial signing,
  partial verification, aggregation, interpolation, norm checks, and encoding
  paths that touch secret material.
- ctgrind, valgrind-based secret-dependence checks, or an equivalent dynamic
  analysis for branches and memory accesses where supported by the target.
- Differential tests that separate public-input timing variance from
  secret-class timing variance.
- CI jobs or documented release-gate commands that run the selected timing
  suites in stable build profiles.
- Captured environment metadata: CPU model, OS, compiler version, Rust version,
  feature gates, optimization profile, and command lines.
- Regression policy for investigating statistically significant timing
  outliers instead of treating noisy results as passes.

Empirical tests are necessary but not sufficient. Passing dudect or ctgrind
does not replace code review, compiler-output inspection, formal leakage-model
work, or external audit.

## Current Repository Status

Current evidence is limited:

- `src/low_level/poly.rs` uses branch-free-looking arithmetic in narrow helper
  paths and explicitly says this is not a formal timing proof.
- `src/crypto/interpolation.rs` notes fixed exponent-loop shape for modular
  inversion but also says it is not a formal timing guarantee.
- `formal-security-theorem.md` includes implementation constant-time discipline
  as an assumption for production realization, not as a proved property.
- `noise-rejection-proof-plan.md` lists abort leakage and side-channel
  properties as remaining proof work.
- No dudect, ctgrind, compiler-output, or external side-channel audit artifacts
  are present in this checkout.

## Non-Goals

This document does not claim:

- Side-channel resistance or constant-time behavior for the current code.
- That branch-free source code implies constant-time machine code.
- That deterministic tests or benchmark reproducibility are timing evidence.
- That `zeroize` alone proves erasure or adaptive-security semantics.
- That simulation labels or scaffold arithmetic instantiate production
  ML-DSA-65.
- That public-input parsing must be constant-time before secret state is used.
- That one CPU, OS, compiler, or build profile establishes portability of a
  timing claim.

## Production Gate

A future production claim must name the exact backend, feature gates, target
platforms, build profiles, empirical test commands, audit artifacts, and
remaining leakage assumptions. Until then, side-channel and constant-time
language in this repository should be phrased as obligations, review targets, or
non-claims.
