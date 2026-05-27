# Noise-Bound Proof Outline for Threshold ML-DSA-65

Date: 2026-05-23

## Status

This document is a proof plan for the threshold ML-DSA-65 construction. It
records the lemmas, invariants, and implementation hooks required for a
publishable security argument.

It is not a completed proof. The current Rust crate contains deterministic
simulation scaffolding and must not be described as enforcing real ML-DSA-65
noise bounds.

The theorem scaffold and hybrid proof sequence that reference these lemmas are
tracked in `formal-proof-scaffold.md`.

## Problem Statement

ML-DSA uses Fiat-Shamir with aborts. A valid signature response must satisfy
strict bounds on response and hint data. In a threshold construction, the final
response is assembled from multiple partial contributions:

```text
z = Combine({z_i}_{i in S})
```

for active signing subset `S`, `|S| >= t`.

The proof must show that the distribution and bounds of `z` are compatible with
the standard ML-DSA-65 verifier.

## Informal Signing Equation

For each validator `i`:

```text
z_i = y_i + c * s1_i
```

where:

- `y_i` is local masking material.
- `c` is the Fiat-Shamir challenge derived after commitments.
- `s1_i` is the validator's share of the ML-DSA secret component.

For Lagrange reconstruction over subset `S`:

```text
lambda_i = product_{j in S, j != i} x_j / (x_j - x_i) mod q
s1       = sum_{i in S} lambda_i * s1_i
y        = sum_{i in S} lambda_i * y_i
z        = sum_{i in S} lambda_i * z_i
         = y + c * s1
```

The algebraic identity is tested by the scaffold's VSS and interpolation code,
but the distributional and rejection-sampling arguments remain open.

## Rust Mapping

```text
coefficient polynomial       -> src/low_level/poly.rs::Poly
modular addition             -> Poly::add_assign
norm check scaffold          -> Poly::check_noise_bounds
VSS evaluation               -> src/crypto/vss.rs::evaluate_polynomial_at
share splitting scaffold     -> src/crypto/vss.rs::split_secret_poly
Lagrange coefficient         -> src/crypto/interpolation.rs::compute_lagrange_coefficient
share reconstruction         -> src/crypto/interpolation.rs::reconstruct_secret_poly
transcript challenge scaffold -> src/transcript.rs::SigningTranscript
```

## Required Bounds

A concrete proof must instantiate the ML-DSA-65 parameter bounds for:

- local masking vector domain
- final response vector `z`
- low bits of `w - c*s2`
- hint vector cardinality
- rejection threshold for `z`
- rejection threshold for hint data
- maximum restart count policy

This document uses symbolic bounds until the real backend is selected:

```text
B_y    local masking support bound
B_s1   secret-share bound
B_s2   second secret-share bound
B_z    final response infinity-norm bound
B_h    hint cardinality bound
B_c    challenge coefficient weight/bound
```

## Lemma 1: VSS Reconstruction Correctness

Statement:

Given a degree `< t` polynomial `f` over the field induced by `q`, and any
subset `S` of at least `t` distinct nonzero validator indices, Lagrange
reconstruction at zero recovers:

```text
f(0) = sum_{i in S} lambda_i * f(i)
```

Implementation status:

- Algebraic scaffold exists in `src/crypto/vss.rs` and
  `src/crypto/interpolation.rs`.
- Unit tests reconstruct deterministic polynomial secrets.

Open work:

- Reject duplicate active indices in interpolation input.
- Define behavior for index `0`.
- Add property tests over many random polynomial fixtures.
- Replace deterministic VSS masks with cryptographic randomness.

## Lemma 2: Challenge Binding

Statement:

For a fixed session, public key, message, validator set, threshold, and
commitment set, all honest validators derive the same challenge `c`, independent
of network ordering.

Implementation status:

- `SigningTranscript` binds session ID, threshold, validator set, public key,
  message, and canonical commitment set.
- Transcript determinism tests cover ordering independence.

Open work:

- Bind DKG epoch ID explicitly.
- Bind block height or consensus slot explicitly.
- Bind commitment openings when the real commitment scheme is selected.
- Domain-separate DKG, signing, evidence, and benchmark transcripts.

## Lemma 3: Commitment Non-Adaptivity

Statement:

No adversarial validator can choose or alter its masking contribution after
observing the challenge.

Required proof ingredients:

- Round 1 commitment scheme is binding.
- Challenge is derived only after a canonical threshold commitment set exists.
- Equivocation is detectable and attributable.

Implementation status:

- Actor requires `SignCommit` before peer `PartialSignature` data contributes
  meaningfully to a session.
- Evidence scaffolding exists.

Open work:

- Define commitment relation for `w_i`, `y_i`, or both.
- Implement commitment openings.
- Prove hiding where needed for masking privacy.

## Lemma 4: Local Rejection Soundness

Statement:

An honest validator only emits `z_i` when its local contribution satisfies the
protocol's rejection predicate.

Symbolic predicate:

```text
LocalAccept_i =
    ||z_i||_infty < B_z_local
    and hint_count(h_i) <= B_h_local
    and VerifyPartial(C_i, z_i, h_i, c, public_dkg_data) = true
```

Implementation status:

- `Poly::check_noise_bounds` exists as a scaffold.
- Actor can reject poisoned byte-prefix shares in simulation.

Open work:

- Implement real `VerifyPartial`.
- Define local bounds in terms of ML-DSA-65 parameters.
- Add tests for edge coefficients at `B_z - 1`, `B_z`, and centered negative
  representatives.
- Add dudect tests for local rejection paths.

## Lemma 5: Aggregate Bound Preservation

Statement:

The aggregator accepts only if the final reconstructed response and hint data
satisfy standard ML-DSA-65 verification bounds:

```text
||z||_infty < B_z
hint_count(h) <= B_h
```

Challenge:

Even if all local shares pass local checks, Lagrange-weighted recombination can
increase coefficient magnitude unless the protocol is designed to preserve the
ML-DSA response distribution.

Required proof ingredients:

- Define the distribution of shared `y_i`.
- Define whether `y` is sampled directly as a shared secret or reconstructed
  from additive masks.
- Bound the effect of Lagrange coefficients on coefficient magnitude.
- Show rejection sampling restores the exact or statistically close target
  distribution.

Implementation status:

- `reconstruct_secret_poly` demonstrates algebraic recombination.
- `SimulatedAggregator` does not enforce real ML-DSA bounds.

Open work:

- This is the main cryptographic gap.
- A publishable construction must solve this before claiming standard
  ML-DSA-compatible threshold signing.

## Lemma 6: Abort-Bias Bound

Statement:

Adversarial aborts do not let corrupted validators bias the final challenge or
signature distribution beyond negligible distance.

Attack:

Corrupted validators may commit, observe `c`, and then withhold partial shares
if the challenge is unfavorable.

Required proof ingredients:

- Bound maximum retries per session or epoch.
- Bind retries to fresh session IDs and transcript counters.
- Penalize or exclude repeated aborting validators.
- Model abort probability and statistical distance from the target signature
  distribution.

Implementation status:

- Actor tracks timeout evidence and retry-like telemetry.
- Exporter reports abort averages.

Open work:

- Formal abort policy.
- Statistical analysis of selective aborts.
- Consensus policy for liveness penalties versus cryptographic slashing.

## Lemma 7: Standard Verification Compatibility

Statement:

The final signature bytes `sigma` output by aggregation satisfy unmodified
ML-DSA-65 verification.

Required equation:

```text
Verify_MLDSA65(pk_epoch, M, sigma) = accept
```

Implementation status:

- Constants match ML-DSA-65 public key and signature sizes.
- Simulation backend explicitly does not implement standard verification.

Open work:

- Integrate real ML-DSA-65 verifier.
- Generate known-answer tests.
- Add an integration test where the threshold aggregate is verified by a
  standard verifier that has no threshold-specific logic.

## Implementation Proof Obligations

Before publication, each proof lemma must map to an executable test or review
artifact:

| Obligation | Required Artifact |
| --- | --- |
| VSS correctness | property tests for reconstruction over random polynomial fixtures |
| Challenge binding | transcript test vectors and domain-separation table |
| Commitment binding | commitment scheme proof and negative tests |
| Partial verification | malformed partial fuzz target |
| Aggregate bounds | coefficient-bound tests around all threshold edges |
| Abort-bias analysis | analytical bound plus simulation artifact |
| Standard verification | KAT-style aggregate verification test |
| Constant-time behavior | dudect or equivalent timing report |

## Minimum Publication Bar

The project is logically and mathematically rigorous enough for submission only
after:

1. A concrete threshold ML-DSA construction is selected and specified.
2. Lemmas 1 through 7 are proven or scoped with explicit limitations.
3. The Rust implementation matches the mathematical spec line by line.
4. All randomness is cryptographically sampled.
5. Final signatures verify with a standard ML-DSA-65 verifier.
6. The benchmark runner emits reproducible artifacts from a fixed environment.
7. The paper clearly separates proven cryptography from systems integration
   engineering.

## Recommended Next Technical Step

Implement a `hazmat-real-mldsa` backend behind a feature flag with:

- real ML-DSA polynomial packing/unpacking
- real NTT/inverse NTT paths
- real challenge derivation compatible with FIPS 204
- real standard verification test vectors

Do not extend benchmark claims until this backend exists.
