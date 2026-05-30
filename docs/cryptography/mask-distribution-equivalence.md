# Mask Distribution Equivalence Worksheet
<a id="mask-distribution-equivalence"></a>

Date: 2026-05-27

Status: proof-route worksheet for `eps_mask`, not a completed mask-distribution
proof.

This worksheet isolates the H1 -> H2 hybrid step from
[rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md).  The
goal is to make the aggregate threshold mask term precise enough that a later
production construction can either prove exact equality to centralized
ML-DSA-65 mask sampling or carry an explicit statistical-distance term into
Theorem T1.

The focused theorem-closure batch for this route is
[eps-mask-theorem-closure.md](eps-mask-theorem-closure.md).

## MDE-0. Scope and Non-Claims
<a id="mde-scope"></a>

The threshold signing proof may not claim accepted-distribution equivalence
until the pre-rejection mask distribution is fixed. This document does not
select that production mask protocol. It defines the theorem target,
bad-event surface, and acceptance criteria that a selected additive,
Lagrange-weighted, MPC, or ideal mask generator must satisfy.

Current hazmat code and simulations are useful for transcript and aggregation
traceability, but they are not evidence that the aggregate mask has the
centralized ML-DSA-65 distribution.

## MDE-1. Theorem Target
<a id="mde-theorem-target"></a>
<a id="theorem-m-close-mask-distribution"></a>

For a fixed ML-DSA-65 public matrix `A_matrix`, public key `pk`, message-binding
digest `mu`, active set `A`, and retry context `rho`, define:

```text
Y_0  <- centralized ML-DSA-65 mask distribution
Y_T  <- production threshold mask generator for active set A and context rho
W0_1 = HighBits(A_matrix * Y_0)
WT_1 = HighBits(A_matrix * Y_T)
```

Theorem M-close-mask-distribution. The route closes `eps_mask` only after
proving either:

```text
Delta((Y_T, WT_1, rho), (Y_0, W0_1, rho)) = 0
```

or the explicit bound:

```text
Delta((Y_T, WT_1, rho), (Y_0, W0_1, rho))
  <= eps_mask_bound(lambda, A, rho).
```

If the latter form is used, `eps_mask_bound` remains a visible summand in
Theorem T1 and may not be silently rounded down to zero. The final value of
`eps_mask` is zero only if exact equality is proved.

## MDE-2. Candidate Protocol Families
<a id="mde-protocol-families"></a>

The production proof must choose exactly one mask-generation family before
closing this route:

| Family | CombineMask equation | Main proof burden |
| --- | --- | --- |
| Additive mask shares | `Y_T = sum_i y_i` over the active set | Show the sum has the centralized coefficient distribution, including support and rejection-retry freshness. |
| Lagrange-weighted mask shares | `Y_T = sum_i lambda_i(A) * y_i` | Show Lagrange scaling and active-set choice preserve the centralized mask distribution or quantify the deviation. |
| MPC/ideal mask generation | `Y_T = F_mask(ctx, A)` | Prove or assume the ideal functionality samples exactly from ML-DSA-65 and hides honest mask material. |
| Dealer-aided mask generation | `Y_T` reconstructed from committed dealer material | Prove dealer consistency, complaint handling, and that accepted dealer outputs are unbiased. |

The proof must bind this choice to the transcript in
[formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md).
Changing families changes the theorem statement.

## MDE-3. Bad-Event Decomposition
<a id="mde-bad-events"></a>

The `eps_mask` route decomposes into the following bad events unless the chosen
construction proves exact equality directly:

```text
eps_mask
  <= eps_mask_support
   + eps_mask_entropy
   + eps_mask_highbits
   + eps_mask_active_set
   + eps_mask_retry_freshness
   + eps_mask_corrupt_bias.
```

| Event | Meaning | Closure requirement |
| --- | --- | --- |
| `eps_mask_support` | `Y_T` leaves the ML-DSA-65 coefficient/module support or samples it with wrong weights. | Parameter-specific proof for all `l * 256` mask coefficients. |
| `eps_mask_entropy` | Honest mask material is predictable or reused across attempts. | CSPRNG, domain separation, retry uniqueness, and erasure model. |
| `eps_mask_highbits` | `HighBits(A_matrix * Y_T)` has a distributional mismatch even if `Y_T` is close. | Prove the public high-bit map preserves the claimed distance or include the induced loss. |
| `eps_mask_active_set` | Different protocol phases use different active signer sets. | Canonical active-set binding across mask openings, challenge, contribution proofs, reconstruction, and output. |
| `eps_mask_retry_freshness` | Rejected attempts reuse mask seeds or transcript inputs. | Injective retry context `rho` and no replay of accepted or rejected mask openings. |
| `eps_mask_corrupt_bias` | Corrupted pre-challenge contributions bias the aggregate distribution. | Prove corrupted inputs are fixed before `H_c`, excluded by verification, or charged to this term rather than to `eps_withhold`. |

## MDE-4. Code and Artifact Crosswalk
<a id="mde-code-crosswalk"></a>

Current implementation evidence is limited to shape and regression guards:

- `src/low_level/mldsa65.rs` contains hazmat masking-contribution derivation
  and aggregate attempt paths used by tests.
- `tests/hazmat_mldsa65_threshold_bridge.rs` exercises selected aggregate
  consistency paths.
- `tests/hazmat_mldsa65_hardening.rs` rejects malformed masking contribution
  encodings.
- `tests/hazmat_mldsa65_actor.rs` and
  `tests/hazmat_mldsa65_simulation_grid.rs` exercise ordering and modeled
  retries.
- [rejection-sampling-bounds.md](rejection-sampling-bounds.md) carries the
  symbolic `eps_mask` term into Theorem T1.

These artifacts do not prove `MDE-1`. They only prevent accidental removal of
interfaces that a later production proof needs.

## MDE-5. Acceptance Criteria
<a id="mde-acceptance-criteria"></a>

Before a manuscript can state that `eps_mask` is negligible or zero, all of
the following must be complete:

- A single production mask-generation family is selected and written as a
  parameter-specific algorithm.
- The coefficient support, module dimensions, seed expansion, retry context,
  and active-set binding match ML-DSA-65.
- The proof accounts for corrupted pre-challenge contributions without
  double-counting selective withholding.
- The high-bit value used by the challenge oracle is covered by the same
  distance bound as the mask, or by a separate displayed loss.
- The implementation crosswalk identifies the code path that enforces each
  precondition, and any unimplemented condition remains marked as open.

## MDE-6. Non-Claims
<a id="mde-non-claims"></a>

This worksheet does not prove that the current hazmat mask aggregation is
distributed like centralized ML-DSA-65 signing. It does not prove
commitment-hiding, contribution soundness, malicious-secure DKG, adaptive
security, or production randomness quality. It is a route for closing
`eps_mask`, not the closure itself.
