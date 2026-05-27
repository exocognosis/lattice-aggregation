# Rejection-Sampling Bounds Worksheet
<a id="rejection-sampling-bounds"></a>

Date: 2026-05-27

Status: bound-oriented proof worksheet, not a completed proof.

This worksheet refines the hybrid skeleton in
`rejection-sampling-hybrid-proof.md` into the inequalities and advantage terms
that still need proof for threshold ML-DSA-65 rejection sampling. It is not a
completed proof and must not be read as a claim that the current threshold
backend preserves the centralized ML-DSA signing distribution.

## Scope

The target is the H2 through H6 gap in the rejection-sampling hybrid:
threshold mask generation, commit-before-challenge ordering, partial response
aggregation, aggregate rejection, abort behavior, and accepted-signature
distribution. The current hazmat code and tests provide implementation
checkpoints for selected ML-DSA-65 arithmetic paths, but they do not establish
the distributional or selective-abort theorem.

This worksheet uses symbolic proof parameters first. Where the hazmat
implementation defines ML-DSA-65 constants, they are recorded as current
implementation evidence, not as a completed parameter proof.

## Notation and Parameters

Let:

- `q` be the ML-DSA modulus and `R_q = Z_q[X] / (X^256 + 1)`.
- `k = K_65`, `l = L_65`, and `n = 256` be the ML-DSA-65 module dimensions.
- `A` be the active signer set, with `|A| >= t`.
- `lambda_i(A)` be the Lagrange coefficient at zero for signer `i in A`.
- `y_i` be local masking material, and `y` the aggregate mask.
- `s1_i`, `s2_i`, and `t0_i` be threshold shares of ML-DSA secret terms.
- `c` be the challenge polynomial sampled from `c_tilde`.
- `tau_65` be the challenge Hamming weight.
- `eta_65` be the secret coefficient range parameter.
- `beta_65 = tau_65 * eta_65`.
- `gamma1_65`, `gamma2_65`, and `omega_65` be the ML-DSA-65 rejection
  parameters.
- `B_z = gamma1_65 - beta_65`.
- `B_low = gamma2_65 - beta_65`.
- `B_ct0 = gamma2_65`.
- `B_h = omega_65`.

Current hazmat constants in `src/low_level/mldsa65.rs` instantiate:

```text
K_65 = MLDSA65_K = 6
L_65 = MLDSA65_L = 5
tau_65 = MLDSA65_TAU = 49
eta_65 = MLDSA65_ETA = 4
beta_65 = MLDSA65_BETA = MLDSA65_TAU * MLDSA65_ETA
gamma1_65 = MLDSA65_GAMMA1 = 2^19
gamma2_65 = MLDSA65_GAMMA2 = (q - 1) / 32
omega_65 = MLDSA65_OMEGA = 55
B_z = MLDSA65_Z_NORM_BOUND = MLDSA65_GAMMA1 - MLDSA65_BETA
```

The proof still needs to cite the external ML-DSA-65 parameter source and show
that the production backend uses exactly those constants, encodings, and
strict inequalities.

## Algebraic Equalities to Condition On

For each accepted aggregate attempt, the proof must establish the same
single-signer algebraic relations that centralized ML-DSA uses:

```text
s1 = sum_{i in A} lambda_i(A) * s1_i
s2 = sum_{i in A} lambda_i(A) * s2_i
t0 = sum_{i in A} lambda_i(A) * t0_i
y  = CombineMask({y_i}_{i in A})
c  = H_c(mu, HighBits(w)) or the stated equivalent challenge input
z  = y + c * s1
r0 = LowBits(w - c * s2)
h  = MakeHint(-c * t0, w - c * s2 + c * t0)
```

If the construction uses Lagrange-weighted mask reconstruction, then the mask
combiner must be:

```text
y = sum_{i in A} lambda_i(A) * y_i
```

If it uses additive masking or an MPC-generated shared mask, the proof must
replace the equation above and prove that the resulting `y` has the
centralized ML-DSA-65 mask distribution or an explicit statistical-distance
bound.

## Local Inequalities

Local checks are useful for accountability and liveness, but they are not
sufficient to prove final ML-DSA rejection sampling. The local predicate must
be specified for the selected threshold construction.

For every signer `i` that releases a partial response, a candidate local
predicate has this shape:

```text
LocalAccept_i(transcript, com_i, c, z_i, proof_i) =
    c = H_c(sid, t, V, pk, mu or m, Com)
    and z_i = y_i + c * s1_i
    and ||z_i||_inf < B_z_local
    and hint_count(h_i) <= B_h_local, if local hints are emitted
    and VerifyPartial(com_i, c, z_i, proof_i, public_share_metadata_i) = accept
```

Open inequalities:

```text
B_z_local <= ?
B_h_local <= ?
Pr[LocalAccept_i leaks share information through abort label] <= eps_local_abort
```

The proof must decide whether local rejection results are hidden until an
aggregate decision or are observable participant-specific abort events. If
local abort labels are observable, the simulator must reproduce them from
public transcript data plus allowed abort leakage.

## Aggregate Inequalities

Aggregate acceptance must be checked on the exact values encoded in the final
standard ML-DSA signature:

```text
AggregateAccept(pk, mu, A, Com, c_tilde, z, h) =
    c_tilde = H_c(mu, w1)
    and c = SampleInBall(c_tilde)
    and weight(c) = tau_65
    and ||z||_inf < B_z
    and ||LowBits(w - c * s2)||_inf < B_low
    and ||c * t0||_inf < B_ct0
    and weight(h) <= B_h
    and sigma = Encode(c_tilde, z, h)
    and MLDSA65.Verify(pk, m or mu, sigma) = accept
```

Using ML-DSA-65 symbolic parameters, the bound obligations are:

```text
forall a in coeffs(z): |center(a)| < gamma1_65 - beta_65
forall a in coeffs(LowBits(w - c * s2)): |a| < gamma2_65 - beta_65
forall a in coeffs(c * t0): |center(a)| < gamma2_65
weight(h) <= omega_65
weight(c) = tau_65
```

The strict-vs-nonstrict form matters. The hazmat implementation rejects when:

```text
||z||_inf >= MLDSA65_Z_NORM_BOUND
||LowBits(w - c*s2)||_inf >= MLDSA65_GAMMA2 - MLDSA65_BETA
||c*t0||_inf >= MLDSA65_GAMMA2
weight(h) > MLDSA65_OMEGA
```

The production proof must show these checks match the standard verifier's
centered coefficient interpretation, module-vector dimensions, hint encoding,
and challenge encoding.

## Aggregate Rejection Mismatch

Let `Reject_0` be the centralized ML-DSA rejection predicate and
`Reject_T` be the threshold aggregate rejection predicate for the same
`pk`, `mu`, reconstructed `y`, and `c`.

Define the aggregate rejection mismatch term:

```text
eps_rej =
  Delta(1[Reject_T(pk, mu, A, Com, c, z, h)],
        1[Reject_0(pk, mu, c, z, h)])
```

The desired theorem needs:

```text
eps_rej <= eps_bound_encoding
         + eps_hint_encoding
         + eps_challenge_encoding
         + eps_active_set_mismatch
```

Each term must be negligible or explicitly accounted for in the final theorem.
Tests that hit accepted and rejected hazmat examples are evidence that code
paths exist; they do not bound `eps_rej`.

## Abort Probability and Retry Bounds

Let `p_acc^0` be the centralized ML-DSA per-attempt acceptance probability and
`p_acc^T` be the threshold per-attempt acceptance probability under the chosen
adversary model.

The proof must bound:

```text
|p_acc^T - p_acc^0| <= eps_mask + eps_rej + eps_abort
Pr[success within R attempts] = 1 - (1 - p_acc^T)^R
Pr[all R attempts abort] = (1 - p_acc^T)^R
E[attempts until success] = 1 / p_acc^T
```

For adversarial withholding, let `W_r` be the event that corrupted parties
withhold after observing round `r` public data, and let `R_max` be the
session retry limit. A worksheet-level bound shape is:

```text
eps_abort <= Pr[exists r <= R_max: W_r changes conditioned challenge view]
           + Delta(View_with_abort_labels, SimulatedView)
           + Pr[retry transcript reuses mask or challenge material]
```

The actual proof must instantiate the network model, timeout policy, exclusion
rules, retry IDs, and evidence semantics from `active-adversary-model.md`.
Availability and denial of service must be stated separately from signature
distribution preservation.

## Selective-Abort Advantage Decomposition

For any distinguisher `D` comparing accepted threshold signatures to accepted
centralized ML-DSA signatures, use the worksheet decomposition:

```text
Adv_rej_sampling(D)
  <= eps_mask
   + eps_commit
   + eps_rej
   + eps_withhold
   + eps_ro
   + eps_verify
```

where:

- `eps_mask` bounds the distance between the aggregate threshold mask
  distribution and centralized ML-DSA mask distribution before conditioning on
  acceptance.
- `eps_commit` bounds commitment binding failures, equivocation after
  challenge derivation, and mismatch between the committed set `Com` and the
  opened or verified contribution set.
- `eps_rej` bounds mismatch between threshold aggregate rejection and
  centralized ML-DSA rejection on `z`, low bits, `ct0`, hints, and challenge
  weight.
- `eps_withhold` bounds network and adversarial withholding, including
  corrupted-party selective aborts after seeing commitments or challenges,
  retry-limit effects, and participant-specific abort labels.
- `eps_ro` bounds random-oracle programming, transcript collision, replay, and
  domain-separation losses from `random-oracle-game.md`.
- `eps_verify` bounds any gap between the aggregate predicate and unmodified
  standard ML-DSA-65 verification.

The four mandatory terms for the current proof gap are:

```text
eps_mask        masking distribution
eps_commit      commitment binding / non-adaptivity
eps_rej         aggregate rejection mismatch
eps_withhold    network and adversarial withholding
```

No current document proves these terms negligible.

## Evidence and Remaining Work

| Bound or term | Current evidence | Remaining proof work |
| --- | --- | --- |
| `B_z = gamma1_65 - beta_65` for aggregate `z` | `src/low_level/mldsa65.rs` defines `MLDSA65_Z_NORM_BOUND`; `finalize_mldsa65_threshold_response` rejects `||z||_inf >= B_z`; hazmat bridge tests check accepted response polynomials satisfy `check_noise_bounds(B_z)`. | Cite the external ML-DSA-65 parameter theorem; prove centered conversion and strict inequality match the standard verifier for all `l` response polynomials; add complete boundary proof/tests. |
| `B_low = gamma2_65 - beta_65` for `LowBits(w - c*s2)` | `finalize_mldsa65_threshold_signature_attempt` rejects low-bit infinity norm at `>= MLDSA65_GAMMA2 - MLDSA65_BETA`. | Prove the threshold `w`, `cs2`, and low-bit decomposition are bit-for-bit the centralized ML-DSA values; prove module-vector coverage and boundary behavior. |
| `B_ct0 = gamma2_65` for `c*t0` | `finalize_mldsa65_threshold_signature_attempt` rejects `secret.ct0` at `>= MLDSA65_GAMMA2`. | Prove reconstructed `ct0` equals centralized `c*t0`; prove centered coefficient interpretation and verifier equivalence. |
| `B_h = omega_65` for hint weight | `MLDSA65_OMEGA` is defined as `55`; signature finalization rejects `hint.weight() > MLDSA65_OMEGA`; hint packing enforces canonical offsets and unused slots. | Prove `MakeHint` and hint encoding are exactly standard ML-DSA-65; prove malformed hints and boundary cases cannot enter accepted signatures. |
| `weight(c) = tau_65` | `MLDSA65_TAU` is defined as `49`; `sample_in_ball` uses the challenge seed to produce the challenge polynomial. | Prove the sampler always outputs exactly `tau_65` signed nonzero coefficients, prove challenge encoding canonicality, and map `c_tilde` to the standard verifier challenge. |
| `eps_mask` | Hazmat masking contributions are aggregated and are domain-separated by validator in tests. | Define the real mask-sharing protocol and prove aggregate `y` is exactly centralized ML-DSA distributed or within a quantified statistical distance. |
| `eps_commit` | Session APIs require masking contributions before challenge derivation and reject out-of-order secret contributions; `random-oracle-game.md` defines commitment and challenge oracle obligations. | Instantiate binding/hiding commitments, prove non-adaptivity under rushing, and prove the committed set equals the opened contribution set. |
| `eps_rej` | Hazmat finalization checks `z`, low bits, `ct0`, hint weight, stale challenge, and selected standard internal-`mu` verification examples. | Prove aggregate and centralized rejection predicates are identical, including strictness, all encodings, active-set consistency, and malformed input rejection. |
| `eps_withhold` | `active-adversary-model.md` identifies rushing and selective aborts; session tests cover duplicate, stale, insufficient, and rejected phases. | Formalize retry limits, timeout/exclusion policy, abort observables, simulator behavior, and statistical distance from conditioning on adversarial withholding. |
| `eps_ro` | `random-oracle-game.md` gives typed domains for `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib`. | Prove byte-level injectivity, domain separation, replay resistance, concurrent session safety, and simulator programming losses. |
| `eps_verify` | Hazmat tests include standard internal-`mu` verification for accepted aggregate examples. | Decide external-message versus internal-`mu` theorem statement and prove every emitted aggregate signature verifies under the unmodified standard ML-DSA-65 API. |

## Top Missing Mathematical Bounds

The three largest missing mathematical bounds are:

1. A bound for `eps_mask`, the statistical or computational distance between
   aggregate threshold masks and centralized ML-DSA-65 masks before rejection.
2. A bound for `eps_withhold`, the selective-abort advantage from corrupted
   validators withholding after commitments or challenges, including retry and
   abort-label leakage.
3. A bound for `eps_rej`, the mismatch between the aggregate threshold
   rejection predicate and the centralized ML-DSA rejection event over `z`,
   low bits, `ct0`, hints, and challenge weight.

Until those are completed, this file remains a worksheet and not a completed
proof.
