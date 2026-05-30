# Rejection-Sampling Bounds Worksheet
<a id="rejection-sampling-bounds"></a>

Date: 2026-05-27

Status: bound-oriented proof worksheet, not a completed proof.

This worksheet refines the hybrid skeleton in
`rejection-sampling-hybrid-proof.md` into the inequalities and advantage terms
that still need proof for threshold ML-DSA-65 rejection sampling. It is not a
completed proof and must not be read as a claim that the current threshold
backend preserves the centralized ML-DSA signing distribution.

The consolidated theorem-closure batch for `eps_mask`, `eps_rej`, and
`eps_withhold` is tracked in
[rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md).

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

<a id="theorem-conditional-accepted-distribution-bound"></a>

## Theorem T1: Conditional Accepted-Distribution Bound

Status: theorem statement and proof-obligation decomposition. This theorem is
not yet proved.

Let `Dist_T^acc(pk, m)` be the distribution of accepted threshold aggregate
signatures output by the H6 game in
[`rejection-sampling-hybrid-proof.md#rsh-h6-accepted-signature-distribution`](rejection-sampling-hybrid-proof.md#rsh-h6-accepted-signature-distribution).
Let `Dist_0^acc(pk, m)` be the accepted-signature distribution of centralized
ML-DSA-65 signing in H0 for the same public key and message binding. Define:

```text
Delta_accept =
  Delta(Dist_T^acc(pk, m), Dist_0^acc(pk, m))
```

where `Delta` denotes the distinguishing advantage of the accepted-signature
distribution experiment for the adversary class fixed by
`active-adversary-model.md`.

Conditional bound:

```text
Delta_accept
  <= eps_mask
   + eps_rej
   + eps_withhold
   + eps_ro
   + eps_commit
```

This bound intentionally omits `eps_verify` as a separate summand only under
the precondition that the aggregate predicate includes unmodified standard
ML-DSA-65 verification, or that `eps_verify` has been folded into `eps_rej` as
an encoding-and-predicate mismatch term. If the production theorem keeps a
separate verifier-compatibility gap, the bound must instead add `eps_verify`.

Definitions:

- `eps_mask = Delta(Y_T, Y_0)` for the pre-challenge aggregate threshold mask
  distribution `Y_T` and centralized ML-DSA-65 mask distribution `Y_0`,
  including the public high-bit value used to derive the challenge.
- `eps_rej = Delta(1[Reject_T], 1[Reject_0])` after fixing the same
  `pk`, `mu`, `c`, reconstructed algebraic terms, and encoded candidate
  signature fields.
- `eps_withhold = Delta(View_with_abort_labels, SimulatedView)` plus the
  probability that adversarial withholding changes the conditioned challenge
  view outside the allowed abort leakage.
- `eps_ro` is the loss from the typed random-oracle game in
  `random-oracle-game.md`, including prior-query, replay, transcript-collision,
  and domain-separation bad events.
- `eps_commit` is the loss from commitment binding, equivocation,
  non-adaptivity, and mismatch between the commitment set `Com` used for
  `H_c` and the contribution set accepted by aggregation.

Preconditions:

- The H1 shared-secret decomposition is correct for `s1`, `s2`, and `t0` over
  the exact active set `A`, as required by `correctness-lemmas.md` Lemma 2,
  Lemma 3, and Lemma 6.
- Every attempt uses a fresh, domain-separated retry context and fresh masking
  material; no accepted attempt reuses a mask, challenge, or commitment tuple
  from an aborted attempt.
- Honest commitments are fixed before `H_c` is queried, and every accepted
  contribution proves consistency with the exact commitment in `Com`.
- The aggregate rejection predicate is evaluated on the exact `z`, low bits,
  `ct0`, hint vector, challenge, and signature encoding that are output or
  verified.
- Abort observables are exactly the observables modeled in the active
  adversary game: local abort labels if exposed, aggregate rejection, retry
  count, timeout or withholding evidence, message sizes, and timing only to the
  extent included by the side-channel boundary.
- The random-oracle domains and encodings are the typed domains in
  `random-oracle-game.md`, and byte-level injectivity or collision losses are
  accounted for in `eps_ro`.

Proof sketch:

1. Move from H0 to H2 by replacing the centralized mask with the threshold
   aggregate mask. The distance paid is `eps_mask`, after H1 supplies the same
   reconstructed secret terms.
2. Insert commit-before-challenge ordering and contribution-set binding. The
   distance paid is `eps_commit`, with random-oracle programming losses charged
   separately to `eps_ro`.
3. Replace centralized rejection by aggregate rejection over reconstructed
   threshold values. The distance paid is `eps_rej`.
4. Condition on accepted attempts while accounting for adversarial withholding,
   retry limits, and abort-label observables. The distance paid is
   `eps_withhold`.
5. Apply the typed random-oracle game for challenge derivation, replay
   resistance, concurrent sessions, and simulator programming. The distance
   paid is `eps_ro`.
6. By the triangle inequality over the hybrid chain, the accepted output
   distributions differ by at most the sum above.

Formalized in this worksheet:

- The symbolic theorem shape for `Delta_accept`.
- The precondition list needed before the bound can be invoked.
- The assignment of mask, rejection, withholding, commitment, and
  random-oracle losses to specific proof steps.

Open:

- Proving any of `eps_mask`, `eps_rej`, `eps_withhold`, `eps_ro`, or
  `eps_commit` negligible or giving concrete symbolic upper bounds.
- Deciding whether the final production theorem keeps `eps_verify` separate or
  absorbs it into `eps_rej`.
- Instantiating the adversary class, retry limit, commitment scheme, and
  production threshold mask protocol.

## Sub-Lemma M: `eps_mask` Mask-Distribution Bound

Statement:

```text
eps_mask =
  Delta((Y_T, HighBits(PublicMatrix*Y_T)),
        (Y_0, HighBits(PublicMatrix*Y_0)))
```

where `Y_T = CombineMask({y_i}_{i in A})` is the aggregate threshold mask for a
fixed active set and retry context, and `Y_0` is the centralized ML-DSA-65 mask
sample before rejection.

Required proof shape:

```text
eps_mask <= eps_mask_share
          + eps_mask_combine
          + eps_mask_corrupt_bias
          + eps_mask_retry
```

The terms are symbolic obligations:

- `eps_mask_share` accounts for local `y_i` sampling not matching the chosen
  threshold protocol's required distribution.
- `eps_mask_combine` accounts for Lagrange, additive, or MPC combination
  changing the support or coefficient distribution of the aggregate `y`.
- `eps_mask_corrupt_bias` accounts for corrupted parties biasing their
  contributions before the challenge, excluding events charged to withholding.
- `eps_mask_retry` accounts for retry contexts failing to produce fresh,
  independent mask material.

Proof sketch:

1. Fix `pk`, `mu`, active set `A`, and an attempt identifier before
   commitment publication.
2. Couple honest local mask generation to the production threshold mask
   protocol.
3. Prove `CombineMask` maps the coupled local shares to a sample distributed
   as `Y_0`, or bound the resulting statistical distance by
   `eps_mask_share + eps_mask_combine`.
4. Treat maliciously chosen but pre-challenge contributions as public inputs
   and charge any remaining bias to `eps_mask_corrupt_bias`.
5. Use retry domain separation to show aborted attempts do not condition future
   masks except through `eps_mask_retry`.

Current formalization:

- The algebraic shape of `CombineMask` is recorded above for Lagrange-weighted
  masks and must be replaced if the selected protocol uses additive or MPC
  mask generation.
- Hazmat evidence shows `aggregate_mldsa65_masking_contributions` currently
  sums local `y_i` and `w_i` values, validates duplicate participants, and
  derives `w1`; the test bridge checks aggregate consistency for selected
  examples.

Exact remaining missing steps:

- Select the production mask-sharing protocol and state whether
  `CombineMask` is additive, Lagrange-weighted, or MPC-generated.
- Prove the aggregate `y` distribution has the centralized ML-DSA-65 support
  and min-entropy, or state an explicit symbolic statistical-distance bound.
- Prove the public value used for challenge derivation,
  `HighBits(PublicMatrix*y)`, is distributed as in centralized ML-DSA-65 under
  the same coupling.
- Prove retry identifiers, attempt counters, and masking seeds are injectively
  encoded and never reused after rejection.
- Separate corrupted-party bias before challenge from corrupted-party
  withholding after challenge, so the same event is not charged to both
  `eps_mask` and `eps_withhold`.

## Sub-Lemma R: `eps_rej` Aggregate-Rejection Bound

Statement:

```text
eps_rej =
  Delta(1[Reject_T(pk, mu, A, Com, c, z, h)],
        1[Reject_0(pk, mu, c, z, h)])
```

for the same reconstructed candidate values. The goal is to make
`Reject_T = Reject_0` except on explicitly listed encoding, active-set, or
verification bad events.

Required proof shape:

```text
eps_rej <= eps_bound_encoding
         + eps_hint_encoding
         + eps_challenge_encoding
         + eps_active_set_mismatch
         + eps_verify_mismatch
```

The term `eps_verify_mismatch` is symbolic and may be set to zero only after
the theorem proves that aggregate acceptance includes standard ML-DSA-65
verification on the final wire signature or an exactly equivalent predicate.

Proof sketch:

1. Use H1 and H4 to fix the same algebraic candidate values
   `z`, `LowBits(w - c*s2)`, `c*t0`, `h`, and `c_tilde`.
2. Show threshold acceptance checks the same strict inequalities as
   centralized ML-DSA-65:

```text
||z||_inf < B_z
||LowBits(w - c*s2)||_inf < B_low
||c*t0||_inf < B_ct0
weight(h) <= B_h
weight(c) = tau_65
```

3. Show centered coefficient conversion, low-bit decomposition,
   `MakeHint`, challenge sampling, and signature packing are canonical and
   bit-for-bit equal to the centralized verifier inputs.
4. Charge any mismatch in strictness, encoding, active-set consistency, or
   verifier equivalence to the listed symbolic terms.

Current formalization:

- The worksheet states all aggregate inequalities and the strict rejection
  forms used by the hazmat functions.
- Hazmat evidence shows `finalize_mldsa65_threshold_response` rejects
  `||z||_inf >= B_z`, and
  `finalize_mldsa65_threshold_signature_attempt` rejects low-bit, `ct0`, and
  hint-weight failures before packing.

Exact remaining missing steps:

- Prove the centered representative used by each threshold norm check equals
  the centered representative in the standard ML-DSA-65 verifier.
- Prove `LowBits(w - c*s2)`, `c*t0`, and `MakeHint` are computed from exactly
  the centralized candidate values after reconstruction.
- Prove malformed hints, noncanonical offsets, challenge-weight mismatches,
  and signature-packing failures cannot enter accepted outputs.
- Prove the active set used for reconstructing `cs1`, `cs2`, and `ct0` is the
  same active set bound into commitments and contribution proofs.
- Decide whether standard verification is part of `Reject_T`; if not, keep
  `eps_verify_mismatch` visible in the final theorem.

## Sub-Lemma W: `eps_withhold` Selective-Withholding Bound

Statement:

```text
eps_withhold =
  Delta(View_with_abort_labels, SimulatedView)
```

with additional bad-event probability for corrupted parties changing the
conditioned challenge or accepted-signature distribution by withholding,
timing out, or forcing retries after observing allowed public data.

Required proof shape:

```text
eps_withhold <= eps_withhold_commit
              + eps_withhold_challenge
              + eps_abort_labels
              + eps_retry_limit
              + eps_timing_boundary
```

The terms are symbolic obligations:

- `eps_withhold_commit` covers withholding after observing honest commitments
  but before `H_c`.
- `eps_withhold_challenge` covers withholding after the challenge or partial
  contribution phase starts.
- `eps_abort_labels` covers participant-specific local abort labels and
  evidence records exposed to the adversary.
- `eps_retry_limit` covers conditioning introduced by a bounded retry policy.
- `eps_timing_boundary` covers observable timing and message-size leakage only
  to the extent included by `side-channel-boundary.md`.

Proof sketch:

1. Fix the corruption option and rushing semantics from
   `active-adversary-model.md`.
2. Define the exact abort transcript: missing commitments, missing secret
   contributions, local abort labels, aggregate rejection, duplicate or stale
   evidence, retry count, timeout/exclusion records, and final success.
3. Construct a simulator that emits the same public abort transcript from
   public data and allowed leakage, without honest secret shares or honest
   masks.
4. Show each retry uses fresh mask material and a typed oracle input distinct
   from every prior attempt.
5. Bound the difference between real and simulated abort-conditioned views by
   the symbolic terms above.

Current formalization:

- `active-adversary-model.md` allows rushing and selective aborts after honest
  commitments.
- `noise-rejection-proof-plan.md` lists local abort labels, aggregate aborts,
  retry counts, timing, message sizes, and slashing evidence as observables.
- Hazmat session tests exercise duplicate, stale, insufficient, rejected, and
  finalized phases, but do not prove a distributional abort bound.

Exact remaining missing steps:

- Choose static or adaptive corruptions and the production network abstraction
  before stating the final withholding game.
- Define retry limits, timeout policy, signer exclusion rules, and whether
  local honest aborts are hidden until the aggregate decision.
- Prove corrupted-party withholding is either denial of service only or is
  charged to a quantified distributional term.
- Prove evidence and telemetry do not reveal honest mask or secret-share
  information beyond the allowed abort transcript.
- Prove bounded retries do not change the accepted-signature distribution
  except through `eps_retry_limit`.

<a id="epsilon-closure-dependency-graph"></a>

## Epsilon Closure Dependency Graph

Status: conservative closure plan only. The routes below do not prove Theorem
T1 and do not assert that `eps_mask`, `eps_rej`, or `eps_withhold` are
negligible. They state what must be true before T1 can be invoked as a
publication-ready accepted-distribution bound for the H2 through H6 hybrid
chain.

```text
H1 algebraic reconstruction
  -> H2 mask distribution route (eps_mask)
  -> H3 commit-before-challenge and RO binding (eps_commit, eps_ro)
  -> H4 exact partial-response reconstruction
  -> H5 rejection-predicate route (eps_rej)
  -> H6 withholding and conditioning route (eps_withhold)
  -> Theorem T1 conditional Delta_accept bound
```

The graph is intentionally acyclic at the proof-obligation level. `eps_mask`
is a pre-rejection distribution term and must be closed before conditioning on
aggregate acceptance. `eps_rej` is a same-candidate predicate-equivalence term
and depends on H1/H4 algebra plus H5 encoding and verifier equivalence.
The predicate-level theorem target is now separated in
[rejection-predicate-equivalence.md](rejection-predicate-equivalence.md).
`eps_withhold` is a view and conditioning term at H6 and depends on the H2
freshness result and the H3 commitment-ordering result, but must not be used
to hide a mask-distribution or rejection-predicate mismatch.

<a id="eps-mask-closure-route"></a>

### eps-mask-closure-route

Route objective: instantiate Sub-Lemma M so the H1 -> H2 transition in the
hybrid map can replace centralized ML-DSA-65 mask sampling with threshold
mask generation before rejection conditioning.

Detailed theorem target, protocol-family split, and bad-event decomposition:
see [mask-distribution-equivalence.md](mask-distribution-equivalence.md).

Theorem-style obligation:

```text
Theorem M-close.
For every public key, message binding, active set A, retry context rho,
and adversary allowed by active-adversary-model.md before H_c is queried,
the production threshold mask generator outputs Y_T such that

Delta((Y_T, HighBits(A_matrix*Y_T), rho),
      (Y_0, HighBits(A_matrix*Y_0), rho))
  <= eps_mask_bound(lambda, A, rho),

where Y_0 is the centralized ML-DSA-65 mask distribution and
eps_mask_bound is either negligible in the security parameter or an explicit
symbolic summand carried unchanged into T1.
```

Acceptance criteria:

- The production mask protocol is fixed: additive, Lagrange-weighted, or
  MPC-generated, with the exact `CombineMask` equation stated.
- The proof covers the full ML-DSA-65 mask support, coefficient ranges,
  module dimensions, seed expansion, rejection-retry context, and public
  high-bit value used by H3.
- Corrupted pre-challenge contributions are modeled as either fixed public
  inputs with a quantified bias term or are excluded by a verified protocol
  rule; the same event is not double-counted in `eps_withhold`.
- Retry identifiers and mask seeds are injective and fresh across all rejected
  attempts used by H6 conditioning.
- The final value of `eps_mask` in T1 is set to zero only if exact equality is
  proved; otherwise the explicit `eps_mask_bound` remains visible.

Exact blockers:

- No production-level mask-sharing distribution has been selected in this
  worksheet.
- The current hazmat aggregation evidence does not prove centralized ML-DSA
  support, min-entropy, or high-bit distribution for aggregate masks.
- The retry-freshness and transcript-binding argument is still symbolic.
- The adversarial pre-challenge bias boundary is not yet separated from
  selective withholding with a formal game hop.

<a id="eps-rej-closure-route"></a>

### eps-rej-closure-route

Route objective: instantiate Sub-Lemma R so the H4 -> H5 transition in the
hybrid map can replace centralized rejection by threshold aggregate rejection
on the same reconstructed candidate values.

Detailed predicate map: see
[rejection-predicate-equivalence.md](rejection-predicate-equivalence.md), which
breaks `eps_rej` into centered-bound, low-bit, `ct0`, hint, challenge,
active-set, signature-encoding, and verifier-mismatch bad events.

Theorem-style obligation:

```text
Theorem R-close.
Conditioned on H1 shared-secret reconstruction, H4 partial-response
reconstruction, and the exact candidate tuple
(pk, mu, c_tilde, c, z, LowBits(w - c*s2), c*t0, h),
the production aggregate predicate Reject_T differs from the centralized
ML-DSA-65 predicate Reject_0 only on explicitly enumerated bad events:

Delta(1[Reject_T], 1[Reject_0])
  <= eps_bound_encoding
   + eps_hint_encoding
   + eps_challenge_encoding
   + eps_active_set_mismatch
   + eps_verify_mismatch.
```

Acceptance criteria:

- The proof fixes whether unmodified standard ML-DSA-65 verification is part
  of `Reject_T`; if not, `eps_verify_mismatch` remains a separate visible
  T1 summand or a visible part of `eps_rej`.
- The strict inequalities for `z`, low bits, `c*t0`, hint weight, and
  challenge weight are shown bit-for-bit equivalent to the standard ML-DSA-65
  predicate under the same centered representatives.
- `LowBits`, `HighBits`, `MakeHint`, challenge sampling, signature packing,
  and verifier input formation are canonical over every module coefficient,
  not only tested examples.
- The active set bound into commitments, challenge derivation, contribution
  proofs, reconstruction, and final aggregation is the same set `A`.
- Every malformed, duplicate, stale, noncanonical, or boundary-value input is
  either rejected before output or charged to one of the displayed bad events.

Exact blockers:

- The worksheet has not yet supplied a full verifier-equivalence proof for the
  final wire signature.
- Boundary coverage for the strict norm thresholds and hint/challenge
  encodings remains evidence work, not a theorem.
- The active-set equality proof across H3, H4, and H5 is still open.
- The final theorem has not decided whether `eps_verify` is absorbed into
  `eps_rej` or remains separate from T1.

<a id="eps-withhold-closure-route"></a>

### eps-withhold-closure-route

Route objective: instantiate Sub-Lemma W so the H5 -> H6 transition in the
hybrid map can condition on accepted aggregate signatures without hiding a
selective-abort bias in the accepted distribution.

Detailed simulator target, abort-observable taxonomy, and symbolic
decomposition: see
[withholding-abort-bound.md](withholding-abort-bound.md).

Theorem-style obligation:

```text
Theorem W-close.
For the production corruption model, network abstraction, retry limit R_max,
timeout/exclusion policy, and abort-observable set O_abort, there exists a
simulator Sim that produces the adversary-visible H6 abort transcript from
public data and allowed leakage such that

Delta(View_with_abort_labels, SimulatedView)
  + Pr[withholding changes the conditioned challenge or accepted-signature
       distribution outside O_abort]
  <= eps_withhold_bound(lambda, R_max, O_abort).
```

Acceptance criteria:

- The proof states static versus adaptive corruption, rushing power, timeout
  semantics, signer exclusion rules, and the exact retry cap used by H6.
- Every observable abort label, evidence record, retry count, message size,
  and timing category is either simulated from public data or explicitly
  placed outside the distribution theorem as availability or side-channel
  leakage.
- Withholding before `H_c`, after `H_c`, and after partial contribution
  publication is separated into the symbolic terms
  `eps_withhold_commit`, `eps_withhold_challenge`, and `eps_abort_labels`.
- The simulator never needs honest secret shares or honest masks, relying only
  on H2 freshness, H3 commitment binding, H4 reconstruction soundness, and H5
  predicate equivalence.
- Bounded retries are proved to preserve the accepted distribution except for
  the explicit `eps_retry_limit` term, and denial-of-service probability is
  stated separately from `Delta_accept`.

Exact blockers:

- The production network and timeout/exclusion policy are not fixed in this
  worksheet.
- The abort transcript and side-channel boundary are not yet theorem-level
  objects.
- No simulator is currently defined for participant-specific abort labels or
  evidence records.
- The bounded-retry conditioning bound is still symbolic and cannot be
  declared negligible without a concrete `R_max`, acceptance probability lower
  bound, and freshness proof.

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
