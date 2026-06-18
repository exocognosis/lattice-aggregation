# Rejection-Sampling Theorem Closure Batch
<a id="rejection-sampling-theorem-closure"></a>

Status: theorem-closure batch for `eps_mask`, `eps_rej`, and
`eps_withhold`, not a completed accepted-distribution proof.

This document consolidates the rejection-sampling proof route needed by the
`FST-T1-IdealVSS` assembly. It imports the existing mask-distribution,
rejection-predicate, and withholding/abort worksheets and states the order in
which their residuals must be closed or carried into the final theorem.

It does not prove that accepted threshold signatures are distributed as
centralized ML-DSA-65 signatures. It does not prove production liveness,
side-channel security, or production readiness. Implementation evidence is not
cryptographic proof.

## RSTC-0. Scope and Non-Claim
<a id="rstc-scope-non-claim"></a>

The closure target is the H2 through H6 rejection-sampling route:

```text
H2 threshold mask distribution
 -> H3 commit-before-challenge and random-oracle binding
 -> H4 exact partial-response reconstruction
 -> H5 aggregate rejection predicate
 -> H6 accepted-output conditioning under withholding/retry behavior
```

The terms under consolidation are:

- `eps_mask`: pre-rejection distance between aggregate threshold masks and
  centralized ML-DSA-65 masks.
- `eps_rej`: same-candidate mismatch between threshold aggregate rejection and
  centralized ML-DSA-65 rejection.
- `eps_withhold`: selective-withholding, retry, timeout, abort-label, and
  evidence-view conditioning loss.

The batch keeps `eps_commit`, `eps_ro`, and `eps_verify` visible because the
rejection-sampling route depends on commitment non-adaptivity, random-oracle
binding, and verifier compatibility.

## RSTC-1. Theorem Target
<a id="rstc-theorem-target"></a>

Conditional accepted-distribution theorem:

```text
Theorem RSTC-Delta-accept.
For every PPT adversary A and environment Z in the static active corruption
model fixed by active-adversary-model.md, the accepted threshold output
distribution in H6 is within the following distance of centralized ML-DSA-65
accepted signing for the same public key and message binding:

Delta_accept(A,Z)
 <= eps_mask(A,Z)
  + eps_rej(A,Z)
  + eps_withhold(A,Z)
  + eps_commit(A,Z)
  + eps_ro(A,Z)
  + eps_verify(A,Z)
  + negl(lambda).
```

The theorem may omit `eps_verify` only if `eps_verify` is formally absorbed
into `eps_rej` by proving that aggregate acceptance includes unmodified
standard ML-DSA-65 verification or an exactly equivalent predicate.

This target is conditional. It becomes a proof only after `RSTC-3`,
`RSTC-4`, and `RSTC-5` are discharged under one fixed production protocol.

## RSTC-2. Dependency Order
<a id="rstc-dependency-order"></a>

The route must be closed in this order:

```text
FST-L1..FST-L3 transcript and collection closure
 -> FST-L4..FST-L7 contribution, aggregation, threshold, and abort closure
 -> eps_mask pre-rejection distribution closure
 -> eps_commit and eps_ro challenge-binding closure
 -> eps_rej same-candidate predicate closure
 -> eps_withhold accepted-output conditioning closure
 -> Delta_accept bound usable by FST-T1-IdealVSS
```

The order prevents proof-term double counting:

- `eps_mask` handles distribution before challenge and rejection
  conditioning.
- `eps_rej` handles predicate mismatch on fixed candidate values only.
- `eps_withhold` handles view and conditioning effects after the mask and
  predicate routes have been separated.

## RSTC-3. eps_mask Closure Route
<a id="rstc-eps-mask-route"></a>

Imported source:
[mask-distribution-equivalence.md](mask-distribution-equivalence.md).
Focused closure batch:
[eps-mask-theorem-closure.md](eps-mask-theorem-closure.md).
Residual Closure Batch A route:
[eps-mask-formalization.md](eps-mask-formalization.md).

Closure statement:

```text
Theorem M-close-mask-distribution.
For fixed public key, message binding, active set A, retry context rho, and
production threshold mask protocol CombineMask, the aggregate mask Y_T and
public high bits HighBits(A_matrix*Y_T) are either exactly distributed as the
centralized ML-DSA-65 pair (Y_0, HighBits(A_matrix*Y_0)) or are within an
explicit displayed distance eps_mask_bound(lambda, A, rho).
```

Required bad-event accounting:

```text
eps_mask
 <= eps_mask_support
  + eps_mask_entropy
  + eps_mask_highbits
  + eps_mask_active_set
  + eps_mask_retry_freshness
  + eps_mask_corrupt_bias.
```

Closure requirements:

- Select exactly one production `CombineMask` family: additive,
  Lagrange-weighted, MPC/ideal, or dealer-aided.
- Prove coefficient support and sampling weights for every ML-DSA-65 mask
  coefficient, not only selected examples.
- Prove the public high-bit value used by `H_c` is covered by the same
  distance bound or by a separate displayed term.
- Prove retry contexts and mask seeds are injective and fresh across rejected
  attempts.
- Separate corrupted pre-challenge bias from post-challenge withholding so the
  same event is not charged to both `eps_mask` and `eps_withhold`.

Current status: open proof obligation. The repository has hazmat aggregation
and transcript evidence, but no theorem proving aggregate threshold masks have
the centralized ML-DSA-65 distribution.

## RSTC-4. eps_rej Closure Route
<a id="rstc-eps-rej-route"></a>

Imported source:
[rejection-predicate-equivalence.md](rejection-predicate-equivalence.md).
Focused closure batch:
[eps-rej-theorem-closure.md](eps-rej-theorem-closure.md).
Residual Closure Batch A route:
[eps-rej-predicate-sublemmas.md](eps-rej-predicate-sublemmas.md).

Closure statement:

```text
Theorem R-close-rejection-predicate.
Conditioned on one fixed reconstructed candidate tuple
(pk, mu, c_tilde, c, z, LowBits(w - c*s2), c*t0, h), the threshold aggregate
predicate Reject_T and centralized ML-DSA-65 predicate Reject_0 differ only on
explicitly enumerated bad events.
```

Required bad-event accounting:

```text
eps_rej
 <= eps_bound_encoding
  + eps_lowbits_decomposition
  + eps_ct0_reconstruction
  + eps_hint_encoding
  + eps_challenge_encoding
  + eps_active_set_mismatch
  + eps_signature_encoding
  + eps_verify_mismatch.
```

Closure requirements:

- Prove strict norm-bound equivalence for `z`, low bits, `c*t0`, hint weight,
  and challenge weight.
- Prove centered representative conversion matches the standard ML-DSA-65
  verifier for every module coefficient.
- Prove `LowBits`, `HighBits`, `MakeHint`, `UseHint`, `SampleInBall`,
  `pack_signature`, and `unpack_signature` are canonical for accepted outputs.
- Prove the active set used in commitments, challenge derivation,
  contribution validation, reconstruction, and final aggregation is identical.
- Partition `eps_verify_mismatch` through
  `Theorem V4-eps-verify-to-eps-rej-absorption`: only the
  `eps_verify_rej_absorb` branch may move into `eps_rej`; every remaining
  verifier-only branch stays visible as `eps_verify_survive`.

Current status: open proof obligation. The repository has predicate maps and
hazmat tests, but not a byte-level theorem that `Reject_T = Reject_0`.

## RSTC-5. eps_withhold Closure Route
<a id="rstc-eps-withhold-route"></a>

Imported source:
[withholding-abort-bound.md](withholding-abort-bound.md).
Focused closure batch:
[eps-withhold-theorem-closure.md](eps-withhold-theorem-closure.md).
Residual Closure Batch A route:
[eps-withhold-simulator-obligations.md](eps-withhold-simulator-obligations.md).

Closure statement:

```text
Theorem W-close-static-active.
For the fixed production corruption model, rushing model, retry limit R_max,
timeout/exclusion policy P_timeout, and abort-observable set O_abort, there is
a simulator Sim that samples the adversary-visible abort transcript from public
data and allowed leakage, and any remaining conditioning bias is bounded by
eps_withhold_bound(lambda, R_max, O_abort, P_timeout).
```

Required bad-event accounting:

```text
eps_withhold
 <= eps_withhold_commit
  + eps_withhold_challenge
  + eps_abort_labels
  + eps_retry_limit
  + eps_timeout_policy.
```

Closure requirements:

- Fix static versus adaptive corruption, rushing power, network synchrony,
  timeout semantics, signer exclusion, and retry cap.
- Define the theorem-level abort transcript `O_abort`, including missing
  commitments, missing contributions, local abort labels, aggregate rejection,
  retry count, timeout/exclusion records, evidence records, and final success.
- Prove each retry uses fresh mask material and a typed oracle input distinct
  from all prior attempts.
- Prove evidence and telemetry do not reveal honest masks, secret shares, or
  rejected honest candidate values beyond allowed abort leakage.
- State denial-of-service and liveness separately from accepted-distribution
  preservation.

Current status: open proof obligation. The repository has actor simulations
and evidence-shaped artifacts, but no selective-abort distribution theorem.

## RSTC-6. Consolidated Bound Route
<a id="rstc-consolidated-bound-route"></a>

The closure batch connects the imported terms as:

```text
Delta_accept(A,Z)
 <= eps_mask_support
  + eps_mask_entropy
  + eps_mask_highbits
  + eps_mask_active_set
  + eps_mask_retry_freshness
  + eps_mask_corrupt_bias
  + eps_bound_encoding
  + eps_lowbits_decomposition
  + eps_ct0_reconstruction
  + eps_hint_encoding
  + eps_challenge_encoding
  + eps_active_set_mismatch
  + eps_signature_encoding
  + eps_verify_mismatch
  + eps_verify_rej_absorb
  + eps_verify_survive
  + eps_withhold_commit
  + eps_withhold_challenge
  + eps_abort_labels
  + eps_retry_limit
  + eps_timeout_policy
  + eps_commit
  + eps_ro
  + negl(lambda).
```

This expanded expression is a reviewer checklist, not a final theorem claim.
Terms can be removed only when the corresponding theorem proves exact equality
or a negligible/concrete bound under fixed production assumptions.
This expression does not prove eps_verify_survive = 0; it records the V4
reviewer checklist split so verifier disagreement is not silently absorbed.

## RSTC-7. Acceptance Criteria
<a id="rstc-acceptance-criteria"></a>

This closure batch is acceptable only if it:

- keeps `eps_mask`, `eps_rej`, and `eps_withhold` separate;
- preserves `eps_commit`, `eps_ro`, and `eps_verify` unless separately
  discharged;
- links to `mask-distribution-equivalence.md`,
  `rejection-predicate-equivalence.md`, and `withholding-abort-bound.md`;
- states that current hazmat tests and actor simulations are evidence only;
- avoids claiming `Delta_accept = 0`;
- avoids claiming production liveness, production selective-abort resistance,
  or production readiness.

## RSTC-8. Non-Claims
<a id="rstc-non-claims"></a>

This document does not claim:

- `eps_mask = 0`;
- `eps_rej = 0`;
- `eps_withhold` is negligible;
- accepted threshold signatures are distributed as centralized ML-DSA-65
  signatures;
- `eps_verify` has been absorbed into `eps_rej`;
- `eps_verify_survive = 0` is proved;
- the current threshold mask protocol is production selected;
- the current network timeout and retry model is production selected;
- the repository is production-ready or externally audited.

## RSTC-9. Manifest Anchors
<a id="rstc-manifest-anchors"></a>

Stable anchors and text markers:

- `# Rejection-Sampling Theorem Closure Batch`
- `rejection-sampling-theorem-closure`
- `Status: theorem-closure batch for eps_mask, eps_rej, and eps_withhold`
- `RSTC-0. Scope and Non-Claim`
- `RSTC-1. Theorem Target`
- `RSTC-2. Dependency Order`
- `RSTC-3. eps_mask Closure Route`
- `RSTC-4. eps_rej Closure Route`
- `RSTC-5. eps_withhold Closure Route`
- `RSTC-6. Consolidated Bound Route`
- `RSTC-7. Acceptance Criteria`
- `RSTC-8. Non-Claims`
- `RSTC-9. Manifest Anchors`
- `Delta_accept`
- `Theorem RSTC-Delta-accept`
- `Theorem M-close-mask-distribution`
- `Theorem R-close-rejection-predicate`
- `Theorem V4-eps-verify-to-eps-rej-absorption`
- `eps_verify_mismatch`
- `eps_verify_rej_absorb`
- `eps_verify_survive`
- `does not prove eps_verify_survive = 0`
- `Theorem W-close-static-active`
- `eps_mask`
- `eps_rej`
- `eps_withhold`
- `eps_commit`
- `eps_ro`
- `eps_verify`
- `eps_mask_support`
- `eps_bound_encoding`
- `eps_withhold_commit`
- `mask-distribution-equivalence.md`
- `rejection-predicate-equivalence.md`
- `withholding-abort-bound.md`
- `eps-mask-theorem-closure.md`
- `eps-rej-theorem-closure.md`
- `eps-withhold-theorem-closure.md`
- `eps-mask-formalization.md`
- `eps-rej-predicate-sublemmas.md`
- `eps-withhold-simulator-obligations.md`
- `implementation evidence is not cryptographic proof`
- `not a completed accepted-distribution proof`
- `not production-ready`
