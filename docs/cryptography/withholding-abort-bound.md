# Withholding and Abort Bound Worksheet
<a id="withholding-abort-bound"></a>

Date: 2026-05-27

Status: proof-route worksheet for `eps_withhold`, not a completed
selective-abort proof.

This worksheet isolates the H5 -> H6 hybrid step from
[rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md). The
goal is to specify the simulator, leakage boundary, retry policy, and
conditioning terms needed before accepted threshold signatures can be compared
to centralized ML-DSA-65 signatures in the presence of corrupted validators.

The focused theorem-closure batch for this route is
[eps-withhold-theorem-closure.md](eps-withhold-theorem-closure.md).

## WAB-0. Scope and Non-Claims
<a id="wab-scope"></a>

The route covers withholding and abort observables after the mask-distribution
and rejection-predicate routes have been separated. It must not be used to hide
an `eps_mask` distribution mismatch or an `eps_rej` predicate mismatch.

This document does not prove production liveness or consensus availability. A
corrupted validator can still cause denial of service under the network model;
the proof obligation here is to prevent that behavior from becoming an
unstated bias in the accepted-signature distribution.

## WAB-1. Theorem Target
<a id="wab-theorem-target"></a>
<a id="theorem-w-close-static-active"></a>

Fix a corruption model, rushing model, retry limit `R_max`, timeout/exclusion
policy `P_timeout`, and allowed abort-observable set `O_abort`. Let
`View_with_abort_labels` be the adversary-visible transcript containing the
public signing context, messages sent by corrupted parties, public commitments,
accepted active sets, retry identifiers, abort labels, evidence records, and
allowed timing/message-size classes.

Theorem W-close-static-active. For the first proof-closure route, the intended
model is static active corruption with rushing in each protocol round,
authenticated context-bound messages, bounded retries, and a fixed
timeout/exclusion policy. The route closes `eps_withhold` only after proving
that there exists a simulator `Sim` such that:

```text
Delta(View_with_abort_labels, Sim(public inputs, O_abort))
  + Pr[withholding changes the conditioned accepted-signature distribution
       outside O_abort]
  <= eps_withhold_bound(lambda, R_max, O_abort, P_timeout).
```

Denial-of-service probability must be stated separately from this distribution
bound.

## WAB-2. Abort-Observable Taxonomy
<a id="wab-abort-taxonomy"></a>

The proof must classify every failed or retried attempt before it can state an
accepted-distribution theorem:

| Class | Example | Distribution treatment |
| --- | --- | --- |
| Local honest rejection | Honest aggregate candidate fails ML-DSA rejection checks. | Simulated from public accept/reject outcome only, or hidden until aggregate decision. |
| Pre-challenge withholding | Corrupted validator withholds a mask opening after seeing commitments. | Availability/exclusion event or `eps_withhold_commit`. |
| Post-challenge withholding | Corrupted validator withholds a secret contribution after seeing `c`. | `eps_withhold_challenge` unless proven denial-of-service only. |
| Malformed contribution | Payload fails decoding, proof, challenge, active-set, or bound checks. | Attributable evidence; not merged with ordinary rejection sampling. |
| Retry-limit exhaustion | `R_max` reached before an accepted attempt. | `eps_retry_limit` plus availability statement. |
| Side-channel class | Timing, message size, retry count, or evidence size is visible. | Either included in `O_abort` and simulated, or excluded from the theorem. |

## WAB-3. Symbolic Decomposition
<a id="wab-decomposition"></a>

The `eps_withhold` route decomposes into:

```text
eps_withhold
  <= eps_withhold_commit
   + eps_withhold_challenge
   + eps_abort_labels
   + eps_retry_limit
   + eps_timeout_policy.
```

| Term | Meaning | Required closure |
| --- | --- | --- |
| `eps_withhold_commit` | Bias from withholding after commitment publication but before `H_c`. | Prove canonical commitment-set selection and signer-exclusion semantics. |
| `eps_withhold_challenge` | Bias from withholding after observing challenge `c`. | Prove missing corrupted contributions cause only retry/exclusion, not adaptive choice of honest masks. |
| `eps_abort_labels` | Leakage from participant-specific failure labels or evidence records. | Simulator for labels from public data, or explicit exclusion from the theorem. |
| `eps_retry_limit` | Conditioning introduced by bounded retries. | Lower-bound acceptance probability and prove fresh attempts up to `R_max`. |
| `eps_timeout_policy` | Bias from timeout duration, network scheduling, or late-arrival handling. | Fix synchrony/network abstraction and deterministic acceptance/exclusion rules. |

## WAB-4. Simulator Obligations
<a id="wab-simulator-obligations"></a>

The simulator for this route must:

- Receive only public context, allowed abort observables, corrupted-party
  inputs, and the final accept/reject status allowed by the theorem.
- Avoid honest secret shares, honest mask seeds, and rejected honest candidate
  values.
- Produce the same distribution of public retry identifiers, active-set
  decisions, timeout/exclusion labels, and attributable malformed evidence
  records covered by `O_abort`.
- Rely on [mask-distribution-equivalence.md](mask-distribution-equivalence.md)
  for mask freshness and
  [rejection-predicate-equivalence.md](rejection-predicate-equivalence.md) for
  rejection-predicate consistency, rather than reproving or absorbing those
  routes.

## WAB-5. Code and Artifact Crosswalk
<a id="wab-code-crosswalk"></a>

Current implementation evidence is limited to modeled actor behavior and
artifact boundaries:

- `src/adapter/actor.rs` models bounded sessions, malformed contribution
  handling, and telemetry collection.
- `src/utils/hazmat_simulation.rs` provides deterministic Section V-style
  scenarios, including Byzantine malformed-contribution behavior.
- `src/adapter/evidence.rs` separates evidence-shaped failures from ordinary
  retry and rejection behavior.
- `tests/hazmat_mldsa65_actor.rs`, `tests/hazmat_mldsa65_fuzzing.rs`, and
  `tests/hazmat_mldsa65_simulation_grid.rs` exercise stale, duplicate,
  malformed, insufficient, and reordered actor inputs.
- [active-adversary-model.md](active-adversary-model.md) records rushing and
  selective-abort threat categories.

These tests and artifacts do not prove `WAB-1`; they only define the modeled
surface a later simulator must cover.

## WAB-6. Acceptance Criteria
<a id="wab-acceptance-criteria"></a>

Before a manuscript can state that `eps_withhold` is negligible or zero, all
of the following must be complete:

- The first production theorem fixes static versus adaptive corruption,
  rushing power, network synchrony, timeout semantics, signer exclusion, and
  retry cap.
- Every abort label, evidence record, retry count, message-size class, and
  timing class is either simulated from public data or explicitly outside the
  accepted-distribution theorem.
- Bounded retries are proved fresh and independent up to the stated loss.
- Withholding by corrupted validators is shown to be denial of service only,
  or its bias appears as a visible theorem summand.
- The final theorem states availability/liveness separately from
  distributional equivalence.

## WAB-7. Non-Claims
<a id="wab-non-claims"></a>

This worksheet does not prove network liveness, slashing soundness,
adaptive-security with erasures, or production side-channel resistance. It does
not make retry telemetry private. It is a route for closing `eps_withhold`, not
the closure itself.
