# FST-L7 Abort Compatibility Worksheet
<a id="fst-l7-abort-compatibility"></a>

Date: 2026-05-28

Status: theorem-closure route for `FST-L7`, conditional on public abort
observables, fixed retry policy, and visible residual terms; not a completed
selective-abort or release noninterference proof.

Selective-abort proof remains open.

## FST-L7-0. Scope and Non-Claim
<a id="fst-l7-scope-non-claim"></a>

This document upgrades the `FST-L7` abort compatibility worksheet from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects
retry, withholding, timeout, evidence, and release behavior to the
accepted-signature distribution route in
[withholding-abort-bound.md](withholding-abort-bound.md),
[rejection-sampling-bounds.md](rejection-sampling-bounds.md), and
[rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md).

The claim boundary is conditional. The route only applies after the theorem
fixes `O_abort`, `R_max`, `P_timeout`, release semantics, evidence semantics,
retry freshness, and timing/message-size observables. It does not prove
selective-abort resistance, network liveness, slashing soundness, evidence
anti-framing, or side-channel safety. It does not close `eps_withhold`,
`eps_abort`, `eps_release`, or `eps_evid`.

## FST-L7-1. Lemma Statement Under Closure
<a id="fst-l7-lemma-statement"></a>

Theorem `FST-L7` (abort compatibility under public observables). Fix static
active corruption with `|C| < t`, authenticated context-bound messages,
rushing within rounds, retry limit `R_max`, timeout/exclusion policy
`P_timeout`, public abort-observable set `O_abort`, evidence-record grammar,
release-record grammar, and domain-separated retry attempts. Then every
execution that aborts, times out, withholds, retries, releases, or emits
evidence is either simulatable from public inputs and `O_abort`, or charged to
one of the visible residuals below. Conditioned on accepted outputs, those
observations do not change the accepted-signature distribution except through
the `Delta_accept` terms.

```text
Delta_accept
  <= eps_mask
   + eps_rej
   + eps_withhold
   + eps_ro
   + eps_commit
   + eps_verify
```

`eps_withhold` is not closed by this worksheet and remains decomposed into
withholding, abort-label, retry, timeout, release, evidence, and timing terms.

The withholding target from `theorem-w-close-static-active` is:

```text
Delta(View_with_abort_labels, Sim(public inputs, O_abort))
  + Pr[withholding changes the conditioned accepted-signature distribution
       outside O_abort]
  <= eps_withhold_bound(lambda, R_max, O_abort, P_timeout).
```

## FST-L7-2. Model and Observable Boundary
<a id="fst-l7-model-observable-boundary"></a>

The theorem is about distributional compatibility of accepted transcripts, not
consensus availability. The production theorem must fix:

- static or adaptive corruption choice;
- rushing power;
- network abstraction;
- retry limit `R_max`;
- timeout and signer-exclusion policy `P_timeout`;
- public abort-observable set `O_abort`;
- evidence and complaint labels;
- authorized release log semantics;
- timing, message-size, retry-count, timeout, and exclusion records.

`O_abort` is the exact public transcript boundary exposed to the environment:
abort labels, round labels, accused validator identifiers when public, timeout
classes, retry counters, exclusion labels, evidence metadata, release metadata,
and any timing or message-size classes explicitly admitted by the theorem.
Anything outside `O_abort` must either be hidden, simulated from public data, or
charged to `eps_timing_boundary`, `eps_evid`, `eps_release`, or
`implementation_residual`.

`R_max` bounds the number of retry attempts per signing context. Each retry
uses a fresh attempt id, fresh random-oracle domain input, fresh mask material,
and a transcript state that cannot reuse prior failed commitments as current
commitments. Any retry-policy deviation is charged to `eps_retry_limit` or
`eps_withhold`.

`P_timeout` determines when a validator is excluded, when a session aborts,
and whether the next attempt preserves or changes the active set. The policy
must be deterministic from public timing labels and authenticated frame
delivery metadata included in `O_abort`.

The simulator may use public context, corrupted-party inputs, final allowed
accept/reject information, and `O_abort`. It must not use honest secret shares,
honest mask seeds, rejected honest candidate values, or non-public rejection
internals.

## FST-L7-3. Dependency Map
<a id="fst-l7-dependency-map"></a>

`FST-L7` depends on `FST-A5`, `FST-G5`, `FST-T1-IdealVSS`,
`ivls-fst-l7-abort-compatibility`, `ivls-epsilon-ledger`,
`theorem-w-close-static-active`,
`theorem-conditional-accepted-distribution-bound`,
`eps-withhold-closure-route`, `eps-withhold-production-route-selection`,
`abort-transcript-o-abort`, `SHR-L7`, `eps_abort(A,Z)`, and
`ledger-non-claims`.

## FST-L7-4. Hybrid Compatibility Route
<a id="fst-l7-hybrid-compatibility-route"></a>

The hybrid route is the H5 to H6 and S6 to S7 compatibility path. It must keep
`eps_mask`, `eps_rej`, and `eps_verify` separate from abort terms. It must then
simulate or charge withholding, abort labels, retry counts, timeout/exclusion
labels, release records, evidence metadata, and timing/message-size classes
through the allowed observable set.

Denial of service and liveness must be stated separately from
accepted-signature distribution. Ordinary rejection-sampling failures must not
be treated as slashable evidence.

The proof is by cases:

1. Precommit abort. If a party aborts before submitting a commitment, the
   simulator emits the public precommit abort label in `O_abort`; no challenge
   has been fixed. Any influence on validator exclusion or retry scheduling is
   charged to `eps_timeout_policy` or `eps_retry_limit`.
2. Postcommit withholding. If a party commits but withholds its opening or
   later share before challenge finalization, the event is charged to
   `eps_withhold_commit` unless the timeout/exclusion policy simulates it from
   public delivery metadata.
3. Postchallenge withholding. If a party sees `H_c` and withholds a partial
   contribution, the event is charged to `eps_withhold_challenge` because it
   can correlate with the candidate acceptance predicate.
4. Invalid-share evidence. If a party submits an invalid contribution and an
   evidence record is produced, the simulator emits only evidence metadata
   admitted by `O_abort`; additional leakage is charged to `eps_evid`.
5. Timeout exclusion. If `P_timeout` excludes a validator, the exclusion must
   be deterministic from public timeout labels. Any policy branch that depends
   on hidden rejection internals is charged to `eps_timeout_policy` or
   `eps_timing_boundary`.
6. Retry freshness. Each retry must domain-separate attempt ids and refresh
   commitments, openings, masks, and contribution frames. Reuse across attempts
   is charged to `eps_retry_limit`, `eps_mask`, `eps_rej`, or `eps_verify`.
7. Release noninterference. A release record or authorized release log entry
   must be derived only after an accepted aggregate output and must not expose
   rejected candidate internals. Any mismatch is charged to `eps_release`.
8. Timing leakage. Timing, message-size, and retry-count observables are either
   included in `O_abort` and simulated, or charged to `eps_timing_boundary`.

## FST-L7-5. Residual Term Ledger
<a id="fst-l7-residual-term-ledger"></a>

The abort route decomposes:

```text
eps_withhold
  <= eps_withhold_commit
   + eps_withhold_challenge
   + eps_abort_labels
   + eps_retry_limit
   + eps_timeout_policy
   + eps_timing_boundary
```

The worksheet also carries:

```text
eps_mask
eps_rej
eps_ro
eps_commit
eps_verify
eps_abort
eps_release
eps_evid
Delta_accept
implementation_residual
audit_residual
```

No term in this ledger is claimed negligible, zero, or numerically bounded.

## FST-L7-6. Simulator Obligations
<a id="fst-l7-simulator-obligations"></a>

The simulator must produce the same distribution of:

- public retry identifiers;
- active-set decisions;
- timeout and exclusion labels;
- allowed abort labels;
- evidence metadata covered by `O_abort`;
- release log entries;
- timing and message-size classes included in the theorem.

It relies on mask-distribution equivalence for fresh masks and rejection
predicate equivalence for accepted/rejected candidate consistency.

The simulator obligations are:

- sample or relay public abort labels exactly as specified by `O_abort`;
- produce retry identifiers and timeout/exclusion labels from public policy
  inputs only;
- never inspect honest shares, honest mask seeds, or rejected honest candidate
  internals;
- simulate evidence metadata without leaking witness data, proof randomness,
  secret shares, or rejection internals;
- emit release records only for authorized accepted aggregate outputs;
- charge any non-public timing or message-size dependency to
  `eps_timing_boundary`.

Implementation evidence includes `src/adapter/actor.rs`,
`src/adapter/evidence.rs`, `src/utils/hazmat_simulation.rs`,
`tests/hazmat_mldsa65_actor.rs`, `tests/hazmat_mldsa65_fuzzing.rs`,
`tests/hazmat_mldsa65_simulation_grid.rs`, and `tests/simulation.rs`.
Implementation evidence is not cryptographic proof.

## FST-L7-7. Acceptance Criteria
<a id="fst-l7-acceptance-criteria"></a>

Before `FST-L7` can be treated as proved:

- the theorem fixes static/adaptive corruption, rushing, network abstraction,
  `R_max`, `P_timeout`, and `O_abort`;
- `eps_mask`, `eps_rej`, and `eps_withhold` are separated;
- retry freshness and domain-separated attempts are proved;
- precommit abort, postcommit withholding, postchallenge withholding,
  invalid-share evidence, timeout exclusion, retry freshness, release
  noninterference, and timing leakage cases are each simulated or charged;
- every abort label, evidence record, timing/message-size bucket, retry count,
  timeout, and exclusion record is simulated from public data or excluded from
  the theorem;
- denial of service and liveness are stated separately;
- implementation tests remain evidence only.

## FST-L7-8. Non-Claims
<a id="fst-l7-non-claims"></a>

This theorem-closure route does not prove final `FST-L7` unless the displayed
residuals are later bounded or retained in the parent theorem. It does not
prove selective-abort advantage is bounded. It does not prove `eps_withhold`
negligible, zero, or numerically bounded. It does not prove production
liveness, slashing soundness, anti-framing, side-channel safety, or production
threshold ML-DSA security.

Implementation evidence is not cryptographic proof.

## FST-L7-9. Manifest Anchors
<a id="fst-l7-manifest-anchors"></a>

- `# FST-L7 Abort Compatibility Worksheet`
- `fst-l7-abort-compatibility`
- `FST-L7-0. Scope and Non-Claim`
- `FST-L7-1. Lemma Statement Under Closure`
- `FST-L7-2. Model and Observable Boundary`
- `FST-L7-3. Dependency Map`
- `FST-L7-4. Hybrid Compatibility Route`
- `FST-L7-5. Residual Term Ledger`
- `FST-L7-6. Simulator Obligations`
- `FST-L7-7. Acceptance Criteria`
- `FST-L7-8. Non-Claims`
- `FST-L7-9. Manifest Anchors`
- `FST-L7`
- `FST-A5`
- `FST-G5`
- `Delta_accept`
- `O_abort`
- `R_max`
- `P_timeout`
- `eps_withhold`
- `eps_withhold_commit`
- `eps_withhold_challenge`
- `eps_abort_labels`
- `eps_retry_limit`
- `eps_timeout_policy`
- `eps_timing_boundary`
- `eps_release`
- `eps_evid`
- `eps_mask`
- `eps_rej`
- `eps_verify`
- `eps_abort`
- `ivls-fst-l7-abort-compatibility`
- `theorem-w-close-static-active`
- `theorem-conditional-accepted-distribution-bound`
- `eps-withhold-closure-route`
- `eps-withhold-production-route-selection`
- `abort-transcript-o-abort`
- `ledger-non-claims`
- `implementation evidence is not cryptographic proof`
- `selective-abort proof remains open`
