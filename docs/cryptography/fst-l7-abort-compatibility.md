# FST-L7 Abort Compatibility Worksheet
<a id="fst-l7-abort-compatibility"></a>

Date: 2026-05-28

Status: proof worksheet for `FST-L7`, not a completed selective-abort or release noninterference proof.

Selective-abort proof remains open.

## FST-L7-0. Scope and Non-Claim
<a id="fst-l7-scope-non-claim"></a>

This worksheet expands the `FST-L7` abort compatibility lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects
retry, withholding, timeout, evidence, and release behavior to the
accepted-signature distribution route in
[withholding-abort-bound.md](withholding-abort-bound.md),
[rejection-sampling-bounds.md](rejection-sampling-bounds.md), and
[rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md).

This worksheet does not prove selective-abort resistance, network liveness,
slashing soundness, evidence anti-framing, or side-channel safety. It does not
close `eps_withhold`, `eps_abort`, `eps_release`, or `eps_evid`.

## FST-L7-1. Lemma Statement Under Closure
<a id="fst-l7-lemma-statement"></a>

Worksheet target:

```text
Lemma FST-L7, abort compatibility, worksheet target.
Under FST-A5, fixed static active corruption with |C| < t, authenticated
context-bound messages, rushing within rounds, retry limit R_max,
timeout/exclusion policy P_timeout, and abort-observable set O_abort, the
accepted threshold-signature distribution is bounded relative to ordinary
ML-DSA-65 signing by:

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
- every abort label, evidence record, timing/message-size bucket, retry count,
  timeout, and exclusion record is simulated from public data or excluded from
  the theorem;
- denial of service and liveness are stated separately;
- implementation tests remain evidence only.

## FST-L7-8. Non-Claims
<a id="fst-l7-non-claims"></a>

This worksheet does not prove `FST-L7`. It does not prove selective-abort
advantage is bounded. It does not prove `eps_withhold` negligible, zero, or
numerically bounded. It does not prove production liveness, slashing soundness,
anti-framing, side-channel safety, or production threshold ML-DSA security.

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
- `ivls-fst-l7-abort-compatibility`
- `theorem-w-close-static-active`
- `theorem-conditional-accepted-distribution-bound`
- `eps-withhold-closure-route`
- `eps-withhold-production-route-selection`
- `abort-transcript-o-abort`
- `ledger-non-claims`
- `implementation evidence is not cryptographic proof`
- `selective-abort proof remains open`
