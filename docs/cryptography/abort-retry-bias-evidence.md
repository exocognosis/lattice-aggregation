# Abort/Retry Bias Evidence Checks

Status: conformance evidence only. This document records concrete blocker-3
progress toward showing that selective aborts and retries do not bias accepted
signatures. It does not prove Fiat-Shamir-with-aborts preservation for
ML-DSA-65 and must not be used as a production security claim.

## Scope

The typed checker in `src/production/abort_bias.rs` validates evidence packages
for three failure classes:

- missing domain separation between challenge derivation, retry binding, and
  accepted-sample audit buckets
- unbounded or secret-dependent abort/retry leakage
- accepted-sample bucket evidence whose total variation from the reference
  bucket distribution exceeds the stated bound

The integration test in `tests/production_abort_bias.rs` exercises the checker
as an owned blocker-3 artifact without changing the shared production module
exports.

## Evidence Model

`DomainSeparationEvidence` carries three `DomainTag` values:

- `Challenge`
- `Retry`
- `AcceptedSample`

Validation rejects any reused tag. This is a guardrail for the proof obligation
that retry transcripts are domain-separated and cannot be replayed as challenge
or accepted-sample evidence.

`AbortLeakageModel` requires finite bounds for:

- `RetryCount`
- `AbortObservationCount`

The current public observable set is intentionally narrow:

- aggregate accept/abort bit per attempt
- retry counter bound into the transcript

The checker rejects `SecretDependentAbortReason`. Future observables should be
added only after the proof model treats them as public or simulatable from
public transcript data.

`AcceptedSampleEvidence` contains deterministic public bucket counts, a minimum
accepted-sample threshold, and a maximum total-variation distance in parts per
million. The checker rejects malformed evidence, insufficient sample counts,
and sample sets whose bucket distribution exceeds the bound.

## What This Rejects

The current tests cover these regressions:

- retry domain reuse with the challenge domain
- an unbounded retry count in the abort leakage model
- secret-dependent abort reasons in the observable leakage set
- visibly biased accepted-sample evidence, such as a 99/1 split under a
  100,000 ppm bound

## Claim Boundary

Passing these checks means only that the submitted evidence package satisfies
the typed conformance constraints above. It does not establish that accepted
threshold signatures have the standard ML-DSA-65 distribution.

To fully close blocker 3, the repo still needs:

- a selected production signing backend with real ML-DSA-65 rejection behavior
- a proof that local aborts are hidden or simulatable from public data
- a proof that retry transcript binding preserves future challenge
  independence
- accepted-signature distribution evidence generated from the real backend,
  with justified bucket construction and sample-size thresholds
- integration of this checker into the production module surface and the shared
  proof/claims traceability files after the API boundary is accepted
