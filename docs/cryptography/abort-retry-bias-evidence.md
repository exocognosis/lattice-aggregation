# Abort/Retry Bias Evidence Checks

Status: conformance evidence track. This document records concrete blocker-3
progress toward showing that selective aborts and retries do not bias accepted
signatures. Fiat-Shamir-with-aborts preservation for ML-DSA-65 and production
security promotion require the selected proof and audit package.

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

## Closure Package Framework

`AbortRetryBiasProofPackage` wraps the conformance evidence with the additional
artifact handles required before blocker 3 can be marked closure-ready. The
package requires nonzero digests for:

- formal leakage model
- retry-domain separation proof
- accepted-signature distribution proof
- adversarial abort policy corpus
- sample-size and bucket-construction rationale

The digest checks are completeness guards only. They identify reviewed external
artifacts and prevent accidental promotion of placeholder or missing proof
material. They do not parse the artifacts or verify the proofs internally.

`AbortBiasBoundThresholds` records the closure thresholds checked against the
validated evidence report:

- maximum retry count
- maximum public abort observations
- minimum accepted samples
- maximum accepted-sample total variation in parts per million

Validation rejects malformed thresholds and any evidence report that exceeds
the stated retry, abort-observation, sample-count, or total-variation bounds.

`ExternalReviewSignoff` requires a nonzero review-report digest, a nonzero
reviewer-signoff digest, and an explicit signed-off flag. A package that is
missing either digest or has not been signed off is rejected before a
closure-ready report is returned.

`AbortBiasClosureReport::status()` returns `ClosureReady` only after the
conformance evidence, proof digests, thresholds, accepted-sample distribution,
and external review signoff all pass the typed checks. A plain
`RetryBiasEvidenceReport` remains `EvidenceOnly`.

## What This Rejects

The current tests cover these regressions:

- retry domain reuse with the challenge domain
- an unbounded retry count in the abort leakage model
- secret-dependent abort reasons in the observable leakage set
- visibly biased accepted-sample evidence, such as a 99/1 split under a
  100,000 ppm bound
- closure packages with a missing required proof digest
- closure packages without external review signoff
- closure thresholds that do not actually bound the validated evidence
- closure packages whose accepted samples are biased before status promotion

## Claim Boundary

Passing these checks means only that the submitted evidence package satisfies
the typed conformance constraints above, and that a closure package has
non-placeholder artifact digests, bounded thresholds, and external review
signoff. It does not establish that accepted threshold signatures have the
standard ML-DSA-65 distribution.

To fully close blocker 3, the repo still needs:

- a selected production signing backend with real ML-DSA-65 rejection behavior
- a proof that local aborts are hidden or simulatable from public data
- a proof that retry transcript binding preserves future challenge
  independence
- a formal leakage-model artifact matching the code-level public observable set
- a retry-domain separation proof artifact covering the production transcript
  encoding and retry counter binding
- accepted-signature distribution evidence generated from the real backend,
  with justified bucket construction and sample-size thresholds
- an adversarial abort-policy corpus with coverage rationale for rushing,
  selective abort, malformed commitment, omitted partial, and retry-exhaustion
  policies
- an external review report and signoff over the proof package, not only the
  typed digest handles
- integration of this checker into the production module surface and the shared
  proof/claims traceability files after the API boundary is accepted
