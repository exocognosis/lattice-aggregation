# FST-L4..FST-L7 Theorem Closure Batch
<a id="fst-l4-l7-theorem-closure"></a>

Status: middle-layer theorem-closure batch, not a full cryptographic proof.

This document consolidates the middle signing-side lemmas needed by
`FST-T1-IdealVSS`: partial-share validity under ideal `F_CONTRIB`,
aggregation correctness, no-subthreshold signing under ideal setup, and abort
compatibility. It builds on the `FST-L1..FST-L3` transcript, challenge, and
collection foundation.

The batch does not prove production threshold ML-DSA-65 security. It organizes
the proof route that says accepted contributions, aggregates, release records,
and abort observations are either valid under the idealized signing route or
charged to named residual terms.

## L47-0. Scope and Non-Claim
<a id="l47-scope-non-claim"></a>

The closure target is:

```text
FST-L4 + FST-L5 + FST-L6 + FST-L7:
  Under ideal F_VSS_DKG, ideal F_CONTRIB, FST-L1..FST-L3, fixed transcript
  grammar, canonical collection semantics, and explicit abort observables,
  accepted middle-layer signing outputs are contribution-valid,
  aggregation-consistent, threshold-authorized, and abort-compatible, except
  through named residual terms.
```

This target is still idealized. It does not instantiate malicious-secure
production VSS/DKG and does not instantiate a production contribution proof.
Implementation evidence is not cryptographic proof.

## L47-1. Lemma Dependency Chain
<a id="l47-lemma-dependency-chain"></a>

The dependency chain is:

```text
FST-L1..FST-L3
  -> FST-L4 partial-share validity under F_CONTRIB
  -> FST-L5 aggregation correctness and verifier-compatibility route
  -> FST-L6 no subthreshold signing under ideal setup
  -> FST-L7 abort, retry, evidence, and release compatibility
  -> FST-L10 classifier closure
```

`FST-L4` ensures accepted contributions are context-bound and relation-bound.
`FST-L5` ensures accepted contributions aggregate into one deterministic output
or a named aggregation/rejection/verifier residual. `FST-L6` ensures accepted
outputs are threshold-authorized under the ideal setup. `FST-L7` ensures abort
and release observables are simulated or charged without silently biasing the
accepted-output distribution.

## L47-2. Theorem Statements Under Closure
<a id="l47-theorem-statements"></a>

`FST-L4` target:

```text
Every accepted ContributionStatement_i is bound to SigningContext,
ChallengeRecord, validator index, epoch key, DKG digest, active set,
contribution relation/schema, and backend declaration, or eps_contrib_ideal,
eps_contrib, or a named contribution bad event is charged.
```

`FST-L5` target:

```text
Every accepted PartialShareSet and ChallengeRecord aggregate to a unique
AggregateOutputRecord whose reconstructed z/h/c/signature bytes match the
accepted active set and standard-verifier boundary, or eps_rej, eps_verify,
eps_collect, eps_mask, or a named aggregation bad event is charged.
```

The verifier portion of this target follows the V4 partition. `FST-L5` may
charge verifier disagreement to `eps_rej` only for the proved
`eps_verify_rej_absorb` branch where `Reject_pred(C) = 1`; otherwise the
disagreement remains visible as `eps_verify` or `eps_verify_survive`. The
`BadVerifyMismatch` route is not closed by this document.

`FST-L6` target:

```text
No accepted AggregateOutputRecord is authorized by fewer than t valid
validators unless the execution is charged to eps_threshold, eps_vss_ideal,
eps_classify, a contribution/collection/classifier bad event, or the base
ML-DSA forgery route.
```

`FST-L7` target:

```text
Abort, timeout, withholding, retry, evidence, and release observations are
simulatable from public observables or charged to eps_withhold, eps_abort,
eps_release, eps_evid, Delta_accept, or related residuals.
```

## L47-3. Shared Objects
<a id="l47-shared-objects"></a>

The batch shares these objects:

- `ContributionStatement_i`: per-validator contribution statement bound to the
  challenge, validator identity, active set, relation, and backend schema.
- `ProductionContributionStatement`: production replacement target for
  `F_CONTRIB`.
- `AggregateOutputRecord`: active set, contribution statements, final
  signature bytes, verification result, release metadata, and classifier input.
- `PartialShareSet`: canonical accepted contribution set.
- `ReleaseSignature`: authorized release record for accepted aggregate output.
- `EvidenceRecord`: public evidence object for invalid shares or protocol
  faults.
- `O_abort`, `R_max`, and `P_timeout`: public abort-observable set, retry
  limit, and timeout/exclusion policy.

## L47-4. Residual Ledger
<a id="l47-residual-ledger"></a>

The batch carries these terms:

```text
eps_l4_l7
 <= eps_contrib_ideal
  + eps_contrib
  + eps_contrib_sound
  + eps_contrib_extract
  + eps_contrib_hide
  + eps_contrib_context
  + eps_contrib_encoding
  + eps_contrib_leakage
  + eps_rej
  + eps_verify
  + eps_verify_rej_absorb
  + eps_verify_survive
  + eps_collect
  + eps_mask
  + eps_threshold
  + eps_classify
  + eps_withhold
  + eps_abort
  + eps_release
  + eps_evid
```

The classifier interaction remains visible through `eps_cls_contrib`,
`eps_cls_threshold`, `eps_cls_collect`, and `eps_cls_unmapped = 0`.

No term in this ledger is claimed negligible, zero, or numerically bounded by
this document.

## L47-5. Proof Route
<a id="l47-proof-route"></a>

The proof route is case-based:

1. Invalid contribution context is rejected or charged to
   `eps_contrib_context`.
2. Invalid contribution relation, extraction, hiding, or leakage is handled by
   ideal `F_CONTRIB` for the immediate theorem and remains visible for
   production replacement.
3. Aggregation mismatch is charged to `BadAggCorrect`, `BadRejectDist`,
   `BadVerifyMismatch`, `BadActiveSetRebind`, `eps_rej`, `eps_verify`,
   `eps_verify_rej_absorb`, or `eps_verify_survive`, with absorption into
   `eps_rej` allowed only through the proved V4 branch.
4. Any aggregate with fewer than `t` valid validators is charged to
   `BadThresholdShare`, `BadRogueSigner`, `BadIdealMismatch`,
   `eps_threshold`, or `eps_classify`.
5. Abort, timeout, evidence, retry, withholding, and release observations are
   simulated from public observables or charged to the `FST-L7` residuals.
6. Any accepted unauthorized middle-layer failure that reaches the final output
   path must be classified by `FST-L10`; it cannot remain in
   `eps_cls_unmapped`.

## L47-6. Acceptance Criteria
<a id="l47-acceptance-criteria"></a>

This batch can be treated as locally closed only if:

- [fst-l4-partial-share-validity.md](fst-l4-partial-share-validity.md) carries
  ideal `F_CONTRIB` and production replacement residuals explicitly.
- [fst-l5-aggregation-correctness.md](fst-l5-aggregation-correctness.md)
  states aggregation, rejection, verifier, and active-set bad-event cases.
- [fst-l6-no-subthreshold-signing.md](fst-l6-no-subthreshold-signing.md)
  states threshold authorization under ideal setup and classifier interaction.
- [fst-l7-abort-compatibility.md](fst-l7-abort-compatibility.md) states
  abort, timeout, retry, evidence, release, withholding, and timing cases.
- [proof-closure-ledger.md](proof-closure-ledger.md) keeps all unresolved
  residuals visible.

## L47-7. Non-Claims
<a id="l47-non-claims"></a>

This batch does not claim:

- the full `FST-T1-IdealVSS` theorem is proved;
- production VSS/DKG security is proved;
- a production contribution backend is selected or proved;
- accepted-distribution preservation is proved;
- selective-abort advantage is bounded;
- verifier compatibility is fully proved;
- classifier totality or `eps_cls_unmapped = 0` is proved;
- implementation evidence is cryptographic proof;
- the repository is production-ready.

## L47-8. Manifest Anchors
<a id="l47-manifest-anchors"></a>

Stable anchors and text markers:

- `# FST-L4..FST-L7 Theorem Closure Batch`
- `fst-l4-l7-theorem-closure`
- `Status: middle-layer theorem-closure batch, not a full cryptographic proof.`
- `L47-0. Scope and Non-Claim`
- `L47-1. Lemma Dependency Chain`
- `L47-2. Theorem Statements Under Closure`
- `L47-3. Shared Objects`
- `L47-4. Residual Ledger`
- `L47-5. Proof Route`
- `L47-6. Acceptance Criteria`
- `L47-7. Non-Claims`
- `L47-8. Manifest Anchors`
- `FST-L4`
- `FST-L5`
- `FST-L6`
- `FST-L7`
- `F_CONTRIB`
- `F_VSS_DKG`
- `AggregateOutputRecord`
- `ContributionStatement_i`
- `PartialShareSet`
- `ReleaseSignature`
- `EvidenceRecord`
- `O_abort`
- `eps_contrib_ideal`
- `eps_rej`
- `eps_verify`
- `eps_verify_rej_absorb`
- `eps_verify_survive`
- `BadVerifyMismatch`
- `eps_threshold`
- `eps_withhold`
- `eps_abort`
- `eps_release`
- `eps_evid`
- `eps_cls_unmapped = 0`
- `implementation evidence is not cryptographic proof`
- `not a full cryptographic proof`
- `not production-ready`
