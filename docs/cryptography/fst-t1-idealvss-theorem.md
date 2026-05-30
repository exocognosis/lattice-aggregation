# FST-T1-IdealVSS Theorem Consolidation
<a id="fst-t1-idealvss-theorem"></a>

Status: theorem consolidation target, not a completed proof.

This document consolidates the immediate signing-side theorem route for the
threshold ML-DSA-65 research scaffold. It is a reviewer-facing target that ties
the IdealVSS setup boundary, ideal contribution boundary, signing lemmas,
simulator worksheets, and residual advantage terms into one statement.

It does not prove the theorem. It records the theorem shape that must be proved
before the repository can claim the IdealVSS signing-side result, and it keeps
all non-closed terms visible.

## FSTT1-0. Scope and Non-Claim
<a id="fstt1-scope-non-claim"></a>

`FST-T1-IdealVSS` is narrower than production `FST-T1 threshold
unforgeability`. It isolates the signing proof by assuming ideal setup through
`F_VSS_DKG` and ideal contribution validation through `F_contrib` / `F_CONTRIB`.

The modeled adversary is a PPT static active corruption adversary that corrupts
at most `t - 1 validators` before setup. The immediate scope is the signing
side under ideal functionalities, not concrete malicious-secure DKG/VSS, not a
production contribution proof, and not deployment readiness.

Implementation evidence is not cryptographic proof. Passing tests, transcript
determinism, hazmat ML-DSA-65 experiments, actor simulations, and manifest
checks are review evidence only.

## FSTT1-1. Theorem Statement Under Ideal Setup
<a id="fstt1-theorem-statement"></a>

Target statement:

```text
FST-T1-IdealVSS/F_CONTRIB target:
For every PPT adversary A statically corrupting at most t - 1 validators before
ideal F_VSS_DKG setup, threshold ML-DSA-65 signing is EUF-CMA secure in Game
FST-G1 under ideal F_VSS_DKG and ideal F_contrib/F_CONTRIB, provided FST-L1
through FST-L7 are proved and FST-L10 eliminates eps_cls_unmapped.
```

Equivalently, every unauthorized accepting aggregate output must either reduce
to `q_out * eps_mldsa(B_mldsa)` for the base ML-DSA-65 assumption or be charged
to a named threshold-side residual term. The classifier residual cannot be
removed until `eps_cls_unmapped = 0` is proved.

## FSTT1-2. Ideal Functionality Boundaries
<a id="fstt1-ideal-boundaries"></a>

`F_TMLDSA` is the ideal threshold signing functionality used by the real/ideal
proof surface. In this immediate theorem route, it receives setup outputs from
`F_VSS_DKG` and contribution-validity decisions from `F_CONTRIB`.

`F_VSS_DKG` exposes the epoch public key, accepted dealer set, per-validator
share outputs, setup digest, and explicitly allowed setup leakage. Its residual
is `eps_vss_ideal`, not concrete `eps_vss`. This theorem route does not prove a
production VSS/DKG backend.

`F_contrib` / `F_CONTRIB` is an ideal contribution functionality. It is used to
isolate signing-side proof work from the still-open production contribution
backend. Its residual is `eps_contrib_ideal`. The production route must later
replace it with a proof, MPC, interactive proof, or ideal-realization theorem.

## FSTT1-3. Assumptions
<a id="fstt1-assumptions"></a>

The consolidation target depends on these assumptions and obligations:

- `FST-A0` through ideal `F_VSS_DKG`, with the exact setup leakage stated.
- `FST-A1` base ML-DSA-65 EUF/SUF-CMA security for the selected game.
- `FST-A4` through `FST-A8` for signing-side commitments, rejection
  preservation, partial validity, transcript binding, and collection
  validation.
- Ideal `F_contrib` / `F_CONTRIB` only as theorem decomposition, with
  `eps_contrib_ideal` visible.
- Static active corruption only, with `|C| < t`.
- No concrete VSS/DKG realization and no production contribution backend
  realization.

## FSTT1-4. Advantage Bound Shape
<a id="fstt1-advantage-bound"></a>

The publication-facing theorem must keep the following residuals visible unless
each is separately proved, eliminated, or bounded:

```text
Adv_FST-T1-IdealVSS(A)
 <= q_out * eps_mldsa(B_mldsa)
  + eps_vss_ideal(A)
  + eps_contrib_ideal(A)
  + eps_commit(A)
  + eps_ro_prior(A)
  + eps_ro_sep(A)
  + eps_mask(A)
  + eps_rej(A)
  + eps_withhold(A)
  + eps_verify(A)
  + eps_collect(A)
  + eps_threshold(A)
  + eps_classify(A)
  + negl(lambda)
```

When importing the simulator route from `S0..S8`, the expression must also keep
`eps_abort`, `eps_release`, and `eps_evid` visible rather than folding them into
informal prose. Publication wording must also keep `implementation_residual`
and `audit_residual` visible until implementation, side-channel, randomness,
transport, consensus-integration, and external-review obligations are closed.

No term in this expression is claimed negligible, zero, or numerically bounded
by this document.

## FSTT1-5. Lemma and Worksheet Dependencies
<a id="fstt1-dependencies"></a>

The theorem target depends on the following signing-side lemmas:

- `FST-L1`: canonical transcript injectivity and random-oracle domain
  separation.
- `FST-L2`: signing challenge binding to the committed transcript.
- `FST-L3`: canonical collection and active-set soundness.
- `FST-L4`: partial-share validity under the ideal `F_CONTRIB` boundary.
- `FST-L5`: aggregation correctness and standard verifier compatibility.
- `FST-L6`: no subthreshold signing under the ideal setup boundary.
- `FST-L7`: abort, withholding, retry, and release compatibility.
- `FST-L10`: unauthorized-output classifier closure and
  `eps_cls_unmapped = 0`.

Controlling source worksheets include:

- [formal-security-theorem.md](formal-security-theorem.md): `FST-T1-IdealVSS`,
  `FST-A0`, `FST-G1`, and `FST-H0-IdealVSS`.
- [idealvss-signing-theorem-closure.md](idealvss-signing-theorem-closure.md):
  `idealvss-theorem-target`, `idealvss-dependency-ledger`,
  `idealvss-hybrid-route`, and `idealvss-acceptance-criteria`.
- [idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md): `IVLS-2`,
  `IVLS-11`, and `ivls-acceptance-criteria`.
- [fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md): the
  foundational transcript, challenge, and collection closure batch for
  `FST-L1`, `FST-L2`, and `FST-L3`.
- [fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md): the
  middle-layer ideal contribution, aggregation, threshold authorization, and
  abort-compatibility closure batch for `FST-L4` through `FST-L7`.
- [fst-l10-classifier-theorem-closure.md](fst-l10-classifier-theorem-closure.md):
  the ordered unauthorized-output classifier route for `FST-L10` and the
  `eps_cls_unmapped = 0` target.
- [fst-t1-idealvss-final-proof.md](fst-t1-idealvss-final-proof.md): the
  assembled conditional IdealVSS theorem route that imports `FST-L1` through
  `FST-L7`, `FST-L10`, and the final-form residual ledger.
- [rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md):
  the accepted-distribution closure batch for `eps_mask`, `eps_rej`, and
  `eps_withhold`.
- [contribution-backend-decision-record.md](contribution-backend-decision-record.md):
  `cbdr-decision`, `cbdr-non-production-idealization-boundary`,
  `cbdr-residual-terms`, and `F_CONTRIB`.
- [real-ideal-simulator.md](real-ideal-simulator.md): `ris-9-hybrid-sequence-s0s8`.
- [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md): `SHR-1A`,
  `SHR-L7`, `SHR-L8`, and the consolidated bound.
- [proof-closure-ledger.md](proof-closure-ledger.md): `ledger-term-table` and
  `ledger-non-claims`.

## FSTT1-6. Simulator and Hybrid Route
<a id="fstt1-hybrid-route"></a>

The real/ideal simulator route should be read as a structured proof plan:

```text
S0 real execution
 -> S1 canonical transcript and collection cleanup
 -> S2 ideal F_VSS_DKG setup boundary
 -> S3 commitment and random-oracle programming boundary
 -> S4 mask and rejection-preservation boundary
 -> S5 ideal F_CONTRIB contribution boundary
 -> S6 aggregation and standard-verifier compatibility
 -> S7 release, abort, evidence, and collection handling
 -> S8 unauthorized-output classification
```

Every transition must either be exact, be charged to a named residual, or be
discharged by a referenced lemma. The route is invalid if an accepting
unauthorized output reaches `S8` without landing in a classifier case or without
the unmapped case being proved impossible.

## FSTT1-7. Acceptance Criteria
<a id="fstt1-acceptance-criteria"></a>

This theorem can be upgraded from target to completed IdealVSS signing theorem
only after all of the following are true:

- `F_VSS_DKG` and `F_CONTRIB` interfaces are exact and stable.
- `FST-L1` through `FST-L7` are written as proof statements, not only
  worksheets.
- `FST-L10` proves classifier totality, disjointness, and
  `eps_cls_unmapped = 0`.
- `eps_vss_ideal`, `eps_contrib_ideal`, and `eps_classify` are kept visible or
  formally discharged.
- The simulator hybrid sequence accounts for `eps_evid`, `eps_abort`, and
  `eps_release`.
- Implementation tests are described only as review evidence.
- No production VSS/DKG, production contribution backend, or deployment
  readiness claim is made.

## FSTT1-8. Non-Claims
<a id="fstt1-non-claims"></a>

This document does not claim:

- `FST-T1-IdealVSS` is proved.
- Production `FST-T1 threshold unforgeability` is proved.
- Concrete malicious-secure VSS/DKG security is proved.
- A production contribution backend has been selected or proved.
- `eps_mask`, `eps_rej`, `eps_withhold`, `eps_verify`, `eps_commit`,
  `eps_ro_prior`, `eps_ro_sep`, `eps_collect`, `eps_threshold`,
  `eps_contrib_ideal`, `eps_vss_ideal`, or `eps_classify` is negligible, zero,
  or numerically bounded.
- The repository is production-ready, audited, or side-channel reviewed.

## FSTT1-9. Manifest Anchors
<a id="fstt1-manifest-anchors"></a>

Stable anchors and text markers:

- `# FST-T1-IdealVSS Theorem Consolidation`
- `fst-t1-idealvss-theorem`
- `Status: theorem consolidation target, not a completed proof.`
- `FSTT1-0. Scope and Non-Claim`
- `FSTT1-1. Theorem Statement Under Ideal Setup`
- `FSTT1-2. Ideal Functionality Boundaries`
- `FSTT1-3. Assumptions`
- `FSTT1-4. Advantage Bound Shape`
- `FSTT1-5. Lemma and Worksheet Dependencies`
- `FSTT1-6. Simulator and Hybrid Route`
- `FSTT1-7. Acceptance Criteria`
- `FSTT1-8. Non-Claims`
- `FSTT1-9. Manifest Anchors`
- `FST-T1-IdealVSS`
- `F_VSS_DKG`
- `F_CONTRIB`
- `F_contrib`
- `fst-t1-idealvss-final-proof.md`
- `eps_vss_ideal`
- `eps_contrib_ideal`
- `eps_classify`
- `eps_cls_unmapped = 0`
- `q_out * eps_mldsa`
- `implementation_residual`
- `audit_residual`
- `not a completed proof`
- `implementation evidence is not cryptographic proof`
- `not production-ready`
