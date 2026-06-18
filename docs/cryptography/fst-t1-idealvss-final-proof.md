# FST-T1-IdealVSS Final Proof Assembly
<a id="fst-t1-idealvss-final-proof"></a>

Status: assembled IdealVSS theorem route, not a production cryptographic proof.

This document assembles the current proof route for `FST-T1-IdealVSS`. It
imports the FST-L1 through FST-L7 theorem-closure batches, the FST-L10
classifier route, the simulator hybrid worksheets, and the final-form epsilon
ledger into one reviewer-facing theorem statement.

The assembly is conditional. It records how the ideal signing-side result is
intended to follow once the imported lemmas hold under their stated
preconditions. It does not instantiate production VSS/DKG, does not replace the
ideal contribution functionality, and does not turn implementation evidence
into cryptographic proof.

## FP-0. Scope and Non-Claim
<a id="fp-scope-non-claim"></a>

`FST-T1-IdealVSS` is the immediate signing-side theorem route for threshold
ML-DSA-65 under ideal setup and ideal contribution validation. It assumes
`F_VSS_DKG` for setup and `F_CONTRIB` / `F_contrib` for contribution-validity
decisions.

The adversary model is static active corruption: the PPT adversary corrupts at
most `t - 1 validators` before ideal setup. The assembly does not cover adaptive
corruption, production DKG/VSS, production contribution proofs, side-channel
security, deployment readiness, or independent audit.

Implementation evidence is not cryptographic proof. Actor tests, hazmat
ML-DSA-65 experiments, transcript determinism checks, and documentation
manifests are review evidence only. This repository remains not
production-ready.

## FP-1. Theorem Statement
<a id="fp-theorem-statement"></a>

Conditional theorem route:

```text
FST-T1-IdealVSS:
For every PPT adversary A and environment Z, if A statically corrupts at most
t - 1 validators before ideal F_VSS_DKG setup, then any accepting unauthorized
aggregate output in FST-G1 for threshold ML-DSA-65 under ideal F_VSS_DKG and
ideal F_CONTRIB/F_contrib is bounded by the base ML-DSA-65 forgery term plus
the visible residual terms in FP-5, assuming FST-L1 through FST-L7 and FST-L10
hold under their stated preconditions.
```

The theorem route is deliberately phrased as an advantage bound, not as a
closed production-security claim. Each residual term is either imported from a
closure document, charged to an ideal functionality boundary, or left visible
as a remaining proof/audit obligation.

## FP-2. Ideal Functionality Boundary
<a id="fp-ideal-functionality-boundary"></a>

`F_TMLDSA` is the ideal threshold-signing functionality used by the simulator
surface. In this route it receives setup outputs from `F_VSS_DKG` and
contribution-validity decisions from `F_CONTRIB`.

`F_VSS_DKG` abstracts the epoch setup boundary: validator enrollment, accepted
dealer/share outputs, epoch public-key material, setup transcript digest, and
allowed leakage. The associated term is `eps_vss_ideal`, not production
`eps_vss`.

`F_CONTRIB` / `F_contrib` abstracts contribution validation. It is an
IdealVSS theorem-isolation device that keeps `eps_contrib_ideal` visible until
a production backend proves contribution soundness, extractability or
simulation, hiding, context binding, and leakage discipline.

These boundaries are acceptable only for the ideal theorem route. They are not
production backend selections.

## FP-3. Imported Lemmas
<a id="fp-imported-lemmas"></a>

The assembled route imports these proof batches:

- [fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md): `FST-L1`,
  `FST-L2`, and `FST-L3` for transcript injectivity, challenge binding, and
  canonical collection soundness.
- [fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md): `FST-L4`,
  `FST-L5`, `FST-L6`, and `FST-L7` for ideal contribution validity,
  aggregation correctness, no subthreshold signing, and abort/release/evidence
  compatibility.
- [fst-l10-classifier-theorem-closure.md](fst-l10-classifier-theorem-closure.md):
  `FST-L10` for ordered unauthorized-output classification and the
  `eps_cls_unmapped = 0` target.
- [eps-contrib-backend-proof-route.md](eps-contrib-backend-proof-route.md):
  Batch B roadmap for replacing or justifying `F_CONTRIB`.
- [eps-verify-absorption-decision.md](eps-verify-absorption-decision.md):
  Batch B route for deciding whether verifier mismatch is absorbed into
  `eps_rej` or carried as `eps_verify`.
- [eps-classify-elimination-route.md](eps-classify-elimination-route.md):
  Batch B route for classifier totality, disjointness, and the
  `eps_cls_unmapped = 0` target.
- [eps-contrib-backend-decision-record.md](eps-contrib-backend-decision-record.md):
  Batch C decision to keep immediate theorem work on ideal `F_CONTRIB` while
  production remains blocked.
- [eps-verify-absorption-decision-record.md](eps-verify-absorption-decision-record.md):
  Batch C decision to carry `eps_verify` separately until byte-level verifier
  and rejection predicate proofs close over the same candidate tuple.
- [eps-classify-per-case-reductions.md](eps-classify-per-case-reductions.md):
  Batch C per-case classifier reduction obligations.
- [eps-vss-production-route.md](eps-vss-production-route.md):
  Batch C production VSS/DKG realization route for replacing `F_VSS_DKG`.
- [f-contrib-ideal-functionality.md](f-contrib-ideal-functionality.md):
  Batch D ideal contribution functionality interface and simulator boundary.
- [eps-verify-rejection-absorption-closure.md](eps-verify-rejection-absorption-closure.md):
  Batch D byte-level verifier/rejection absorption theorem interface.
- [eps-classify-totality-disjointness-closure.md](eps-classify-totality-disjointness-closure.md):
  Batch D classifier totality, disjointness, and unmapped-elimination route.
- [vss-dkg-production-obligation-split.md](vss-dkg-production-obligation-split.md):
  Batch D split between ideal `F_VSS_DKG` assumptions and production DKG
  obligations.
- [f-contrib-realization-simulator.md](f-contrib-realization-simulator.md):
  Batch E real/ideal simulator draft for future `F_CONTRIB` realization.
- [eps-verify-to-rej-absorption-theorem.md](eps-verify-to-rej-absorption-theorem.md):
  Batch E verifier-to-rejection absorption hybrid draft.
- [eps-classify-unmapped-zero-theorem.md](eps-classify-unmapped-zero-theorem.md):
  Batch E contradiction route for the `eps_cls_unmapped = 0` theorem target.
- [vss-dkg-backend-dependency-graph.md](vss-dkg-backend-dependency-graph.md):
  Batch E backend-selection dependency graph for replacing ideal `F_VSS_DKG`.
- [fst-t1-idealvss-theorem.md](fst-t1-idealvss-theorem.md): the theorem target,
  ideal-boundary statement, dependencies, and simulator route.
- [epsilon-residual-ledger-final-form.md](epsilon-residual-ledger-final-form.md):
  the publication-facing residual names and final-form bound.
- [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md): the
  `S0..S8` real/ideal transition worksheet.
- [proof-closure-ledger.md](proof-closure-ledger.md): term status, closure
  requirements, and non-claim language.

The imported lemma set is necessary but not enough for production security.
Production security additionally needs concrete VSS/DKG and contribution
backend realization theorems, accepted-distribution closure, side-channel
review, and audit.

## FP-4. Hybrid Proof Assembly
<a id="fp-hybrid-proof-assembly"></a>

The simulator route is assembled as the following transition chain:

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

The transition from `S0 real execution` to `S1` imports `FST-L1`, `FST-L2`,
and `FST-L3`; losses are charged to `eps_ro_prior`, `eps_ro_sep`,
`eps_commit`, and `eps_collect` as applicable.

The transition from `S1` to `S2` replaces concrete setup with `F_VSS_DKG`;
loss is charged to `eps_vss_ideal`.

The transition from `S2` to `S3` programs and binds the Fiat-Shamir transcript;
loss is charged to `eps_commit`, `eps_ro_prior`, and `eps_ro_sep`.

The transition from `S3` to `S4` preserves mask and rejection behavior; losses
remain visible as `eps_mask`, `eps_rej`, `eps_withhold`, and `eps_verify`.

The transition from `S4` to `S5` replaces production contribution checking with
`F_CONTRIB`; loss is charged to `eps_contrib_ideal`.

The transition from `S5` to `S6` imports `FST-L5` and `FST-L6`; losses are
charged to `eps_collect`, `eps_threshold`, `eps_rej`, and `eps_verify`.

The transition from `S6` to `S7` imports `FST-L7`; losses are charged to
`eps_withhold`, `eps_abort`, `eps_release`, and `eps_evid`.

The transition from `S7` to `S8 unauthorized-output classification` imports
`FST-L10`; the residual is `eps_classify`, and the unmapped case must satisfy
`eps_cls_unmapped = 0` before the classifier can be described as total.

## FP-5. Advantage Bound
<a id="fp-advantage-bound"></a>

The assembled final-form bound is:

```text
Adv_FST_T1_IdealVSS(A,Z)
 <= eps_sched(A,Z)
  + eps_evid(A,Z)
  + eps_vss_ideal(A,Z)
  + eps_contrib_ideal(A,Z)
  + eps_commit(A,Z)
  + eps_ro_prior(A,Z)
  + eps_ro_sep(A,Z)
  + eps_mask(A,Z)
  + eps_rej(A,Z)
  + eps_withhold(A,Z)
  + eps_verify(A,Z)
  + eps_abort(A,Z)
  + eps_release(A,Z)
  + eps_collect(A,Z)
  + eps_threshold(A,Z)
  + q_out * eps_mldsa(B_mldsa)
  + eps_classify(A,Z)
  + implementation_residual
  + audit_residual
  + negl(lambda)
```

No term in this expression is silently erased. The assembly can cite a lemma,
ideal boundary, or assumption for a term, but it cannot claim that the term is
negligible, zero, or numerically bounded unless the referenced document proves
that stronger statement.

## FP-6. Classifier Elimination Condition
<a id="fp-classifier-elimination-condition"></a>

`FST-L10` is the last gate for unauthorized accepting outputs. The classifier
must be total and disjoint over the production transcript grammar. Its cases
include base ML-DSA forgery, threshold-share break, VSS/DKG break, commitment
break, contribution break, random-oracle transcript break, collection break,
evidence break, authorized replay, and the unmapped case.

The condition `eps_cls_unmapped = 0` eliminates only the unmapped classifier
case. The other classifier cases must still be reduced to the base term
`q_out * eps_mldsa(B_mldsa)` or charged to named terms such as
`eps_threshold`, `eps_vss_ideal`, `eps_commit`, `eps_contrib_ideal`,
`eps_ro_prior`, `eps_ro_sep`, `eps_collect`, and `eps_evid`.

Therefore `eps_classify` can be expanded through named classifier cases, but it
must not be deleted by prose unless every case has been accounted for.

The Batch B classifier roadmap is
[eps-classify-elimination-route.md](eps-classify-elimination-route.md). It
keeps `eps_cls_unmapped = 0` as a target condition, not a proved fact.
The Batch C per-case route is
[eps-classify-per-case-reductions.md](eps-classify-per-case-reductions.md).

## FP-7. Residual Terms That Remain
<a id="fp-residual-terms-remain"></a>

The following terms remain visible in the IdealVSS theorem route:

- `eps_vss_ideal` for ideal setup leakage and semantics.
- `eps_contrib_ideal` for ideal contribution validation.
- `eps_contrib` and the
  [eps_contrib backend proof route](eps-contrib-backend-proof-route.md) until a
  proof, MPC/interactive, or ideal-realization backend is selected and proved.
  The current Batch C decision record is
  [eps-contrib-backend-decision-record.md](eps-contrib-backend-decision-record.md).
  The Batch D ideal functionality interface is
  [f-contrib-ideal-functionality.md](f-contrib-ideal-functionality.md).
  The Batch E simulator draft is
  [f-contrib-realization-simulator.md](f-contrib-realization-simulator.md).
- `eps_commit`, `eps_ro_prior`, and `eps_ro_sep` for commitment and
  random-oracle programming.
- `eps_mask`, `eps_rej`, `eps_withhold`, and `eps_verify` for mask,
  rejection, selective-abort, and verifier-compatibility gaps.
- `eps_verify` remains governed by
  [eps-verify-absorption-decision.md](eps-verify-absorption-decision.md) until
  the final theorem chooses absorption into `eps_rej` or separate carry.
  The current Batch C decision record is
  [eps-verify-absorption-decision-record.md](eps-verify-absorption-decision-record.md).
  The Batch D closure route is
  [eps-verify-rejection-absorption-closure.md](eps-verify-rejection-absorption-closure.md).
  The Batch E absorption theorem draft is
  [eps-verify-to-rej-absorption-theorem.md](eps-verify-to-rej-absorption-theorem.md).
- `eps_abort`, `eps_release`, and `eps_evid` for simulator-visible abort,
  release, and evidence transitions.
- `eps_collect` and `eps_threshold` for canonical active-set handling and
  no-subthreshold authorization.
- `eps_classify` until classifier totality, disjointness, and all per-case
  reductions are discharged. The Batch D closure route is
  [eps-classify-totality-disjointness-closure.md](eps-classify-totality-disjointness-closure.md).
  The Batch E unmapped-zero theorem draft is
  [eps-classify-unmapped-zero-theorem.md](eps-classify-unmapped-zero-theorem.md).
- `implementation_residual` and `audit_residual` until code correctness,
  constant-time behavior, randomness, integration, and external review are
  closed.

## FP-8. What This Proves
<a id="fp-what-this-proves"></a>

This assembly records a documentation-level theorem route: all current
IdealVSS signing-side assumptions, lemma imports, simulator transitions, and
residual terms are now joined into one coherent statement.

It is sufficient to support reviewer discussion of the conditional
`FST-T1-IdealVSS` claim under ideal `F_VSS_DKG`, ideal `F_CONTRIB`, and static
active corruption of at most `t - 1 validators`, provided the imported lemmas
are accepted under their stated preconditions.

## FP-9. What This Does Not Prove
<a id="fp-what-this-does-not-prove"></a>

This assembly is not a production cryptographic proof. It does not prove:

- production `FST-T1 threshold unforgeability`;
- malicious-secure production VSS/DKG;
- production contribution soundness, extraction, simulation, or hiding;
- accepted-distribution equality for aggregate masks and rejection sampling;
- selective-abort security under production network timing;
- side-channel safety or constant-time execution;
- FIPS validation;
- production slashing soundness;
- external audit closure.

The artifact remains not production-ready.

## FP-10. Acceptance Criteria
<a id="fp-acceptance-criteria"></a>

This proof assembly is acceptable only if it:

- states the exact `FST-T1-IdealVSS` theorem route under ideal `F_VSS_DKG` and
  ideal `F_CONTRIB` / `F_contrib`;
- imports `FST-L1`, `FST-L2`, `FST-L3`, `FST-L4`, `FST-L5`, `FST-L6`,
  `FST-L7`, and `FST-L10`;
- preserves `eps_cls_unmapped = 0` as a classifier condition, not a blanket
  deletion of `eps_classify`;
- keeps `eps_abort`, `eps_release`, and `eps_evid` visible in the simulator
  route;
- includes `implementation_residual` and `audit_residual`;
- says implementation evidence is not cryptographic proof;
- says the assembly is not a production cryptographic proof and not
  production-ready.

## FP-11. Manifest Anchors
<a id="fp-manifest-anchors"></a>

Stable anchors and text markers:

- `# FST-T1-IdealVSS Final Proof Assembly`
- `fst-t1-idealvss-final-proof`
- `Status: assembled IdealVSS theorem route, not a production cryptographic proof.`
- `FP-0. Scope and Non-Claim`
- `FP-1. Theorem Statement`
- `FP-2. Ideal Functionality Boundary`
- `FP-3. Imported Lemmas`
- `FP-4. Hybrid Proof Assembly`
- `FP-5. Advantage Bound`
- `FP-6. Classifier Elimination Condition`
- `FP-7. Residual Terms That Remain`
- `FP-8. What This Proves`
- `FP-9. What This Does Not Prove`
- `FP-10. Acceptance Criteria`
- `FP-11. Manifest Anchors`
- `FST-T1-IdealVSS`
- `FST-G1`
- `F_TMLDSA`
- `F_VSS_DKG`
- `F_CONTRIB`
- `F_contrib`
- `static active corruption`
- `at most t - 1 validators`
- `FST-L1`
- `FST-L2`
- `FST-L3`
- `FST-L4`
- `FST-L5`
- `FST-L6`
- `FST-L7`
- `FST-L10`
- `fst-l1-l3-theorem-closure.md`
- `fst-l4-l7-theorem-closure.md`
- `fst-l10-classifier-theorem-closure.md`
- `eps-contrib-backend-proof-route.md`
- `eps-verify-absorption-decision.md`
- `eps-classify-elimination-route.md`
- `eps-contrib-backend-decision-record.md`
- `eps-verify-absorption-decision-record.md`
- `eps-classify-per-case-reductions.md`
- `eps-vss-production-route.md`
- `f-contrib-ideal-functionality.md`
- `eps-verify-rejection-absorption-closure.md`
- `eps-classify-totality-disjointness-closure.md`
- `vss-dkg-production-obligation-split.md`
- `f-contrib-realization-simulator.md`
- `eps-verify-to-rej-absorption-theorem.md`
- `eps-classify-unmapped-zero-theorem.md`
- `vss-dkg-backend-dependency-graph.md`
- `eps_cls_unmapped = 0`
- `q_out * eps_mldsa(B_mldsa)`
- `eps_vss_ideal`
- `eps_contrib_ideal`
- `eps_commit`
- `eps_ro_prior`
- `eps_ro_sep`
- `eps_mask`
- `eps_rej`
- `eps_withhold`
- `eps_verify`
- `eps_abort`
- `eps_release`
- `eps_evid`
- `eps_collect`
- `eps_threshold`
- `eps_classify`
- `implementation_residual`
- `audit_residual`
- `Adv_FST_T1_IdealVSS(A,Z)`
- `S0 real execution`
- `S8 unauthorized-output classification`
- `not a production cryptographic proof`
- `implementation evidence is not cryptographic proof`
- `not production-ready`
