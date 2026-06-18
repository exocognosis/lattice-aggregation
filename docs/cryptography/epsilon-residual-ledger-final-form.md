# Epsilon Residual Ledger Final Form
<a id="epsilon-residual-ledger-final-form"></a>

Status: final-form residual worksheet, not a completed advantage proof.

This document normalizes the named epsilon terms that remain visible in the
IdealVSS signing theorem route. It is intended for paper drafting and reviewer
navigation: it states the current bound shape, records how the simulator and
worksheet terms map to publication-facing names, and prevents implementation
evidence from being mistaken for cryptographic proof.

## ERLFF-0. Scope and Non-Claim
<a id="erlff-scope-status"></a>

This is a residual ledger. It does not prove that any term is negligible, zero,
or numerically bounded. It does not close `FST-T1-IdealVSS`, and it does not
claim production `FST-T1 threshold unforgeability`.

The ledger keeps idealization terms explicit:

- `F_VSS_DKG` / `eps_vss_ideal` is an IdealVSS proof-decomposition boundary,
  not concrete production VSS/DKG security.
- `F_CONTRIB` / `eps_contrib_ideal` is the immediate contribution-route
  placeholder, not a production backend.
- Production theorem work still requires replacing ideal setup and ideal
  contribution assumptions with concrete realization theorems before production
  claims.

## ERLFF-1. Consolidated Bound
<a id="erlff-final-advantage-expression"></a>

The current final-form worksheet expression is:

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

The simulator worksheet also states the route as:

```text
Adv_real_ideal(A,Z)
 <= eps_sched(A,Z)
  + eps_evid(A,Z)
  + eps_vss_ideal(A,Z)
  + eps_commit(A,Z)
  + eps_contrib(A,Z)
  + eps_ro_prior(A,Z)
  + eps_ro_sep(A,Z)
  + eps_reject(A,Z)
  + eps_abort(A,Z)
  + eps_release(A,Z)
  + eps_collect(A,Z)
  + eps_threshold(A,Z)
  + q_out * eps_mldsa(B_mldsa)
  + eps_classify(A,Z)
  + negl(lambda)
```

In this final-form ledger, `eps_contrib_ideal` is the immediate IdealVSS route
for `eps_contrib`. The production route must later replace it with a concrete
contribution backend theorem.

## ERLFF-2. Publication-Facing Term Map
<a id="erlff-term-definitions"></a>

| Term | Role in the bound | Current status |
| --- | --- | --- |
| `eps_vss` | Concrete VSS/DKG setup loss. | Open production blocker. |
| `eps_vss_ideal` | Loss from using ideal `F_VSS_DKG`. | Idealized route, not production. |
| `eps_contrib` | Contribution validity, binding, extraction or simulation, and hiding loss. | Production backend open. |
| `eps_contrib_ideal` | Loss placeholder under ideal `F_CONTRIB`. | Immediate theorem route, not production. |
| `eps_mask` | Aggregate-mask distribution gap. | Open proof obligation. |
| `eps_commit` | Commitment binding, hiding, and non-adaptivity loss. | Open proof obligation. |
| `eps_ro` | Random-oracle programming and domain-separation loss. | Open proof obligation. |
| `eps_ro_prior` | Prior-query loss before challenge programming. | Open proof obligation. |
| `eps_ro_sep` | Typed-domain and encoding separation loss. | Open proof obligation. |
| `eps_rej` | Aggregate-vs-central rejection predicate mismatch. | Open proof obligation. |
| `eps_withhold` | Selective abort, retry, timeout, and withholding bias. | Open proof obligation. |
| `eps_verify` | Standard verifier compatibility residual. | Engineering evidence only, proof open. |
| `eps_abort` | Abort-transition simulation loss. | Open simulator term. |
| `eps_release` | Release-record simulation and noninterference loss. | Open simulator term. |
| `eps_evid` | Evidence-record soundness and attribution loss. | Open simulator term. |
| `eps_collect` | Canonical collection and active-set validation loss. | Open proof obligation. |
| `eps_threshold` | Threshold authorization and no-subthreshold-signing residual. | Open proof obligation. |
| `eps_classify` | Unauthorized-output classifier residual. | Must be eliminated for final theorem. |
| `eps_mldsa` | Base ML-DSA-65 forgery advantage. | External assumption term. |
| `implementation_residual` | Code, side-channel, randomness, compiler, and integration residuals. | Audit and implementation blocker. |
| `audit_residual` | Independent assurance gap. | Not closed. |

Implementation evidence is not cryptographic proof.

## ERLFF-3. Idealization Terms
<a id="erlff-idealization-terms"></a>

`eps_vss_ideal` is charged when the proof replaces concrete DKG/VSS with
`F_VSS_DKG`. It is acceptable for the immediate signing-side theorem only if the
ideal functionality exposes exact leakage, setup outputs, dealer acceptance,
and share delivery semantics.

`eps_contrib_ideal` is charged when the proof replaces concrete contribution
proof checking with `F_CONTRIB`. It isolates signing-side reasoning from the
future production contribution backend. It does not select or prove a
zero-knowledge, MPC, interactive, or lattice-specific proof system.

Neither term can be erased in production wording until a concrete realization
theorem replaces the ideal boundary.

## ERLFF-4. Rejection-Sampling Expansion
<a id="erlff-rejection-sampling-expansion"></a>

The simulator worksheet uses `eps_reject(A,Z)` as the bundled
rejection-sampling transition term:

```text
eps_reject(A,Z)
 <= eps_mask
  + eps_commit
  + eps_rej
  + eps_withhold
  + eps_ro
  + eps_verify
```

The accepted-distribution term `Delta_accept` can be removed only after mask
distribution, commitment non-adaptivity, rejection predicate equivalence,
selective-abort behavior, random-oracle programming, and verifier compatibility
are each proved or explicitly bounded.

The visible subterms `eps_mask`, `eps_rej`, and `eps_withhold` expand through
[eps-mask-theorem-closure.md](eps-mask-theorem-closure.md),
[eps-rej-theorem-closure.md](eps-rej-theorem-closure.md), and
[eps-withhold-theorem-closure.md](eps-withhold-theorem-closure.md),
respectively. Those documents are theorem-closure roadmaps for the residuals;
they do not make any of the terms zero, negligible, or production-ready.

Residual Closure Batch A refines those roadmaps through
[eps-mask-formalization.md](eps-mask-formalization.md),
[eps-rej-predicate-sublemmas.md](eps-rej-predicate-sublemmas.md), and
[eps-withhold-simulator-obligations.md](eps-withhold-simulator-obligations.md).
Those files expose the game, predicate-sublemma, and simulator-obligation
surfaces that a later proof must discharge.

## ERLFF-5. Classifier Expansion
<a id="erlff-classifier-expansion"></a>

The unauthorized-output classifier residual must expand into named cases:

```text
eps_classify(A,Z)
 <= eps_cls_mldsa(A,Z)
  + eps_cls_threshold(A,Z)
  + eps_cls_vss_dkg(A,Z)
  + eps_cls_commit(A,Z)
  + eps_cls_contrib(A,Z)
  + eps_cls_ro_transcript(A,Z)
  + eps_cls_collect(A,Z)
  + eps_cls_evid(A,Z)
  + eps_cls_unmapped(A,Z)
```

The final theorem cannot remove `eps_classify` until classifier totality and
disjointness are proved and `eps_cls_unmapped = 0`.

Residual Closure Batch B refines the contribution, verifier, and classifier
routes through
[eps-contrib-backend-proof-route.md](eps-contrib-backend-proof-route.md),
[eps-verify-absorption-decision.md](eps-verify-absorption-decision.md), and
[eps-classify-elimination-route.md](eps-classify-elimination-route.md). These
files are proof-roadmap artifacts, not completed contribution, verifier, or
classifier proofs.

Residual Closure Batch C adds decision and narrowing records:
[eps-contrib-backend-decision-record.md](eps-contrib-backend-decision-record.md),
[eps-verify-absorption-decision-record.md](eps-verify-absorption-decision-record.md),
[eps-classify-per-case-reductions.md](eps-classify-per-case-reductions.md), and
[eps-vss-production-route.md](eps-vss-production-route.md). These records do
not remove `eps_contrib_ideal`, absorb `eps_verify`, prove
`eps_cls_unmapped = 0`, or select production VSS/DKG.

Residual Closure Batch D adds theorem-interface records:
[f-contrib-ideal-functionality.md](f-contrib-ideal-functionality.md),
[eps-verify-rejection-absorption-closure.md](eps-verify-rejection-absorption-closure.md),
[eps-classify-totality-disjointness-closure.md](eps-classify-totality-disjointness-closure.md),
and [vss-dkg-production-obligation-split.md](vss-dkg-production-obligation-split.md).
These records do not eliminate `eps_contrib_ideal`, absorb `eps_verify`,
prove `eps_cls_unmapped = 0`, or replace `eps_vss_ideal`; they make the
interfaces and proof obligations precise enough for the next theorem pass.

Residual Closure Batch E adds formal-reduction drafts:
[f-contrib-realization-simulator.md](f-contrib-realization-simulator.md),
[eps-verify-to-rej-absorption-theorem.md](eps-verify-to-rej-absorption-theorem.md),
[eps-classify-unmapped-zero-theorem.md](eps-classify-unmapped-zero-theorem.md),
and [vss-dkg-backend-dependency-graph.md](vss-dkg-backend-dependency-graph.md).
These drafts do not prove simulator indistinguishability, absorb
`eps_verify`, prove `eps_cls_unmapped = 0`, or select a production VSS/DKG
backend; they assign the next proof skeletons to stable residual routes.

Residual Closure Batch F adds consistency and boundary-traceability locks. It
does not remove residuals: `ThresholdAuthorizationBreak` is the canonical
classifier authorization case name, `eps_verify_rej_absorb` and
`eps_verify_survive` remain visible in the V4 verifier partition, and
[hazmat-real-mldsa-protocol.md](hazmat-real-mldsa-protocol.md) records the
proof-bound scaffold frame and fail-closed production policy names.

## ERLFF-6. Parameterization Requirements
<a id="erlff-parameterization-requirements"></a>

Each term that remains in a publication theorem must be parameterized by the
security parameter, validator count, threshold, session count, retry limit,
oracle-query bounds, signing-query bound, active-set size, timeout policy,
backend family, transcript grammar version, and leakage model as applicable.

No parameterized numeric bound is supplied by this document.

## ERLFF-7. Acceptance Criteria
<a id="erlff-acceptance-criteria"></a>

This ledger is acceptable as a final-form residual map only if it:

- keeps `eps_vss_ideal` and `eps_contrib_ideal` visible;
- maps `eps_reject(A,Z)` to `eps_mask`, `eps_commit`, `eps_rej`,
  `eps_withhold`, `eps_ro`, and `eps_verify`;
- expands `eps_classify(A,Z)` through `eps_cls_unmapped`;
- preserves `implementation_residual` and `audit_residual`;
- avoids claiming any term is negligible, zero, or bounded without a proof;
- states that implementation evidence is not cryptographic proof.

## ERLFF-8. Non-Claims
<a id="erlff-non-claims"></a>

This document is not a completed proof, not production-ready, and not an audit.
It does not provide malicious-secure production VSS/DKG, a production
contribution proof, a completed ROM proof, an accepted-distribution theorem, a
selective-abort bound, or an `eps_cls_unmapped = 0` proof.

## ERLFF-9. Manifest Anchors
<a id="erlff-manifest-anchors"></a>

Stable anchors and text markers:

- `# Epsilon Residual Ledger Final Form`
- `epsilon-residual-ledger-final-form`
- `Status: final-form residual worksheet, not a completed advantage proof.`
- `ERLFF-0. Scope and Non-Claim`
- `ERLFF-1. Consolidated Bound`
- `ERLFF-2. Publication-Facing Term Map`
- `ERLFF-3. Idealization Terms`
- `ERLFF-4. Rejection-Sampling Expansion`
- `ERLFF-5. Classifier Expansion`
- `ERLFF-6. Parameterization Requirements`
- `ERLFF-7. Acceptance Criteria`
- `ERLFF-8. Non-Claims`
- `ERLFF-9. Manifest Anchors`
- `Adv_real_ideal(A,Z)`
- `eps_vss_ideal`
- `eps_contrib_ideal`
- `eps_reject(A,Z)`
- `Delta_accept`
- `eps-mask-formalization.md`
- `eps-rej-predicate-sublemmas.md`
- `eps-withhold-simulator-obligations.md`
- `eps-contrib-backend-proof-route.md`
- `eps-verify-absorption-decision.md`
- `eps-classify-elimination-route.md`
- `eps-contrib-backend-decision-record.md`
- `eps-verify-absorption-decision-record.md`
- `eps-classify-per-case-reductions.md`
- `f-contrib-ideal-functionality.md`
- `eps-verify-rejection-absorption-closure.md`
- `eps-classify-totality-disjointness-closure.md`
- `vss-dkg-production-obligation-split.md`
- `f-contrib-realization-simulator.md`
- `eps-verify-to-rej-absorption-theorem.md`
- `eps-classify-unmapped-zero-theorem.md`
- `vss-dkg-backend-dependency-graph.md`
- `hazmat-real-mldsa-protocol.md`
- `ThresholdAuthorizationBreak`
- `eps_verify_rej_absorb`
- `eps_verify_survive`
- `eps-vss-production-route.md`
- `eps_cls_unmapped = 0`
- `implementation evidence is not cryptographic proof`
- `not a completed proof`
- `not production-ready`
