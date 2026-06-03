# FST-L10 Classifier Theorem Closure Batch
<a id="fst-l10-classifier-theorem-closure"></a>

Status: classifier theorem-closure batch, not a full cryptographic proof.

This document consolidates the unauthorized-output classifier layer for
`FST-T1-IdealVSS`. It ties `FST-L10`, the classifier closure route, and the
classifier elimination plan into one proof target: after `FST-L1..FST-L7` have
closed under their stated assumptions, every accepting unauthorized output must
land in exactly one classifier case. The target is `eps_cls_unmapped = 0`.

The batch is conditional. It does not by itself prove final unforgeability,
production VSS/DKG security, production contribution soundness, or production
readiness.

## L10C-0. Scope and Non-Claim
<a id="l10c-scope-non-claim"></a>

The closure target is:

```text
FST-L10:
  Under the fixed production transcript grammar, FST-L1..FST-L7 theorem
  routes, ideal F_VSS_DKG, and ideal F_CONTRIB, every accepting unauthorized
  output Out* is classified into exactly one ordered case:
  AuthorizedReplay, MldsaForgery, ThresholdAuthorizationBreak, VssDkgBreak,
  CommitmentBreak, ContributionBreak, RoTranscriptBreak, CollectionBreak,
  EvidenceBreak, or Unmapped.

  The final classifier theorem must prove Pr[Unmapped] = eps_cls_unmapped = 0.
```

Implementation evidence is not cryptographic proof.

## L10C-1. Input Domain
<a id="l10c-input-domain"></a>

The classifier input domain is:

- `Out*`: accepting aggregate output candidate.
- `AggregateOutputRecord`: transcript-bound aggregate signature record.
- `ReleaseSignature`: ideal or real release record.
- `EvidenceRecord`: public evidence associated with invalid frames or protocol
  faults.
- `authorized_release_log`: ideal log of messages and outputs released by
  `F_TMLDSA`.
- `SigningContext`, `ChallengeRecord`, `CommitmentSet`, `PartialShareSet`,
  active set, validator inventory, DKG digest, epoch key, and message binding.

Any output not representable in this input grammar is not silently ignored. It
is either rejected before classification or assigned to `Unmapped`, which must
be proved impossible before `eps_classify` can be removed.

## L10C-2. Ordered Case Grammar
<a id="l10c-ordered-case-grammar"></a>

The classifier order is:

1. `AuthorizedReplay`: the output is already in `authorized_release_log` or is
   a deterministic replay allowed by the release policy.
2. `MldsaForgery`: the output verifies under standard ML-DSA-65 but was not
   released by the threshold functionality.
3. `ThresholdAuthorizationBreak`: fewer than `t` valid, unique, authorized
   validators are counted.
4. `VssDkgBreak`: the output depends on setup behavior outside ideal
   `F_VSS_DKG`.
5. `CommitmentBreak`: commitment binding, opening-set equality, or
   challenge-context binding fails.
6. `ContributionBreak`: accepted contribution validity, context, extraction,
   hiding, schema, or leakage assumptions fail.
7. `RoTranscriptBreak`: transcript injectivity, domain separation, prior-query,
   replay, or random-oracle binding fails.
8. `CollectionBreak`: canonical collection, active-set, quorum, duplicate,
   stale-record, evidence, or release consistency fails.
9. `EvidenceBreak`: evidence attribution, anti-framing, release interaction, or
   public-evidence semantics fail.
10. `Unmapped`: no prior case applies.

## L10C-3. Totality Target
<a id="l10c-totality-target"></a>

Totality means every accepting unauthorized `Out*` is either rejected by the
production grammar or classified by one of the ordered cases. The proof route
uses:

- [fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md) for transcript,
  challenge, and collection well-formedness.
- [fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md) for contribution,
  aggregation, threshold authorization, abort, evidence, and release routing.
- [production-transcript-grammar.md](production-transcript-grammar.md) for the
  classifier input grammar.
- `F_VSS_DKG` and `F_CONTRIB` for the immediate IdealVSS theorem boundary.

The target equation is:

```text
eps_classify
 <= eps_cls_mldsa
  + eps_cls_threshold
  + eps_cls_vss_dkg
  + eps_cls_commit
  + eps_cls_contrib
  + eps_cls_ro_transcript
  + eps_cls_collect
  + eps_cls_evid
  + eps_cls_unmapped

eps_cls_unmapped = 0
```

## L10C-4. Disjointness Target
<a id="l10c-disjointness-target"></a>

Disjointness means the first matching ordered case is unique and stable under
canonical parsing. If an output appears to satisfy two cases, the earlier case
in the grammar owns it and the later case is not counted. This prevents double
charging while preserving a complete route for every bad event.

The disjointness proof depends on fixed case predicates, canonical transcript
records, stable evidence/release semantics, and no optional classifier fields
with ambiguous meanings.

## L10C-5. Per-Case Reduction Map
<a id="l10c-reduction-map"></a>

| Case | Charged term | Required reduction or dependency |
| --- | --- | --- |
| `AuthorizedReplay` | none | Match `authorized_release_log` under deterministic replay policy. |
| `MldsaForgery` | `eps_cls_mldsa` / `q_out * eps_mldsa(B_mldsa)` | Produce a base ML-DSA-65 forgery. |
| `ThresholdAuthorizationBreak` | `eps_cls_threshold`, `eps_threshold` | Reduce to `FST-L6` threshold authorization failure. |
| `VssDkgBreak` | `eps_cls_vss_dkg`, `eps_vss_ideal` | Charge ideal setup boundary or future concrete VSS/DKG theorem. |
| `CommitmentBreak` | `eps_cls_commit`, `eps_commit` | Charge commitment/context/opening failure. |
| `ContributionBreak` | `eps_cls_contrib`, `eps_contrib_ideal`, `eps_contrib` | Charge ideal `F_CONTRIB` or future production backend theorem. |
| `RoTranscriptBreak` | `eps_cls_ro_transcript`, `eps_ro_prior`, `eps_ro_sep` | Charge `FST-L1`/`FST-L2` transcript and challenge route. |
| `CollectionBreak` | `eps_cls_collect`, `eps_collect` | Charge `FST-L3` collection route. |
| `EvidenceBreak` | `eps_cls_evid`, `eps_evid` | Charge evidence or release-attribution route. |
| `Unmapped` | `eps_cls_unmapped` | Must be proved impossible for final theorem closure. |

## L10C-5A. Case Name Alignment
<a id="l10c-case-name-alignment"></a>

The canonical threshold-side authorization case name is
`ThresholdAuthorizationBreak`. Older proof notes may describe the same semantic
case as a threshold-share break, but manifest-tracked classifier documents must
use `ThresholdAuthorizationBreak` for the ordered case grammar. This alignment
does not prove classifier totality, classifier disjointness, or
`eps_cls_unmapped = 0`; it only removes a naming ambiguity before the
unmapped-zero proof route is attempted.

## L10C-6. Acceptance Criteria
<a id="l10c-acceptance-criteria"></a>

The classifier can be treated as closed only if:

- `FST-L10` states totality and disjointness as proof obligations.
- The classifier closure and elimination documents use the same ordered case
  grammar.
- Every case has a reduction target or visible residual term.
- `Unmapped` is syntactically unreachable after all accepted outputs are parsed
  under the production grammar and the `FST-L1..FST-L7` routes.
- `eps_cls_unmapped = 0` is stated as a theorem result only under those
  prerequisites.

## L10C-7. Non-Claims
<a id="l10c-non-claims"></a>

This batch does not claim final unforgeability unless all predecessor lemmas
and backend assumptions are closed. It does not prove production VSS/DKG,
production contribution soundness, side-channel safety, audit completion, or
production readiness.

## L10C-8. Manifest Anchors
<a id="l10c-manifest-anchors"></a>

Stable anchors and text markers:

- `# FST-L10 Classifier Theorem Closure Batch`
- `fst-l10-classifier-theorem-closure`
- `Status: classifier theorem-closure batch, not a full cryptographic proof.`
- `L10C-0. Scope and Non-Claim`
- `L10C-1. Input Domain`
- `L10C-2. Ordered Case Grammar`
- `L10C-3. Totality Target`
- `L10C-4. Disjointness Target`
- `L10C-5. Per-Case Reduction Map`
- `L10C-5A. Case Name Alignment`
- `L10C-6. Acceptance Criteria`
- `L10C-7. Non-Claims`
- `L10C-8. Manifest Anchors`
- `FST-L10`
- `AuthorizedReplay`
- `MldsaForgery`
- `ThresholdAuthorizationBreak`
- `l10c-case-name-alignment`
- `VssDkgBreak`
- `CommitmentBreak`
- `ContributionBreak`
- `RoTranscriptBreak`
- `CollectionBreak`
- `EvidenceBreak`
- `Unmapped`
- `eps_classify`
- `eps_cls_unmapped = 0`
- `FST-L1..FST-L7`
- `F_CONTRIB`
- `F_VSS_DKG`
- `implementation evidence is not cryptographic proof`
- `not a full cryptographic proof`
- `not production-ready`
