# Unauthorized Output Classifier Elimination Plan
<a id="unauthorized-output-classifier-elimination"></a>

Date: 2026-05-28

Status: elimination plan for `eps_classify`, not a completed classifier proof.

## Scope and Non-Claim
<a id="uoce-scope-non-claim"></a>

This plan turns the classifier worksheet into a concrete elimination sequence.
The goal is to remove `eps_classify` from the final theorem by proving
`eps_cls_unmapped = 0`, after all production grammar and backend choices are
fixed.

This document does not prove `eps_cls_unmapped = 0`. It does not prove ML-DSA
unforgeability, VSS/DKG security, contribution soundness, commitment security,
random-oracle separation, evidence noninterference, or collection soundness.

## Production Grammar Prerequisite
<a id="uoce-production-grammar-prerequisite"></a>

The classifier cannot be eliminated until the production verifier grammar fixes
canonical encodings for:

```text
(m*, sigma*, pk_epoch, epoch_id, session_id, attempt,
 validator_set_digest, active_set, threshold,
 contribution_frames, contribution_statements, contribution_proofs,
 VSS_DKG_references, commitment_records, random_oracle_queries,
 collection_metadata, evidence_records, authorized_release_log)
```

Any accepted field that is ambiguous, optional without a default, or dependent
on noncanonical ordering keeps `eps_cls_unmapped` open.

## Elimination Sequence
<a id="uoce-elimination-sequence"></a>

1. Fix the ordered classifier grammar from
   [unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md).
2. Prove totality: every accepting unauthorized output matches a listed case
   or `Unmapped`.
3. Prove disjointness by ordered first-match semantics.
4. Attach a reduction algorithm, runtime loss, and assumption target to every
   non-gap case.
5. Prove the production grammar makes the `Unmapped` case unreachable.
6. Replace `eps_classify` with the sum of named reductions and delete
   `eps_cls_unmapped`.

## Case Closure Table
<a id="uoce-case-closure-table"></a>

| Case | Closure dependency |
| --- | --- |
| `eps_cls_mldsa` | Base ML-DSA EUF-CMA or strong unforgeability reduction. |
| `eps_cls_threshold` | Threshold-share authorization and collection soundness. |
| `eps_cls_vss_dkg` | Concrete VSS/DKG theorem or ideal setup theorem boundary. |
| `eps_cls_commit` | Commitment binding, hiding, and opening-set equality. |
| `eps_cls_contrib` | Selected production contribution backend theorem. |
| `eps_cls_ro_transcript` | Random-oracle and transcript injectivity closure. |
| `eps_cls_collect` | Canonical collection and active-set validation. |
| `eps_cls_evid` | Evidence noninterference and anti-framing theorem. |
| `eps_cls_unmapped` | Must be proved unreachable. |

## Acceptance Criteria
<a id="uoce-acceptance-criteria"></a>

Before `eps_classify` can be removed:

- The classifier input tuple is exactly the production verifier grammar.
- Every case has a reduction target and no case silently absorbs another open
  proof term.
- The authorized-release replay case is byte-level deterministic.
- Collection, contribution, transcript, and evidence failures are ordered so
  one output is charged once.
- The theorem explicitly proves `eps_cls_unmapped = 0`.

## Non-Claims
<a id="uoce-non-claims"></a>

This plan does not claim the classifier is total today. It does not claim
`eps_classify` is bounded or removable before backend, commitment,
random-oracle, rejection-sampling, collection, and evidence terms are closed.

## Manifest Anchors

- `# Unauthorized Output Classifier Elimination Plan`
- `unauthorized-output-classifier-elimination`
- `uoce-production-grammar-prerequisite`
- `uoce-elimination-sequence`
- `uoce-case-closure-table`
- `eps_cls_mldsa`
- `eps_cls_threshold`
- `eps_cls_vss_dkg`
- `eps_cls_commit`
- `eps_cls_contrib`
- `eps_cls_ro_transcript`
- `eps_cls_collect`
- `eps_cls_evid`
- `eps_cls_unmapped = 0`
- `uoce-acceptance-criteria`
- `uoce-non-claims`

