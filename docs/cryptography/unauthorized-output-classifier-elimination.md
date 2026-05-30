# Unauthorized Output Classifier Elimination Plan
<a id="unauthorized-output-classifier-elimination"></a>

Date: 2026-05-29

Status: classifier-elimination route text for `eps_classify`, not a completed
classifier proof.

## Scope and Non-Claim
<a id="uoce-scope-non-claim"></a>

This route turns the classifier worksheet into an ordered elimination sequence.
The goal is to remove `eps_classify` from the final theorem by replacing each
classifier case with a named residual or reduction and by making
`eps_cls_unmapped = 0` a theorem target after all production grammar and
backend choices are fixed.

This document does not prove `eps_cls_unmapped = 0`. It does not prove ML-DSA
unforgeability, VSS/DKG security, contribution soundness, commitment security,
random-oracle separation, evidence noninterference, or collection soundness.
It also does not state the final unauthorized-output theorem unless the
FST-L10 classifier totality/disjointness obligations and all per-case
reductions close.

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

The production grammar prerequisite is downstream of the FST-L1 through FST-L7
theorem closure batches: those batches close the base ML-DSA, transcript,
collection, commitment, contribution-interface, evidence, and ideal-boundary
terms that this route charges to classifier cases. This document only consumes
those closures; it does not restate them as new production claims.

## Elimination Sequence
<a id="uoce-elimination-sequence"></a>

The FST-L10 classifier route must eliminate cases in this order. The order is
part of the proof obligation: once a case matches, later cases must not receive
the same output.

1. `eps_cls_mldsa`: classify malformed or fresh `(m*, sigma*)` acceptance
   against the base ML-DSA verifier and reduce it to the closed ML-DSA
   unforgeability residual from FST-L1.
2. `eps_cls_threshold`: classify outputs whose individual ML-DSA checks pass
   but whose threshold authorization, signer set, or replay authorization is
   invalid; reduce to the threshold authorization and collection residuals
   closed across FST-L2 and FST-L6.
3. `eps_cls_vss_dkg`: classify invalid epoch-key or share-origin acceptance;
   charge only to the ideal `F_VSS_DKG` boundary unless a concrete VSS/DKG
   theorem has been selected and closed.
4. `eps_cls_commit`: classify outputs that require inconsistent commitment
   openings, statement binding failures, or opening-set mismatch; reduce to
   the commitment residual closed in the FST-L4 batch.
5. `eps_cls_contrib`: classify accepted outputs whose contribution statements
   or proofs are not justified by the selected contribution interface; charge
   only to the ideal `F_CONTRIB` boundary unless a production contribution
   backend theorem has been selected and closed.
6. `eps_cls_ro_transcript`: classify transcript-domain, random-oracle,
   challenge-binding, or serialization collisions that survive the earlier
   cases; reduce to the transcript and random-oracle residuals closed in
   FST-L2/FST-L3.
7. `eps_cls_collect`: classify accepted outputs that require noncanonical
   collection, active-set, quorum, duplicate-share, or ordering behavior;
   reduce to the canonical collection residual closed in FST-L6.
8. `eps_cls_evid`: classify outputs that require evidence suppression,
   evidence fabrication, or anti-framing failure after collection is fixed;
   reduce to the evidence residual closed in FST-L7.
9. `eps_cls_unmapped`: after steps 1 through 8 are mechanically total and
   disjoint, prove the production grammar leaves no accepting unauthorized
   output outside the ordered cases. This is the target theorem
   `eps_cls_unmapped = 0`, not an already-proven production claim.

Only after the ordered FST-L10 totality/disjointness proof and every per-case
residual above closes may `eps_classify` be replaced by the sum of named
reductions with no unmapped addend.

## Case Closure Table
<a id="uoce-case-closure-table"></a>

| Case | Residual or reduction target | Closure status required before final theorem |
| --- | --- | --- |
| `eps_cls_mldsa` | Base ML-DSA EUF-CMA or strong-unforgeability residual. | FST-L1 theorem closure batch must supply the exact ML-DSA reduction and parameter loss consumed by FST-L10. |
| `eps_cls_threshold` | Threshold authorization, signer-set validity, replay authorization, and collection soundness residuals. | FST-L2/FST-L6 closure must show the accepted output cannot pass threshold checks unless charged to those residuals. |
| `eps_cls_vss_dkg` | Epoch-key/share-origin residual at the concrete VSS/DKG theorem, or the ideal `F_VSS_DKG` boundary. | If the route remains idealized, FST-L10 must state the ideal-boundary assumption explicitly; it must not claim production VSS/DKG security. |
| `eps_cls_commit` | Commitment binding, opening-set equality, and statement-consistency residuals. | FST-L4 closure must bind every accepted contribution and release statement to one canonical committed value set. |
| `eps_cls_contrib` | Contribution statement/proof soundness residual at the selected backend, or the ideal `F_CONTRIB` boundary. | If the route remains idealized, FST-L10 must state the ideal-boundary assumption explicitly; it must not claim a production contribution backend theorem. |
| `eps_cls_ro_transcript` | Random-oracle domain separation, challenge binding, transcript injectivity, and canonical serialization residuals. | FST-L2/FST-L3 closure must make every surviving transcript failure chargeable before collection or evidence cases are considered. |
| `eps_cls_collect` | Canonical collection, active-set validation, quorum accounting, duplicate rejection, and deterministic ordering residuals. | FST-L6 closure must prove collection behavior is deterministic for the production verifier grammar. |
| `eps_cls_evid` | Evidence noninterference, evidence availability, and anti-framing residuals. | FST-L7 closure must show evidence handling cannot authorize an otherwise unauthorized output and cannot frame an honest participant. |
| `eps_cls_unmapped` | Target theorem that no accepting unauthorized production output remains outside the ordered classifier cases. | Requires fixed production grammar plus FST-L10 totality/disjointness and all preceding per-case closures; until then this addend remains open. |

## Acceptance Criteria
<a id="uoce-acceptance-criteria"></a>

Before `eps_classify` can be removed:

- The classifier input tuple is exactly the production verifier grammar.
- Every case has a reduction target and no case silently absorbs another open
  proof term.
- The ordered sequence above is proved total and disjoint under FST-L10
  first-match semantics.
- The FST-L1 through FST-L7 theorem closure batches are cited at the exact
  residuals they close, with no unstated upgrade from ideal functionality to
  production backend security.
- The `F_CONTRIB` and `F_VSS_DKG` ideal-functionality boundaries remain visible
  unless concrete production backend theorems replace them.
- The authorized-release replay case is byte-level deterministic.
- Collection, contribution, transcript, and evidence failures are ordered so
  one output is charged once.
- The theorem explicitly proves `eps_cls_unmapped = 0` after the prerequisites
  above; this document does not assert that equality by itself.

## Non-Claims
<a id="uoce-non-claims"></a>

This plan does not claim the classifier is total today. It does not claim
`eps_classify` is bounded or removable before backend, commitment,
random-oracle, rejection-sampling, collection, and evidence terms are closed.
It does not claim production VSS/DKG security, a production contribution
backend, or final unforgeability by this document alone. Implementation tests,
audits, traces, and integration evidence may support the grammar review, but
they are not cryptographic proof and cannot close a residual without the
corresponding theorem.

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
