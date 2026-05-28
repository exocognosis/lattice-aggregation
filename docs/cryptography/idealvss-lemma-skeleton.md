# IdealVSS Lemma Skeleton
<a id="idealvss-lemma-skeleton"></a>

Date: 2026-05-28

Status: lemma skeleton for `FST-T1-IdealVSS`, not a completed proof.

## IVLS-0. Scope and Non-Claim
<a id="ivls-scope-non-claim"></a>

This document expands the IdealVSS signing theorem route into a lemma-by-lemma
proof skeleton. It depends on
[idealvss-signing-theorem-closure.md](idealvss-signing-theorem-closure.md) and
uses the grammar target in
[production-transcript-grammar.md](production-transcript-grammar.md).

It does not prove any lemma. It records the statement shape, proof inputs,
residual terms, and blockers that must be resolved before
`FST-T1-IdealVSS` can be claimed.

This skeleton does not instantiate concrete VSS/DKG or close `eps_vss`. It
treats implementation tests as review evidence, not cryptographic proof, and
assumes only the ideal setup outputs allowed by `F_VSS_DKG`: `pk_epoch`,
`dkg_digest`, `AcceptedDealers`, `share_i`, and allowed leakage.

## IVLS-1. Theorem Context: FST-T1-IdealVSS
<a id="ivls-theorem-context"></a>

`FST-T1-IdealVSS` may be closed only after:

- `FST-A0` fixes the ideal `F_VSS_DKG` setup interface.
- `FST-A1` supplies the base ML-DSA-65 unforgeability assumption.
- `FST-A4` through `FST-A8` are instantiated by the signing protocol.
- `FST-L1` through `FST-L7` are proved.
- `FST-L10` eliminates `eps_cls_unmapped`.
- `eps_contrib`, `eps_commit`, `eps_ro`, `eps_mask`, `eps_rej`,
  `eps_withhold`, and `eps_verify` are proved, bounded, or explicitly carried
  into a weaker theorem statement.

## IVLS-2. Lemma Dependency Table
<a id="ivls-lemma-dependency-table"></a>

| Lemma | Target statement | Required inputs | Residual term if open |
| --- | --- | --- | --- |
| `FST-L1` transcript injectivity | Two accepted transcript records encode the same proof object only if every typed field is identical. | [fst-l1-transcript-injectivity.md](fst-l1-transcript-injectivity.md), [production-transcript-grammar.md](production-transcript-grammar.md), [random-oracle-game.md](random-oracle-game.md). | `eps_ro_sep + eps_ro_injective_encoding` |
| `FST-L2` challenge binding | A partial contribution cannot be reused across a different session, message, key, active set, commitment set, or attempt. | [fst-l2-challenge-binding.md](fst-l2-challenge-binding.md), `FST-L1`, commitment records, `H_c` domain. | `eps_ro_prior + eps_ro_replay + eps_commit_context` |
| `FST-L3` validator-set soundness | Accepted commitment and contribution sets contain unique validators from the canonical epoch validator set and at least `t` contributors. | [fst-l3-collection-soundness.md](fst-l3-collection-soundness.md), collection validation rules, active-set grammar. | `eps_collect` |
| `FST-L4` partial-share validity | Every accepted contribution is attributable to one signer, share metadata, transcript, commitment, challenge, public key, and `dkg_digest`. | Contribution backend theorem, `ContributionStatement_i`. | `eps_contrib + eps_vss_ideal` |
| `FST-L5` aggregation correctness | Threshold-valid accepted contributions reconstruct values that produce a verifier-accepted ML-DSA-65 signature. | Recombination proof, rejection checks, standard verifier compatibility. | `eps_rej + eps_verify` |
| `FST-L6` no subthreshold signing | An adversary corrupting fewer than `t` validators cannot produce a new accepting aggregate output except through ML-DSA forgery or named threshold failure. | Ideal setup, contribution validity, classifier reductions. | `eps_classify + eps_threshold` |
| `FST-L7` abort compatibility | Retry, withholding, timeout, release, and evidence behavior do not bias accepted signatures beyond the stated bound. | Rejection-sampling closure, abort transcript, timeout policy. | `eps_mask + eps_rej + eps_withhold + eps_verify + eps_abort + eps_release + eps_evid` |
| `FST-L10` classifier closure | Every accepting unauthorized aggregate output is assigned to one reduction case and `eps_cls_unmapped = 0`. | Production grammar and classifier elimination plan. | `eps_classify` |

## IVLS-3. FST-L1 Canonical Transcript Injectivity
<a id="ivls-fst-l1-transcript-injectivity"></a>

Proof skeleton:

1. Cite the production grammar record labels and version fields.
2. Prove each field has a unique typed encoding.
3. Prove vectors and maps use canonical validator ordering.
4. Prove optional values are tagged and cannot be confused with omitted fields.
5. Conclude that identical transcript bytes imply identical transcript fields.

Open blocker: no byte-level injectivity proof is complete.

## IVLS-4. FST-L2 Challenge Binding
<a id="ivls-fst-l2-challenge-binding"></a>

Proof skeleton:

1. Use `FST-L1` to bind the `ChallengeRecord` fields.
2. Use commitment binding and opened-set equality to fix the commitment set
   before `H_c`.
3. Charge prior-query and replay failures to `eps_ro`.
4. Prove accepted partial contributions carry the same challenge digest.

Open blocker: `eps_ro` and `eps_commit` remain open.

## IVLS-5. FST-L3 Validator-Set Soundness
<a id="ivls-fst-l3-validator-set-soundness"></a>

Proof skeleton:

1. Define canonical `V`, active set, and contribution set encodings.
2. Prove duplicate, unknown, stale, and insufficient contributors are rejected.
3. Prove the same active set is used in commitments, challenge, contribution
   statements, aggregation, evidence, and classifier records.

Open blocker: production collection theorem is not written.

## IVLS-6. FST-L4 Partial-Share Validity
<a id="ivls-fst-l4-partial-share-validity"></a>

Proof skeleton:

1. Select the contribution backend or cite an ideal contribution functionality.
2. Prove every accepted `ContributionStatement_i` binds the signer, challenge,
   DKG digest, commitments, payload digest, relation ID, and parameter set.
3. Use backend soundness or extraction to map accepted corrupted contributions
   to valid relation witnesses or named backend failures.

Open blocker: no production contribution backend is selected.

## IVLS-7. FST-L5 Aggregation Correctness
<a id="ivls-fst-l5-aggregation-correctness"></a>

Proof skeleton:

1. Prove accepted shares reconstruct the intended ML-DSA secret-dependent
   response values under the IdealVSS setup outputs.
2. Prove aggregate rejection checks match centralized ML-DSA-65 checks.
3. Prove the final bytes are exactly accepted by unmodified
   `MLDSA65.Verify(pk_epoch, M, sigma)`.

Open blocker: `eps_rej` and `eps_verify` remain open.

## IVLS-8. FST-L6 No Subthreshold Signing
<a id="ivls-fst-l6-no-subthreshold-signing"></a>

Proof skeleton:

1. Condition on ideal setup with fewer than `t` corruptions.
2. Use contribution validity and collection soundness to show accepted outputs
   require at least `t` valid in-set contributions or a named failure.
3. Use the classifier to map unauthorized accepting outputs to base ML-DSA
   forgery or threshold-side assumption violation.

Open blocker: classifier elimination and contribution backend proofs remain
open.

## IVLS-9. FST-L7 Abort Compatibility
<a id="ivls-fst-l7-abort-compatibility"></a>

Proof skeleton:

1. Fix retry limit, timeout policy, exclusion semantics, and abort transcript.
2. Show retry attempts use fresh mask and challenge material.
3. Simulate visible abort, timeout, evidence, and release records.
4. Bound conditioning on accepted attempts without hiding `eps_mask` or
   `eps_rej` inside `eps_withhold`.

Open blocker: selective-abort and retry bounds remain open.

## IVLS-10. FST-L10 Unauthorized-Output Classifier Closure
<a id="ivls-fst-l10-classifier-closure"></a>

Proof skeleton:

1. Use the production grammar as the classifier input domain.
2. Prove ordered case totality and disjointness.
3. Attach a reduction algorithm and loss to every non-gap case.
4. Prove `eps_cls_unmapped = 0`.

Open blocker: production grammar and per-case reductions are not complete.

## IVLS-11. Cross-Lemma Epsilon Ledger
<a id="ivls-epsilon-ledger"></a>

The skeleton keeps these residuals visible:

```text
eps_commit, eps_ro, eps_mask, eps_rej, eps_withhold,
eps_contrib, eps_classify, eps_verify, eps_abort,
eps_release, eps_evid, eps_collect, eps_threshold.
```

No residual listed here is claimed negligible, zero, or numerically bounded by
this document.

## IVLS-12. Acceptance Criteria
<a id="ivls-acceptance-criteria"></a>

Before this skeleton can become proof text:

- Every lemma names a theorem statement, adversary model, runtime, and success
  probability.
- Every reduction states its oracle access and programmed queries.
- Every residual term is either proved, bounded, or carried visibly.
- The final theorem does not silently treat implementation tests as proof.

## IVLS-13. Manifest Anchors
<a id="ivls-manifest-anchors"></a>

- `# IdealVSS Lemma Skeleton`
- `idealvss-lemma-skeleton`
- `IVLS-0. Scope and Non-Claim`
- `IVLS-1. Theorem Context: FST-T1-IdealVSS`
- `IVLS-2. Lemma Dependency Table`
- `IVLS-3. FST-L1 Canonical Transcript Injectivity`
- `IVLS-4. FST-L2 Challenge Binding`
- `IVLS-5. FST-L3 Validator-Set Soundness`
- `IVLS-6. FST-L4 Partial-Share Validity`
- `IVLS-7. FST-L5 Aggregation Correctness`
- `IVLS-8. FST-L6 No Subthreshold Signing`
- `IVLS-9. FST-L7 Abort Compatibility`
- `IVLS-10. FST-L10 Unauthorized-Output Classifier Closure`
- `IVLS-11. Cross-Lemma Epsilon Ledger`
- `IVLS-12. Acceptance Criteria`
- `IVLS-13. Manifest Anchors`
- `FST-L1`
- `FST-L2`
- `FST-L3`
- `FST-L4`
- `FST-L5`
- `FST-L6`
- `FST-L7`
- `FST-L10`
- `eps_cls_unmapped = 0`
- `ivls-fst-l1-transcript-injectivity`
- `ivls-fst-l4-partial-share-validity`
- `ivls-fst-l7-abort-compatibility`
- `ivls-epsilon-ledger`
- `ivls-acceptance-criteria`
