# FST-L4 Partial-Share Validity Worksheet
<a id="fst-l4-partial-share-validity"></a>

Date: 2026-05-28

Status: proof worksheet for `FST-L4`, not a completed partial-share validity proof.

## FSTL4-0. Scope and Non-Claim
<a id="fstl4-scope-non-claim"></a>

This worksheet expands the `FST-L4` partial-share validity lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It links the
production transcript statement `ContributionStatement_i` to the contribution
backend route in
[contribution-soundness-relation.md](contribution-soundness-relation.md),
[contribution-backend-selection.md](contribution-backend-selection.md), and
[contribution-backend-instantiation.md](contribution-backend-instantiation.md).

This document does not prove the selected backend is sound, extractable,
witness hiding, zero knowledge, MPC private, or production ready. It does not
close `eps_contrib`, `eps_vss_ideal`, or `eps_ro_prior`.

## FSTL4-1. Theorem Context
<a id="fstl4-theorem-context"></a>

`FST-L4` is the signing-side lemma that lets the simulator replace accepted
partial-share frames with relation-valid contribution objects. In the
simulator worksheet, this is the S4 to S5 contribution replacement step:

```text
Delta_45 <= eps_contrib(A,Z) + eps_vss_ideal(A,Z) + eps_ro_prior(A,Z)
```

The lemma depends on `FST-A3`, `FST-A4`, and `FST-A6`, plus the ideal setup
outputs of `F_VSS_DKG` for the immediate IdealVSS theorem route.

## FSTL4-2. Accepted Contribution Objects
<a id="fstl4-accepted-contribution-objects"></a>

Accepted contribution objects include `ContributionStatement_i`,
`ProductionContributionStatement`, backend proof or verification artifact,
partial-share encoding, commitment digests, and any public contribution
metadata consumed by aggregation, evidence, release, or classifier logic.

The current `TranscriptHashScaffold` and `ProductionProofRelation` boundaries
are engineering scaffolds. They document where a production backend must attach
but are not production eligible as sound contribution proofs.

## FSTL4-3. Lemma Statement
<a id="fstl4-lemma-statement"></a>

Target lemma:

```text
FST-L4:
  Under FST-A3, FST-A4, FST-A6, the production contribution backend theorem,
  and the accepted production transcript grammar, every partial share accepted
  for aggregation is attributable to exactly one validator in the accepted
  active set and is bound to exactly one SigningContext, ChallengeRecord,
  ContributionStatement_i, public key, dkg_digest, commitment transcript,
  backend_id, relation_id, and statement_schema_id, except through explicitly
  named residual events.
```

Idealized variant:

```text
FST-L4-IdealVSS:
  In the FST-T1-IdealVSS route, share-metadata consistency and DKG binding may
  be discharged only through the ideal F_VSS_DKG outputs. This carries
  eps_vss_ideal and does not instantiate concrete production VSS/DKG.
```

The accepted object must be bound to one `validator_index`, `SigningContext`,
`ChallengeRecord`, DKG digest, public key, mask commitment, secret commitment,
contribution encoding, backend identifier, relation identifier, and statement
schema.

## FSTL4-4. Proof Obligations
<a id="fstl4-proof-obligations"></a>

### Public Statement Boundary
<a id="fstl4-public-statement-boundary"></a>

The production public statement is the canonical contribution statement:

```text
ContributionStatement_i = Enc(
  label,
  version,
  SigningContext,
  validator_index,
  ChallengeRecord digest,
  dkg_digest,
  public_key_digest,
  masking_commitment_digest,
  secret_commitment_digest,
  contribution_commitment_digest,
  backend_id,
  relation_id,
  statement_schema
)
```

The verifier must reject unsupported schemas, malformed fixed-width fields,
invalid threshold parameters, unknown validators, mismatched DKG digests,
mismatched challenge digests, stale attempts, and non-canonical encodings.

### Witness Relation Target
<a id="fstl4-witness-relation-target"></a>

The target relation is `R_contrib(S_contrib, W_contrib) = 1`. Depending on the
selected backend, the witness or backend-native verified object must establish:

- the signer owns a share consistent with `F_VSS_DKG` or the selected concrete
  DKG/VSS relation;
- masking and secret commitment witnesses open to the committed public values;
- the challenge and contribution encoding satisfy the threshold ML-DSA-65
  partial-contribution equations;
- attempt-local masking is fresh and bound to the signing context;
- the contribution encoding is exactly the value committed by
  `contribution_commitment_digest`;
- secret-dependent values such as `c*s1`, `c*s2`, `c*t0`, masks, and private
  shares are not leaked outside the selected leakage function.

## FSTL4-5. Residual Terms
<a id="fstl4-residual-terms"></a>

Before the lemma can close, the selected backend must provide:

```text
eps_contrib
  <= eps_contrib_sound
   + eps_contrib_extract
   + eps_contrib_hide
   + eps_contrib_context
   + eps_contrib_encoding
   + eps_contrib_leakage
```

The backend may be a NIZK proof, MPC verification protocol, interactive proof,
or ideal contribution functionality. A transcript-hash scaffold is not a
production contribution backend and cannot close `eps_contrib`.

Cross-term dependencies remain visible:

```text
eps_vss_ideal
eps_ro_prior
eps_ro_sep
eps_commit
eps_collect
eps_cls_contrib
eps_cls_unmapped = 0
```

None of these terms is proved negligible, zero, or bounded by this worksheet.

## FSTL4-6. Simulator and Classifier Interaction
<a id="fstl4-simulator-classifier-interaction"></a>

The simulator interaction is the `SHR-L5` contribution replacement route. An
accepted corrupted contribution must be extractable or replaceable by a
relation-valid object, while honest contribution frames must be simulatable
under the selected hiding theorem.

Classifier interaction is through `eps_cls_contrib`: if an unauthorized
accepting aggregate depends on a malformed or invalid contribution, the
classifier must map that output to the contribution case or leave
`eps_cls_unmapped = 0` open.

### Bad Events and Accounting
<a id="fstl4-bad-events-accounting"></a>

The worksheet tracks:

- `BadContribHide`: simulated honest proof artifacts are distinguishable.
- `BadContribSound`: an invalid partial verifies under the production relation.
- `BadContribExtract`: an accepted corrupted contribution cannot be extracted
  or replaced by the required relation-valid object.
- `BadContribPortable`: a proof or partial generated for one typed context
  verifies in another context.
- `FailContribExtract`: the extractor fails on an accepted contribution.
- `FailContribPortable`: the context-portability check cannot assign the
  failure to a backend or transcript term.
- `BadHcontribPrior`: a prior `H_contrib` query prevents required random-oracle
  programming.
- `BadVssIdealLeak`: the IdealVSS route assumes leakage beyond `F_VSS_DKG`.

Each accepting invalid contribution must be charged exactly once to
`eps_contrib`, `eps_vss_ideal`, `eps_ro_prior`, or a later classifier case.

## FSTL4-7. Implementation Crosswalk
<a id="fstl4-implementation-crosswalk"></a>

Implementation evidence includes `src/crypto/contribution_proof.rs`,
`src/adapter/actor.rs`, `src/collections.rs`, `src/types.rs`,
`tests/contribution_proof.rs`, `tests/production_policy.rs`,
`tests/hazmat_mldsa65_wire.rs`, and `tests/validation.rs`.

This implementation evidence is not cryptographic proof.

### Proof Skeleton
<a id="fstl4-proof-skeleton"></a>

The intended proof is:

1. Use `FST-L1` and `FST-L2` to bind `ContributionStatement_i` to one typed
   challenge and signing context.
2. Use `FST-L3` to prove the signer is a unique in-set active contributor.
3. Invoke the selected backend theorem on `(S_contrib, pi_contrib)`.
4. Extract or replace the accepted contribution with a relation-valid object.
5. Charge backend soundness, extraction, hiding, context, encoding, leakage,
   ideal VSS, and random-oracle failures to the named residuals.

## FSTL4-8. Dependencies
<a id="fstl4-dependencies"></a>

`FST-L4` depends on:

- `FST-L1` transcript injectivity;
- `FST-L2` challenge binding;
- `FST-L3` validator-set and active-set soundness;
- contribution backend selection and instantiation;
- ideal setup leakage from `F_VSS_DKG` for the immediate theorem path;
- random-oracle programming for `H_contrib`.
- `Theorem CBI-production-contribution`;
- `csr-production-statement`, `csr-soundness-game`,
  `csr-extraction-target`, and `csr-witness-hiding-target`;
- active-set and `PartialShareSet` uniqueness from `FST-L3`.

## FSTL4-9. Acceptance Criteria
<a id="fstl4-acceptance-criteria"></a>

Before `FST-L4` can be treated as proved:

- the production contribution backend is selected or explicitly idealized;
- the public statement fields are fixed and injectively encoded;
- the backend theorem states soundness, extraction or replacement, hiding,
  leakage, and context binding;
- every backend residual is included in `eps_contrib`;
- `eps_vss_ideal` is limited to the exact `F_VSS_DKG` interface;
- current scaffold transcript-hash payloads are not cited as production proof.

## FSTL4-10. Non-Claims
<a id="fstl4-non-claims"></a>

This worksheet does not claim partial-share validity is proved. It does not
prove production DKG/VSS security, contribution backend soundness, witness
hiding, extraction, algebraic ML-DSA partial correctness, rejection-sampling
correctness, or no-subthreshold signing. It does not close `eps_vss`,
`eps_vss_ideal`, `eps_classify`, or `eps_cls_unmapped = 0`.

## FSTL4-11. Manifest Anchors
<a id="fstl4-manifest-anchors"></a>

- `# FST-L4 Partial-Share Validity Worksheet`
- `fst-l4-partial-share-validity`
- `FSTL4-0. Scope and Non-Claim`
- `FSTL4-1. Theorem Context`
- `Status: proof worksheet for FST-L4, not a completed partial-share validity proof.`
- `FSTL4-2. Accepted Contribution Objects`
- `FSTL4-3. Lemma Statement`
- `FSTL4-4. Proof Obligations`
- `FSTL4-5. Residual Terms`
- `FSTL4-6. Simulator and Classifier Interaction`
- `FSTL4-7. Implementation Crosswalk`
- `FSTL4-8. Dependencies`
- `FSTL4-9. Acceptance Criteria`
- `FSTL4-10. Non-Claims`
- `FST-L4`
- `FST-L4-IdealVSS`
- `FST-A3`
- `FST-A4`
- `FST-A6`
- `ContributionStatement_i`
- `ProductionContributionStatement`
- `ProductionProofRelation`
- `TranscriptHashScaffold`
- `not production eligible`
- `SigningContext`
- `ChallengeRecord`
- `S_contrib`
- `W_contrib`
- `R_contrib`
- `H_contrib`
- `Theorem CBI-production-contribution`
- `eps_contrib`
- `eps_vss_ideal`
- `eps_ro_prior`
- `eps_cls_contrib`
- `eps_cls_unmapped = 0`
- `eps_contrib_sound`
- `eps_contrib_extract`
- `eps_contrib_hide`
- `eps_contrib_context`
- `eps_contrib_encoding`
- `eps_contrib_leakage`
- `BadContribSound`
- `BadContribExtract`
- `BadContribPortable`
- `FailContribExtract`
- `FailContribPortable`
- `BadHcontribPrior`
- `implementation evidence is not cryptographic proof`
- `not a completed proof`
