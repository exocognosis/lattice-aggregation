# FST-L4 Partial-Share Validity Worksheet
<a id="fst-l4-partial-share-validity"></a>

Date: 2026-05-28

Status: theorem-closure worksheet for `FST-L4` under ideal `F_CONTRIB`,
not a completed production partial-share validity proof.

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

This document closes only the ideal-functionality route where contribution
acceptance is delegated to ideal `F_CONTRIB`/`F_contrib` under the fixed
transcript and collection assumptions used by the FST simulator. It does not
prove the selected production backend is sound, extractable, witness hiding,
zero knowledge, MPC private, or production ready. It does not close the
production residual `eps_contrib`, `eps_vss_ideal`, or `eps_ro_prior`.

## FSTL4-1. Theorem Context
<a id="fstl4-theorem-context"></a>

`FST-L4` is the signing-side lemma that lets the simulator replace accepted
partial-share frames with relation-valid contribution objects. In the
ideal-contribution route this replacement is discharged by ideal `F_CONTRIB`;
in the production route it remains conditional on a future backend theorem. In
the simulator worksheet, this is the S4 to S5 contribution replacement step:

```text
Delta_45 <= eps_contrib(A,Z) + eps_vss_ideal(A,Z) + eps_ro_prior(A,Z)
```

The lemma depends on `FST-A3`, `FST-A4`, and `FST-A6`, plus the ideal setup
outputs of `F_VSS_DKG` for the immediate IdealVSS theorem route. The closure
claim in this worksheet is conditional on a fixed transcript grammar, fixed
collection policy, and ideal `F_CONTRIB` behavior; it is not a production
contribution-backend claim.

## FSTL4-2. Accepted Contribution Objects
<a id="fstl4-accepted-contribution-objects"></a>

Accepted contribution objects include `ContributionStatement_i`,
`ProductionContributionStatement`, backend proof or verification artifact,
partial-share encoding, commitment digests, and any public contribution
metadata consumed by aggregation, evidence, release, or classifier logic.

The current `TranscriptHashScaffold` and `ProductionProofRelation` boundaries
are engineering scaffolds. They document where a production backend must attach
but are not production eligible as sound contribution proofs.

Definitions used below:

- `ContributionStatement_i` is the canonical per-validator public statement
  encoded into the accepted transcript for validator index `i`.
- `ProductionContributionStatement` is the production-shaped statement record
  whose fields must match `ContributionStatement_i`; this worksheet treats it
  as syntax, not as proof of production backend security.
- `S_contrib` is the public statement tuple submitted to the contribution
  verifier, including the signing context, challenge digest, validator index,
  epoch key, DKG digest, active-set digest, backend declaration, relation
  identifier, schema identifier, commitments, and encoded contribution.
- `W_contrib` is the witness or backend-native private state that would make
  the contribution relation true.
- `R_contrib(S_contrib, W_contrib)` is the contribution validity relation: it
  holds only when the witness is consistent with the DKG output, active set,
  challenge, commitments, partial-share equations, encoding, and leakage
  boundary declared by `S_contrib`.
- `H_contrib` is the contribution-domain random oracle used to derive typed
  contribution challenges, statement hashes, and transcript bindings.
- `TranscriptHashScaffold` is the current transcript-hash engineering
  placeholder for binding fields. It can preserve typed transcript context but
  is not a soundness, extraction, hiding, ZK, or MPC proof.
- `F_CONTRIB`/`F_contrib` is the ideal contribution functionality. On input
  `(S_contrib, W_contrib)` it either returns an accepting contribution handle
  only for relation-valid statements under the declared schema and backend, or
  returns reject with a named bad event/residual when the caller attempts to
  cross contexts, alter fields, use stale setup, submit malformed encodings, or
  rely on extraction/simulation outside the ideal interface.

## FSTL4-3. Lemma Statement
<a id="fstl4-lemma-statement"></a>

Target theorem under ideal contribution functionality:

```text
FST-L4:
  Under FST-A3, FST-A4, FST-A6, fixed transcript grammar, fixed collection
  policy, the ideal F_CONTRIB/F_contrib interface, and the accepted production
  transcript grammar, every contribution accepted for aggregation is
  attributable to exactly one validator in the accepted active set and is bound
  to exactly one SigningContext, ChallengeRecord, validator_index, epoch key,
  dkg_digest, active-set digest, ContributionStatement_i, public key,
  commitment transcript, contribution relation/schema, and backend
  declaration, except when a named bad event or residual fires.
```

Idealized variant:

```text
FST-L4-IdealVSS:
  In the FST-T1-IdealVSS route, share-metadata consistency and DKG binding may
  be discharged only through the ideal F_VSS_DKG outputs. This carries
  eps_vss_ideal and does not instantiate concrete production VSS/DKG.
```

The accepted object must be bound to one `validator_index`, `SigningContext`,
`ChallengeRecord`, epoch key, DKG digest, active set, public key, mask
commitment, secret commitment, contribution encoding, backend identifier,
relation identifier, and statement schema.

Production replacement theorem placeholder:

```text
Theorem CBI-production-contribution:
  If a concrete production backend later realizes F_CONTRIB for the declared
  ProductionContributionStatement grammar, then the ideal term
  eps_contrib_ideal may be replaced by production residuals eps_contrib_sound,
  eps_contrib_extract, eps_contrib_hide, eps_contrib_context,
  eps_contrib_encoding, and eps_contrib_leakage.
```

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
  epoch_key_digest,
  ChallengeRecord digest,
  dkg_digest,
  active_set_digest,
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
Under ideal `F_CONTRIB`, rejection is part of the ideal interface; under a
future production backend, every accepting path must prove the same checks or
charge a named production residual.

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

For the ideal route, `F_CONTRIB` is the selected backend. Its acceptance bit is
defined to be `1` only when `R_contrib(S_contrib, W_contrib) = 1` and the
statement fields match the fixed transcript and collection policy.

## FSTL4-5. Residual Terms
<a id="fstl4-residual-terms"></a>

For ideal `F_CONTRIB`, the contribution replacement term is:

```text
eps_contrib_ideal
  <= eps_contrib_context
   + eps_contrib_encoding
   + eps_contrib_leakage
```

The ideal functionality makes `eps_contrib_sound`, `eps_contrib_extract`, and
`eps_contrib_hide` zero only inside the idealized model and only for callers
that stay within the fixed statement grammar and ideal leakage interface. This
is not evidence for a concrete backend.

Before a production lemma can close, the selected backend must provide:

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

The simulator interaction is the `SHR-L5` contribution replacement route. In
the ideal route, an accepted corrupted contribution is already a relation-valid
object by `F_CONTRIB` acceptance. In a production replacement route, an
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

### Proof Cases
<a id="fstl4-proof-cases"></a>

The closure argument partitions every attempted accepting contribution as
follows:

- Wrong context: if `SigningContext` differs from the statement context, the
  contribution is rejected by `F_CONTRIB` or charged to
  `BadContribPortable`/`eps_contrib_context`.
- Wrong challenge: if the `ChallengeRecord` digest or `H_contrib` domain
  differs, the statement is not the accepted `S_contrib`; acceptance is charged
  to `BadContribPortable`, `BadHcontribPrior`, or `eps_ro_prior`.
- Wrong validator or share id: if `validator_index` does not identify the
  unique active-set contributor or the share metadata is inconsistent, the case
  is discharged by `FST-L3` and ideal `F_VSS_DKG`, or charged to
  `eps_vss_ideal`.
- Stale DKG digest: if the epoch key, DKG digest, or active-set digest differs
  from the fixed collection state, ideal `F_CONTRIB` rejects; production
  acceptance is charged to `eps_contrib_context` or `BadContribPortable`.
- Wrong backend, schema, or relation: if `backend_id`, `relation_id`, or
  `statement_schema_id` differs from the declared statement, the encoding is
  rejected or charged to `eps_contrib_encoding`.
- Malformed contribution: if fixed-width fields, commitment digests, threshold
  parameters, contribution encoding, or canonical serialization are malformed,
  the contribution is rejected or charged to `eps_contrib_encoding`.
- Extraction or simulation failure under production replacement: if a concrete
  backend replaces `F_CONTRIB` and an accepted corrupted contribution cannot be
  extracted/replaced, charge `BadContribExtract` and
  `eps_contrib_extract`; if honest artifacts cannot be simulated, charge
  `BadContribHide` and `eps_contrib_hide`; if an invalid statement verifies,
  charge `BadContribSound` and `eps_contrib_sound`.
- Classifier mapping: if an unauthorized accepting aggregate depends on the
  contribution attempt and is not rejected earlier, the classifier must assign
  it to `eps_cls_contrib`; the theorem keeps `eps_cls_unmapped = 0` as an
  explicit accounting obligation.

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
3. Invoke ideal `F_CONTRIB` on `(S_contrib, W_contrib)` for theorem closure, or
   invoke the future selected backend theorem on `(S_contrib, pi_contrib)` for
   a production replacement argument.
4. In the ideal route, use `F_CONTRIB` acceptance as the relation-valid object.
   In the production route, extract or replace the accepted contribution with a
   relation-valid object.
5. Charge backend soundness, extraction, hiding, context, encoding, leakage,
   ideal VSS, random-oracle, and classifier failures to the named residuals.

## FSTL4-8. Dependencies
<a id="fstl4-dependencies"></a>

`FST-L4` depends on:

- `FST-L1` transcript injectivity;
- `FST-L2` challenge binding;
- `FST-L3` validator-set and active-set soundness;
- contribution backend selection and instantiation;
- ideal `F_CONTRIB`/`F_contrib` for this worksheet's closure path;
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

This worksheet satisfies only the explicitly idealized case: ideal
`F_CONTRIB` provides the contribution acceptance predicate under fixed
transcript and collection assumptions. Treating `FST-L4` as a production proof
still requires `Theorem CBI-production-contribution` or an equivalent concrete
backend theorem.

## FSTL4-10. Non-Claims
<a id="fstl4-non-claims"></a>

This worksheet does not claim production partial-share validity is proved. It
does not prove production DKG/VSS security, contribution backend soundness,
witness hiding, extraction, algebraic ML-DSA partial correctness,
rejection-sampling correctness, zero knowledge, MPC privacy, a production
backend, or no-subthreshold signing. It does not close `eps_contrib`,
`eps_vss`, `eps_vss_ideal`, `eps_classify`, or `eps_cls_unmapped = 0` outside
the ideal `F_CONTRIB` theorem route. Implementation evidence is not
cryptographic proof.

## FSTL4-11. Manifest Anchors
<a id="fstl4-manifest-anchors"></a>

- `# FST-L4 Partial-Share Validity Worksheet`
- `fst-l4-partial-share-validity`
- `FSTL4-0. Scope and Non-Claim`
- `FSTL4-1. Theorem Context`
- `Status: theorem-closure worksheet for FST-L4 under ideal F_CONTRIB, not a completed production partial-share validity proof.`
- `FSTL4-2. Accepted Contribution Objects`
- `FSTL4-3. Lemma Statement`
- `FSTL4-4. Proof Obligations`
- `FSTL4-5. Residual Terms`
- `FSTL4-6. Simulator and Classifier Interaction`
- `FSTL4-7. Implementation Crosswalk`
- `FSTL4-8. Dependencies`
- `FSTL4-9. Acceptance Criteria`
- `FSTL4-10. Non-Claims`
- `FSTL4-11. Manifest Anchors`
- `FST-L4`
- `FST-L4-IdealVSS`
- `FST-A3`
- `FST-A4`
- `FST-A6`
- `ContributionStatement_i`
- `ProductionContributionStatement`
- `ProductionProofRelation`
- `TranscriptHashScaffold`
- `F_CONTRIB`
- `F_contrib`
- `not production eligible`
- `SigningContext`
- `ChallengeRecord`
- `S_contrib`
- `W_contrib`
- `R_contrib`
- `H_contrib`
- `Theorem CBI-production-contribution`
- `eps_contrib_ideal`
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
