# Production Transcript Grammar for Threshold ML-DSA-65
<a id="production-transcript-grammar"></a>

Date: 2026-05-28

Status: grammar target for proof closure, not a production protocol
specification or security proof.

## PTG-0. Scope and Non-Claim
<a id="ptg-scope-non-claim"></a>

This document fixes the byte-level grammar that the future production proof
must use when referring to threshold ML-DSA-65 transcripts. It refines
[formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md)
into named canonical records that can be cited by the random-oracle proof,
contribution backend, rejection-sampling proof, evidence model, and
unauthorized-output classifier.

This is not a completed transcript injectivity proof. It does not prove
challenge unbiasability, contribution soundness, rejection-sampling
equivalence, evidence soundness, or production deployment readiness.

## PTG-1. Input Tuple
<a id="ptg-input-tuple"></a>

The classifier and verifier-facing proof grammar is built around the tuple:

```text
(
  m*,
  sigma*,
  pk_epoch,
  epoch_id,
  session_id,
  attempt,
  validator_set_digest,
  active_set,
  threshold,
  contribution_frames,
  contribution_statements,
  contribution_proofs,
  VSS_DKG_references,
  commitment_records,
  random_oracle_queries,
  collection_metadata,
  evidence_records,
  authorized_release_log
)
```

This tuple is a proof input. It is not passed to unmodified ML-DSA-65
verification, which sees only `(pk_epoch, M, sigma)`.

## PTG-2. Canonical Encoding
<a id="ptg-canonical-encoding"></a>
<a id="ptg-encoding-rules"></a>

All production transcript records use one canonical encoding function:

```text
Enc(label, version, field_1, ..., field_n)
```

Required rules:

- `label` is a domain-separated ASCII protocol label.
- `version` is a fixed-width protocol version.
- Integers are unsigned big-endian with a declared width.
- Byte strings are length-prefixed.
- Vectors and maps include a count and are sorted by canonical validator index
  unless the record explicitly states another order.
- Optional fields are encoded as tagged variants, never by omission.
- Every record includes enough context to prevent cross-epoch, cross-session,
  cross-attempt, cross-message, and cross-parameter replay.

## PTG-3. Signing Attempt Grammar
<a id="ptg-signing-attempt-grammar"></a>
<a id="ptg-context-records"></a>

The root context for signing is:

```text
SigningContext = Enc(
  "lattice-aggregation/threshold-mldsa65/context",
  version,
  parameter_set_id,
  epoch_id,
  sid,
  block_height,
  attempt,
  threshold,
  validator_set_digest,
  pk_epoch,
  dkg_digest,
  message_binding
)
```

`message_binding` is either raw message bytes `M`, an ML-DSA-compatible
message representative `mu`, or a tagged pair `(M, mu)` depending on the final
standard-verifier compatibility proof. The production theorem must choose one
form and keep it consistent across signing, aggregation, evidence, and
verification.

Each signing attempt grammar includes `SigningContext`, `MaskCommitRecord_i`,
`MaskOpenStatement_i`, canonical `Wset`, `w1`, `ChallengeRecord`,
`SecretCommitRecord_i`, `ContributionStatement_i`, retry freshness, and no
arrival-order dependence.

## PTG-4. Commitment Records
<a id="ptg-commitment-records"></a>

Masking commitment record:

```text
MaskCommitRecord_i = Enc(
  "lattice-aggregation/threshold-mldsa65/mask-commit",
  version,
  SigningContext,
  validator_index_i,
  mask_commitment_digest_i
)
```

Mask opening statement:

```text
MaskOpenStatement_i = Enc(
  "lattice-aggregation/threshold-mldsa65/mask-open",
  version,
  SigningContext,
  validator_index_i,
  public_mask_statement_i,
  mask_aux_digest_i
)
```

Secret contribution precommitment:

```text
SecretCommitRecord_i = Enc(
  "lattice-aggregation/threshold-mldsa65/secret-commit",
  version,
  SigningContext,
  validator_index_i,
  challenge_digest,
  secret_commitment_digest_i
)
```

The production proof must show that accepted openings bind to the exact
commitment records included in the challenge transcript.

## PTG-5. Challenge Record
<a id="ptg-challenge-record"></a>

The threshold challenge input is:

```text
ChallengeRecord = Enc(
  "lattice-aggregation/threshold-mldsa65/challenge",
  version,
  SigningContext,
  OrderedMaskCommitSet,
  OrderedMaskOpenSet,
  aggregate_public_w1_or_digest
)
```

`OrderedMaskCommitSet` and `OrderedMaskOpenSet` are canonical validator-index
maps. If a production path keeps `w_i` hidden and proves only a digest, the
digest relation must be defined in the contribution backend and commitment
proof. If a standard-verifying path requires FIPS 204 `mu` and `w1`, the proof
must reconcile this record with unmodified ML-DSA-65 challenge derivation.

## PTG-6. Contribution Frame Grammar
<a id="ptg-contribution-frame-grammar"></a>
<a id="ptg-contribution-statement-record"></a>

The production contribution statement is:

```text
ContributionStatement_i = Enc(
  "lattice-aggregation/threshold-mldsa65/contribution-statement",
  version,
  SigningContext,
  validator_index_i,
  challenge_digest,
  pk_epoch,
  dkg_digest,
  mask_commitment_digest_i,
  secret_commitment_digest_i,
  contribution_encoding_digest_i,
  backend_id,
  relation_id,
  statement_schema_id
)
```

This record is the public statement that any production contribution backend
must verify. The current transcript-hash scaffold can bind a payload digest to
this shape for tests, but it does not prove soundness, hiding, extraction, or
production relation validity.

## PTG-7. Collection and Release Grammar
<a id="ptg-collection-release-grammar"></a>
<a id="ptg-aggregate-output-record"></a>

The aggregate output record used by the proof and classifier is:

```text
AggregateOutputRecord = Enc(
  "lattice-aggregation/threshold-mldsa65/aggregate-output",
  version,
  SigningContext,
  active_set,
  OrderedMaskCommitSet,
  OrderedContributionStatementSet,
  sigma,
  verification_result
)
```

`sigma` must be exactly the standard ML-DSA-65 signature bytes submitted to
`MLDSA65.Verify(pk_epoch, M, sigma)`. Threshold metadata is not part of the
standard verifier input; it is proof, audit, and evidence context.

Authorized release logs are deterministic records of signatures released by
the ideal functionality or accepted production signing path. They must be
byte-level comparable so replayed authorized outputs are distinguished from
new unauthorized outputs.

## PTG-8. Evidence and Abort Grammar
<a id="ptg-evidence-abort-grammar"></a>
<a id="ptg-evidence-abort-records"></a>

Abort transcript:

```text
AbortRecord = Enc(
  "lattice-aggregation/threshold-mldsa65/abort",
  version,
  SigningContext,
  abort_kind,
  observed_round,
  observed_validator_index_or_none,
  public_evidence_digest_or_none
)
```

Evidence record:

```text
EvidenceRecord = Enc(
  "lattice-aggregation/threshold-mldsa65/evidence",
  version,
  SigningContext,
  accused_validator_index,
  evidence_kind,
  offending_frame_digest,
  verifier_context_digest,
  public_error_code
)
```

Evidence must not include honest secret shares, masks, proof witnesses, or
rejection internals unless a later evidence noninterference theorem explicitly
allows that leakage.

## PTG-9. Random-Oracle Domains
<a id="ptg-random-oracle-domains"></a>
<a id="ptg-random-oracle-mapping"></a>

The grammar maps to random-oracle domains as follows:

| Oracle | Grammar input |
| --- | --- |
| `H_mu` | `SigningContext.message_binding`, once the production message-binding form is selected. |
| `H_w` | `MaskCommitRecord_i` and `MaskOpenStatement_i`. |
| `H_c` | `ChallengeRecord`. |
| `H_vss` | `dkg_digest` and production VSS/DKG setup statements. |
| `H_contrib` | `ContributionStatement_i` and backend proof transcript. |

The proof must show these encodings are injective and domain separated before
`eps_ro` can be closed.

## PTG-10. Classifier Interface
<a id="ptg-classifier-interface"></a>
<a id="ptg-classifier-compatibility"></a>

The unauthorized-output classifier should consume `AggregateOutputRecord`,
`EvidenceRecord`, accepted contribution statements, random-oracle query logs,
and the authorized release log. The classifier cannot prove
`eps_cls_unmapped = 0` until this grammar is fixed and every accepted field is
either required, defaulted, or rejected as malformed.

## PTG-11. Totality and Disjointness Obligations
<a id="ptg-totality-disjointness-obligations"></a>

The classifier must use deterministic ordered first-match semantics. Every
accepting unauthorized output must map to a named case or `Unmapped`, and the
proof must then show `eps_cls_unmapped = 0` before removing `eps_classify`.

## PTG-12. Acceptance Criteria
<a id="ptg-acceptance-criteria"></a>

Before this grammar can support proof closure:

- Every record has a canonical encoding and a manifest-pinned anchor.
- Optional fields are tagged and cannot create ambiguous accepted transcripts.
- Authorized release replay is byte-level deterministic.
- Classifier cases are charged once under the ordered grammar.

## PTG-13. Open Proof Obligations
<a id="ptg-open-proof-obligations"></a>

- Prove byte-level injectivity for every record.
- Prove record labels are domain separated and version stable.
- Prove no optional field can create ambiguous accepted transcripts.
- Prove standard-verifier compatibility for the selected `message_binding`.
- Prove evidence and abort records do not leak more than the allowed leakage
  functions.
- Prove the classifier grammar is total over accepting unauthorized outputs.

## PTG-14. Non-Claims
<a id="ptg-non-claims"></a>

This grammar does not prove `eps_cls_unmapped = 0`; it only fixes a
prerequisite language needed to prove it. It does not prove ROM closure,
production contribution soundness, VSS/DKG security, commitment security,
selective-abort bounds, evidence noninterference, FIPS validation, audit, or
production readiness.

## Manifest Anchors

- `# Production Transcript Grammar for Threshold ML-DSA-65`
- `production-transcript-grammar`
- `ptg-scope-non-claim`
- `ptg-input-tuple`
- `ptg-canonical-encoding`
- `ptg-encoding-rules`
- `ptg-random-oracle-domains`
- `ptg-signing-attempt-grammar`
- `ptg-context-records`
- `SigningContext`
- `ptg-commitment-records`
- `MaskCommitRecord_i`
- `SecretCommitRecord_i`
- `ptg-challenge-record`
- `ChallengeRecord`
- `ptg-contribution-statement-record`
- `ptg-contribution-frame-grammar`
- `ContributionStatement_i`
- `ptg-aggregate-output-record`
- `ptg-collection-release-grammar`
- `AggregateOutputRecord`
- `ptg-evidence-abort-records`
- `ptg-evidence-abort-grammar`
- `AbortRecord`
- `EvidenceRecord`
- `ptg-random-oracle-mapping`
- `H_contrib`
- `ptg-classifier-interface`
- `ptg-classifier-compatibility`
- `ptg-totality-disjointness-obligations`
- `ptg-acceptance-criteria`
- `ptg-non-claims`
- `eps_cls_unmapped = 0`
- `ptg-open-proof-obligations`
