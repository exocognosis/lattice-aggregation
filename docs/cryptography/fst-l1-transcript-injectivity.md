# FST-L1 Transcript Injectivity Worksheet
<a id="fst-l1-transcript-injectivity"></a>

Date: 2026-05-28

Status: reduction worksheet for `FST-L1`, not a completed injectivity proof.

## FSTL1-0. Scope and Non-Claim
<a id="fstl1-scope-non-claim"></a>

This worksheet expands the `FST-L1` transcript-injectivity lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It uses the source
grammar in [production-transcript-grammar.md](production-transcript-grammar.md)
and the random-oracle separation requirements in
[random-oracle-game.md](random-oracle-game.md).

This document does not prove byte-level injectivity. It does not close
`eps_ro`, `eps_ro_sep`, `eps_ro_injective_encoding`, or
`eps_ro_domain_separation`, and it does not claim production transcript
security, VSS/DKG security, rejection-sampling equivalence, classifier closure,
or deployment readiness.

## FSTL1-1. Lemma Statement
<a id="fstl1-lemma-statement"></a>

Target lemma:

```text
FST-L1:
  For every accepted production transcript record R and R',
  Enc(R) = Enc(R') implies R = R',
  except through the explicitly stated encoding-collision event.
```

The lemma is a prerequisite for `FST-A7`: every random-oracle input used by
the protocol must be an injective, typed, versioned byte encoding of exactly
one proof object.

## FSTL1-2. Source Grammar
<a id="fstl1-source-grammar"></a>

The source language is the production transcript grammar:

- `SigningContext`;
- `MaskCommitRecord_i`;
- `MaskOpenStatement_i`;
- `SecretCommitRecord_i`;
- `ChallengeRecord`;
- `ContributionStatement_i`;
- `AggregateOutputRecord`;
- `AbortRecord`;
- `EvidenceRecord`.

Each record is interpreted as a typed object before hashing. The proof must
not rely on implementation tests as cryptographic evidence.

## FSTL1-3. Encoding Model
<a id="fstl1-encoding-model"></a>

The intended encoding model is:

```text
Enc(label, version, field_1, ..., field_n)
```

The proof must instantiate or replace these axioms with concrete byte-level
parser lemmas:

- `label` strings are fixed and prefix-free across record families.
- `version` has one fixed width and one accepted value per grammar revision.
- Integer widths are fixed and big-endian.
- Byte strings are length-prefixed.
- Vectors and maps include counts.
- Validator-index maps are sorted by canonical validator order.
- Optional fields use explicit tags.
- No record is accepted through untagged concatenation or implicit defaults.

## FSTL1-4. Record Injectivity Obligations
<a id="fstl1-record-injectivity-obligations"></a>

| Record | Injectivity obligation |
| --- | --- |
| `SigningContext` | Distinguish parameter set, epoch, session, height, attempt, threshold, validator set, public key, DKG digest, and message binding. |
| `MaskCommitRecord_i` | Bind signer identity and mask commitment digest to one signing context. |
| `MaskOpenStatement_i` | Bind public mask statement and auxiliary digest to the matching signer and context. |
| `SecretCommitRecord_i` | Bind challenge digest and secret commitment digest to one signer and context. |
| `ChallengeRecord` | Bind the ordered commitment set, opened set, and aggregate `w1` or digest. |
| `ContributionStatement_i` | Bind signer, challenge, key, DKG digest, commitment digests, contribution encoding, backend, relation, and schema. |
| `AggregateOutputRecord` | Bind active set, contribution statements, final signature bytes, and verification result. |
| `AbortRecord` | Bind abort kind, round, validator identity if present, and public evidence digest if present. |
| `EvidenceRecord` | Bind accused validator, evidence kind, offending frame, verifier context, and error code. |

## FSTL1-5. Canonical Ordering Obligations
<a id="fstl1-canonical-ordering-obligations"></a>

`OrderedMaskCommitSet`, `OrderedMaskOpenSet`,
`OrderedContributionStatementSet`, `active_set`, and classifier collection
records must have one accepted order. The proof must show that network arrival
order cannot produce a second valid encoding for the same set or a valid
encoding for a different set with the same bytes.

## FSTL1-6. Optional and Variant Field Obligations
<a id="fstl1-optional-variant-obligations"></a>

Abort, evidence, backend, relation, and release records contain variant fields.
Every accepted variant must have a tag that distinguishes absent values,
present values, backend-specific payloads, and error classes. Tagged optionals
must reject trailing, truncated, duplicate, and malformed encodings.

## FSTL1-7. Random-Oracle Domain Separation
<a id="fstl1-random-oracle-domain-separation"></a>

The byte-level proof must separate `H_mu`, `H_w`, `H_c`, `H_vss`, and
`H_contrib`. SHAKE256 labels alone are not sufficient unless the production
encoding proof establishes prefix-free domains and record injectivity.

## FSTL1-8. ChallengeRecord Injectivity
<a id="fstl1-challengerecord-injectivity"></a>

For `ChallengeRecord`, identical encoded bytes must imply identical:

- `SigningContext`;
- ordered commitment set;
- ordered opening set;
- aggregate public `w1` or aggregate digest;
- attempt and message binding.

This is the local field-equality step needed by `FST-L2`.

## FSTL1-9. Cross-Record Replay Exclusion
<a id="fstl1-cross-record-replay-exclusion"></a>

The proof must exclude cross-record and cross-session replay by typed labels,
version fields, session identifiers, epoch identifiers, attempts, active-set
digests, message binding, public key binding, and DKG digest binding. Any
failure is charged to `BadTranscriptCollision`, `BadRoDomain`, or
`BadCrossSession`.

## FSTL1-10. Residual Terms
<a id="fstl1-residual-terms"></a>

The worksheet decomposes injectivity failure as:

```text
eps_ro_sep
  <= eps_ro_domain_separation
   + eps_label_collision
   + eps_version_collision
   + eps_record_cross_parse

eps_ro_injective_encoding
  <= eps_field_boundary_collision
   + eps_ordering_collision
   + eps_optional_collision
   + eps_record_acceptance_gap
```

Each subterm must be proved zero by construction or carried visibly into the
random-oracle theorem. Hash collisions are not the primary issue here; the
target is unambiguous typed encoding before hashing.

## FSTL1-11. Acceptance Criteria
<a id="fstl1-acceptance-criteria"></a>

Before `FST-L1` can be treated as proved:

- every record in the production grammar has a byte-level parser definition;
- parser acceptance is total over valid records and rejects invalid encodings;
- record labels and field tags are fixed in a versioned table;
- canonical validator ordering is proved for all maps and active sets;
- message binding is resolved as raw `M`, `mu`, or a proved consistent pair;
- every residual term is either eliminated or retained in the theorem.

## FSTL1-12. Non-Claims
<a id="fstl1-non-claims"></a>

This worksheet does not prove random-oracle programmability, challenge
binding, contribution soundness, collection soundness, rejection sampling, or
classifier totality. Evidence and abort records must not leak honest shares,
masks, proof witnesses, or rejection internals unless a later theorem allows
that leakage.

## FSTL1-13. Manifest Anchors
<a id="fstl1-manifest-anchors"></a>

- `# FST-L1 Transcript Injectivity Worksheet`
- `fst-l1-transcript-injectivity`
- `FSTL1-0. Scope and Non-Claim`
- `FSTL1-1. Lemma Statement`
- `FSTL1-2. Source Grammar`
- `FSTL1-3. Encoding Model`
- `FSTL1-4. Record Injectivity Obligations`
- `FSTL1-5. Canonical Ordering Obligations`
- `FSTL1-6. Optional and Variant Field Obligations`
- `FSTL1-7. Random-Oracle Domain Separation`
- `FSTL1-8. ChallengeRecord Injectivity`
- `FSTL1-9. Cross-Record Replay Exclusion`
- `FSTL1-10. Residual Terms`
- `FSTL1-11. Acceptance Criteria`
- `FSTL1-12. Non-Claims`
- `FST-L1`
- `FST-A7`
- `ChallengeRecord`
- `SigningContext`
- `ContributionStatement_i`
- `AggregateOutputRecord`
- `Enc(label, version, field_1, ..., field_n)`
- `eps_ro_sep`
- `eps_ro_injective_encoding`
- `eps_ro_domain_separation`
- `BadTranscriptCollision`
- `BadRoDomain`
- `BadCrossSession`
