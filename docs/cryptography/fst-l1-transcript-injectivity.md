# FST-L1 Transcript Injectivity Worksheet
<a id="fst-l1-transcript-injectivity"></a>

Date: 2026-05-28

Status: theorem-closure text for `FST-L1` under the pinned transcript grammar
assumptions; not a production deployment claim.

## FSTL1-0. Scope and Non-Claim
<a id="fstl1-scope-non-claim"></a>

This document states the conditional closure of the `FST-L1`
transcript-injectivity lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It uses the source
grammar in [production-transcript-grammar.md](production-transcript-grammar.md)
and the random-oracle separation requirements in
[random-oracle-game.md](random-oracle-game.md).

The claim boundary is conservative. `FST-L1` closes only as a formal theorem
over the currently pinned transcript grammar, fixed record labels, fixed
version field, explicit field tags, canonical validator order, and byte-level
encoders whose parser/serializer injectivity has been audited. If
[production-transcript-grammar.md](production-transcript-grammar.md) changes,
or if any production encoder admits an unreviewed byte representation, the
closure reopens and the residual terms below remain charged.

This document does not claim production transcript security, VSS/DKG security,
rejection-sampling equivalence, classifier closure, ROM soundness, or
deployment readiness. Implementation tests and scaffold evidence can support
engineering review, but they are not cryptographic proof.

## FSTL1-1. Lemma Statement
<a id="fstl1-lemma-statement"></a>

Theorem `FST-L1` (canonical transcript injectivity). Fix one transcript grammar
revision from [production-transcript-grammar.md](production-transcript-grammar.md)
and the corresponding byte-level encoder family `Enc`. Assume:

- each accepted transcript record is parsed in exactly one record domain;
- `label`, `version`, option tags, variant tags, field widths, vector counts,
  map counts, and byte-string lengths are fixed by that grammar revision;
- every validator-indexed collection is sorted in canonical validator order
  and rejects duplicates and unknown validators;
- every random-oracle call uses the stated domain label and record kind;
- encoder and parser implementations are audited against the grammar.

Then, for accepted transcript records `R` and `R'` in the `FST-L1` source
language:

```text
FST-L1:
  Enc(R) = Enc(R') implies R = R',
  except through BadTranscriptCollision, BadRoDomain, BadCrossSession,
  eps_ro_domain_separation, or eps_ro_injective_encoding.
```

Equivalently, an adversary cannot cause two distinct accepted typed transcript
objects to be interpreted as the same random-oracle input except through the
visible residual terms `eps_ro_sep`, `eps_ro_injective_encoding`, and
`eps_ro_domain_separation`, with bad events `BadTranscriptCollision`,
`BadRoDomain`, and `BadCrossSession` retained for the surrounding hybrids.

The lemma is a prerequisite for `FST-A7`: every random-oracle input used by the
protocol must be an injective, typed, versioned byte encoding of exactly one
proof object.

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

Each record is interpreted as a typed object before hashing. Its record domain
is the set of values accepted by the grammar under one label, one version, and
one ordered field schema. A value outside that domain is not repaired by
defaults or alternate parsers; it is rejected before hashing.

The theorem quantifies only over accepted source-language records. It therefore
does not prove that every deployed byte stream is accepted, that every
implementation rejects malformed input, or that production code has been
audited. It proves that the formal source domains are disjoint and injectively
encoded when the pinned grammar and audited encoders are held fixed.

## FSTL1-3. Encoding Model
<a id="fstl1-encoding-model"></a>

The canonical encoding model is:

```text
Enc(label, version, field_1, ..., field_n)
```

Canonical encoding means that each typed record has exactly one byte string and
each accepted byte string decodes to exactly one typed record. The proof uses
the following parser lemmas as assumptions that must be instantiated by the
byte-level encoder audit:

- `label` strings are fixed and prefix-free across record families.
- `version` has one fixed width and one accepted value per grammar revision.
- Integer widths are fixed and big-endian.
- Byte strings are length-prefixed.
- Vectors and maps include counts.
- Validator-index maps are sorted by canonical validator order.
- Optional fields use explicit tags.
- No record is accepted through untagged concatenation or implicit defaults.

Under these rules, equality of two encodings first identifies the common
record domain by `label` and `version`, then identifies every field boundary,
then applies field-level injectivity recursively to nested records, vectors,
maps, options, and variants.

## FSTL1-4. Record Injectivity Obligations
<a id="fstl1-record-injectivity-obligations"></a>

Record domains are pairwise disjoint by label and version. Within each domain,
injectivity reduces to the following field obligations:

| Record domain | Injectivity obligation |
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

Nested records are compared structurally. For example, equality of
`ChallengeRecord` encodings implies equality of the nested `SigningContext`,
then equality of the ordered commitment and opening collections, then equality
of the aggregate `w1` value or digest.

## FSTL1-5. Canonical Ordering Obligations
<a id="fstl1-canonical-ordering-obligations"></a>

Active-set and order injectivity is the statement that a collection's accepted
encoding determines both its members and their canonical order. For
`OrderedMaskCommitSet`, `OrderedMaskOpenSet`,
`OrderedContributionStatementSet`, `active_set`, and classifier collection
records:

- the encoded count fixes the collection length;
- each validator index appears at most once;
- every validator index is drawn from the bound validator set;
- the accepted order is the canonical validator order, not network arrival
  order;
- each element is parsed under its own record-domain rules.

Thus a permutation of the same active set either re-encodes to the same
canonical byte string after sorting, or is rejected if it is presented as an
already ordered object that violates canonical order. A different active set
cannot share the same bytes without an element, count, or field-boundary
collision charged to `eps_ro_injective_encoding`.

## FSTL1-6. Optional and Variant Field Obligations
<a id="fstl1-optional-variant-obligations"></a>

Optional and variant fields are part of the record domain, not informal side
conditions. Abort, evidence, backend, relation, and release records contain
variant fields. Every accepted variant must have a tag that distinguishes:

- absent values from present values;
- empty byte strings from absent byte strings;
- backend-specific payloads from other backend payloads;
- relation identifiers from relation payloads;
- evidence and abort error classes from their associated data.

Tagged optionals must reject trailing, truncated, duplicate, and malformed
encodings. No field may be accepted through both an implicit default and an
explicit tag. Therefore equality of bytes fixes the option or variant case
before any payload equality is considered.

## FSTL1-7. Random-Oracle Domain Separation
<a id="fstl1-random-oracle-domain-separation"></a>

Random-oracle domain separation is modeled as a typed map from
`(oracle_name, record_domain, label, version, context)` to one byte domain.
The byte-level proof must separate `H_mu`, `H_w`, `H_c`, `H_vss`, and
`H_contrib`. Separation requires both explicit oracle labels and injective
record encodings under those labels.

SHAKE256 labels alone are not sufficient unless the production encoding proof
establishes prefix-free domains, stable context binding, and record
injectivity. A collision between oracle domains is charged to `BadRoDomain`
and remains visible as `eps_ro_domain_separation` inside `eps_ro_sep`.

## FSTL1-8. ChallengeRecord Injectivity
<a id="fstl1-challengerecord-injectivity"></a>

For `ChallengeRecord`, identical encoded bytes must imply identical:

- `SigningContext`;
- ordered commitment set;
- ordered opening set;
- aggregate public `w1` or aggregate digest;
- attempt and message binding.

This is the local field-equality step needed by `FST-L2`.

Proof. The `ChallengeRecord` label and version select the challenge record
domain. The length-delimited nested `SigningContext` then has equal bytes and
is equal by the `SigningContext` domain lemma. The collection counts and
canonical validator order identify the commitment and opening elements
position by position, and each element is equal by its record-domain lemma.
The final aggregate field is either the tagged public `w1` value or the tagged
digest variant; equality of the tag fixes the case and equality of the
length-delimited payload fixes the value. Therefore two accepted
`ChallengeRecord` encodings are equal only for the same challenge object,
except through `eps_ro_injective_encoding`.

## FSTL1-9. Cross-Record Replay Exclusion
<a id="fstl1-cross-record-replay-exclusion"></a>

The proof excludes cross-record and cross-session replay by typed labels,
version fields, session identifiers, epoch identifiers, attempts, active-set
digests, message binding, public key binding, and DKG digest binding. Any
failure is charged to `BadTranscriptCollision`, `BadRoDomain`, or
`BadCrossSession`.

The proof is by cases.

1. Same record kind. Equal `label` and `version` put both records in one
   record domain. Fixed field boundaries and recursive field injectivity force
   equality of every scalar, byte string, nested record, vector, map, option,
   and variant. The records are equal unless a parser or field-boundary
   collision occurs, which is charged to `eps_ro_injective_encoding` and
   `BadTranscriptCollision`.
2. Cross-record replay. Different record kinds have different prefix-free
   labels and disjoint parser domains. A byte string accepted as both kinds
   violates label or record-domain separation and is charged to
   `BadTranscriptCollision` or `BadRoDomain`.
3. Active-set permutation. Validator-indexed collections include counts,
   unique validator indices, and canonical validator order. Arrival-order
   permutations cannot produce a distinct accepted ordered object with the
   same bytes; a failure is an ordering collision inside
   `eps_ro_injective_encoding`.
4. Optional-field ambiguity. Option and variant tags distinguish absent,
   present, empty, backend-specific, relation-specific, abort, and evidence
   cases before payload parsing. A value accepted under two cases is charged to
   the optional/variant component of `eps_ro_injective_encoding`.
5. Domain-label collision. Random-oracle inputs include oracle-domain labels
   and record-domain labels. A collision between `H_mu`, `H_w`, `H_c`,
   `H_vss`, or `H_contrib` domains is `BadRoDomain` and contributes
   `eps_ro_domain_separation`.
6. Version/context mismatch. Version, epoch, session, attempt, message
   binding, public key, active-set digest, validator-set digest, and DKG digest
   are explicit fields in the relevant records. Reuse across incompatible
   contexts either changes bytes or triggers `BadCrossSession`.

## FSTL1-10. Residual Terms
<a id="fstl1-residual-terms"></a>

The closure keeps the residual terms visible. Injectivity failure is
decomposed as:

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

For theorem-closure use, `eps_label_collision`, `eps_version_collision`,
`eps_record_cross_parse`, `eps_field_boundary_collision`,
`eps_ordering_collision`, `eps_optional_collision`, and
`eps_record_acceptance_gap` are folded into the displayed residuals unless a
future byte-level audit proves them zero. The named bad events remain:

- `BadTranscriptCollision`: two distinct accepted typed transcript records
  share one encoding;
- `BadRoDomain`: two random-oracle domains or record domains share an
  accepted input;
- `BadCrossSession`: a transcript object is reused across a mismatched epoch,
  session, attempt, message, key, validator set, active set, or DKG context.

## FSTL1-11. Acceptance Criteria
<a id="fstl1-acceptance-criteria"></a>

Before `FST-L1` can be treated as closed in a theorem that depends on this
document:

- every record in the production grammar has a byte-level parser definition;
- parser acceptance is total over valid records and rejects invalid encodings;
- record labels and field tags are fixed in a versioned table;
- canonical validator ordering is proved for all maps and active sets;
- message binding is resolved as raw `M`, `mu`, or a proved consistent pair;
- every residual term is either eliminated or retained in the theorem.

The closure is invalidated by any change to
[production-transcript-grammar.md](production-transcript-grammar.md) that
changes labels, field order, accepted variants, canonical ordering, context
fields, or oracle-domain labels unless this document and the byte-level encoder
audit are updated together.

## FSTL1-12. Non-Claims
<a id="fstl1-non-claims"></a>

This theorem-closure text does not prove random-oracle programmability, ROM
soundness, challenge binding, contribution soundness, collection soundness,
rejection sampling, classifier totality, or production deployment readiness. It
does not audit production encoders, parsers, serialization libraries, constant
time behavior, logging, or error handling.

Implementation evidence is not cryptographic proof. Tests may demonstrate that
one implementation follows the intended grammar for sampled cases, but `FST-L1`
requires the formal byte-level injectivity and parser-disjointness lemmas
described above. Evidence and abort records must not leak honest shares, masks,
proof witnesses, or rejection internals unless a later theorem allows that
leakage.

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
