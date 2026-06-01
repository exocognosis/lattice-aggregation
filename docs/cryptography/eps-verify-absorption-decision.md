# eps_verify Absorption Decision Route
<a id="eps-verify-absorption-decision-route"></a>

Status: decision roadmap for eps_verify absorption, not a completed verifier
compatibility proof.

## Scope
<a id="eps-verify-scope"></a>

This route fixes the proof question shape for whether verifier mismatch is
absorbed into `eps_rej` or carried separately as `eps_verify` in Residual
Closure Batch B. It does not choose the final accounting route. It records the
standard verification boundary, the visible residual decomposition, and the
criteria required before a later theorem may eliminate or absorb the verifier
residual.

## Standard Verification Boundary
<a id="eps-verify-standard-verification-boundary"></a>

The boundary is the unmodified ML-DSA-65 verification predicate evaluated on the
public verification inputs and emitted signature bytes:

```text
MLDSA65.Verify(pk, M, sigma) = accept
```

The proof route must identify the external message `M` with the internal
message representative `mu` through the same pre-hash, domain-separation, and
context rules used by standard ML-DSA-65. Until that binding is proved, verifier
compatibility cannot be claimed.

Definitions for this boundary:

- `sigma`: the exact signature byte string emitted by aggregate construction,
  including standard-size ML-DSA-65 layout and all encoding constraints for the
  challenge bytes, `z`, and hint `h`.
- `pk`: the public key consumed by the unmodified verifier. For threshold
  aggregation proofs this must be the same public key represented by
  `pk_epoch`, with any epoch or DKG metadata kept outside the standard verifier
  input unless a separate binding theorem maps it to `pk`.
- `mu`: the message representative used by the signing and aggregation
  transcript. The route must prove that verifier-side message processing derives
  the same `mu` from `pk`, context, and `M`.
- challenge bytes: the encoded challenge component inside `sigma`, including
  the byte string usually written `c_tilde`, the challenge hash input order, and
  the deterministic expansion relation used by ML-DSA-65 verification.
- hint use: the verifier-side use of the encoded hint `h`, including hint count,
  index ordering, malformed-hint rejection, and the reconstruction relation
  applied to the aggregate candidate.
- high-bit reconstruction: the verifier-side reconstruction of high bits from
  the public key component, challenge, `z`, and hint, using the standard
  ML-DSA-65 rounding and decomposition functions.
- aggregate acceptance predicate: the threshold-side predicate that accepts an
  `AggregateOutputRecord`, including collection validity, challenge binding,
  rejection predicates, candidate reconstruction, and byte emission.
- unmodified ML-DSA-65 verification predicate: the standard verifier relation
  with no threshold-specific fallback, relaxed encoding, alternate challenge
  derivation, or aggregate-aware hint interpretation.

## Theorem Target
<a id="theorem-v1-standard-verifier-compatibility"></a>

`Theorem V1-standard-verifier-compatibility`:

```text
For every accepted aggregate output O with signature bytes sigma, public key pk,
message representative mu, and external message M, if all prerequisite
transcript, aggregation, encoding, rejection-predicate, challenge-binding,
hint-use, and message-binding obligations hold, then the unmodified ML-DSA-65
verification predicate accepts exactly when the aggregate acceptance predicate
accepts the same candidate relation.
```

The theorem target must be stated as predicate compatibility, not as
implementation success. It must quantify over malformed encodings, rejected
candidate values, challenge mismatch, hint mismatch, and message-binding
mismatch so those cases are either rejected by both predicates or charged to a
visible residual.

## Visible Residual Decomposition
<a id="eps-verify-visible-residual-decomposition"></a>

The verifier residual must remain decomposed until a later proof closes or
absorbs each subterm:

```text
eps_verify
  <= eps_verify_encoding
   + eps_verify_challenge
   + eps_verify_highbits
   + eps_verify_hint_use
   + eps_verify_message_binding
   + eps_verify_reject_absorption
   + eps_verify_mismatch
```

Subterm meanings:

- `eps_verify_encoding`: aggregate emits bytes that are accepted by the
  threshold route but are not identical to standard ML-DSA-65 signature
  encodings, or malformed standard encodings are not rejected at the same
  boundary.
- `eps_verify_challenge`: challenge bytes, challenge expansion, or challenge
  hash inputs differ between aggregate construction and unmodified verification.
- `eps_verify_highbits`: verifier-side high-bit reconstruction differs from the
  aggregate candidate relation after applying the standard rounding and hint
  reconstruction functions.
- `eps_verify_hint_use`: hint encoding, hint cardinality, hint ordering, or
  verifier-side hint application differs from the aggregate route.
- `eps_verify_message_binding`: external message `M`, context, public key, and
  internal representative `mu` are not proved to bind to the same verifier
  input relation.
- `eps_verify_reject_absorption`: the portion of verifier mismatch that may be
  absorbed into `eps_rej` if rejection-predicate equivalence also proves exact
  verifier compatibility for the same candidate values.
- `eps_verify_mismatch`: remaining aggregate-accepts/verifier-rejects or
  verifier-accepts/aggregate-rejects cases not assigned to a more specific
  verifier subterm.

## Decision Paths
<a id="eps-verify-decision-paths"></a>

Two accounting paths remain open.

Batch C decision-record details are tracked in
[eps_verify Absorption Decision Record](eps-verify-absorption-decision-record.md).

Path A: absorb verifier mismatch into `eps_rej`.

This path is available only if the exact predicate-equivalence theorem includes
standard verifier compatibility. The proof must show that `Reject_T` and
`Reject_0` are evaluated on the same candidate relation, that accepted aggregate
bytes are exactly the verifier bytes, and that every verifier-side rejection
case is already represented by the rejection-predicate theorem. Under this
path, `eps_verify_reject_absorption` is discharged into `eps_rej`, and no
separate `eps_verify` term is carried for the same events.

Path B: keep verifier mismatch as separate `eps_verify`.

This path is required if rejection-predicate equivalence is narrower than full
verifier compatibility, if message binding from `M` to `mu` is outside the
rejection theorem, if byte encoding or hint-use compatibility is proved by a
separate lemma, or if any aggregate/verifier mismatch remains visible after
`eps_rej` closure. Under this path, `eps_verify` stays in the final bound with
its subterms listed explicitly.

Choice criteria for the final theorem:

- exact predicate scope: does the rejection theorem include byte-level verifier
  acceptance, or only candidate rejection predicates before byte emission?
- message boundary: is `M` to `mu` compatibility part of rejection equivalence,
  or a separate verifier theorem?
- encoding boundary: are `sigma`, challenge bytes, and hint bytes proved
  standard before `eps_rej`, or only after aggregation acceptance?
- mismatch accounting: can every verifier mismatch be assigned to an existing
  `eps_rej` subterm without double counting or hiding a new assumption?
- theorem readability: does absorption make the final theorem clearer without
  weakening auditability of verifier-specific obligations?

The final choice is open. This document only states what must be proved before
choosing absorption or separate carry.

## Acceptance Criteria
<a id="eps-verify-acceptance-criteria"></a>

A later closure document may mark this route resolved only after it provides:

- a precise statement of `Theorem V1-standard-verifier-compatibility`;
- byte-for-byte definition of `sigma` at the verifier boundary;
- a proof that verifier-side challenge bytes and aggregate challenge bytes are
  identical;
- a proof that high-bit reconstruction and hint use match the standard
  verifier;
- a proof that `pk`, `M`, and `mu` are bound to the same verification relation;
- an explicit decision to absorb into `eps_rej` or carry `eps_verify`;
- residual accounting showing no verifier mismatch is silently omitted or
  double counted.

## Non-Claims
<a id="eps-verify-non-claims"></a>

This roadmap does not prove verifier compatibility. It does not decide
absorption into `eps_rej`. It makes no negligible claim and no zero claim for
`eps_verify`, `eps_verify_mismatch`, or any listed subterm. It is not a
production-readiness statement. Implementation evidence, tests, or successful
hazmat verifier experiments are useful review inputs but are not cryptographic
proof.

Implementation evidence is not cryptographic proof.

## Manifest Anchors
<a id="eps-verify-manifest-anchors"></a>

Stable strings for manifests, cross-references, and residual tracking:

- `eps-verify-absorption-decision-route`
- `eps-verify-scope`
- `eps-verify-standard-verification-boundary`
- `theorem-v1-standard-verifier-compatibility`
- `eps-verify-visible-residual-decomposition`
- `eps-verify-decision-paths`
- `eps-verify-acceptance-criteria`
- `eps-verify-non-claims`
- `eps-verify-manifest-anchors`
- `Theorem V1-standard-verifier-compatibility`
- `eps_verify_encoding`
- `eps_verify_challenge`
- `eps_verify_highbits`
- `eps_verify_hint_use`
- `eps_verify_message_binding`
- `eps_verify_reject_absorption`
- `eps_verify_mismatch`
