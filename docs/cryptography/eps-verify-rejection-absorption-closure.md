# eps_verify Rejection Absorption Closure Route
<a id="eps-verify-rejection-absorption-closure"></a>

Status: Batch D theorem-closure route, not a completed proof.

Theorem target name: `Theorem V3-verifier-rejection-absorption`

Batch E refines this route into the formal-reduction draft
[`eps-verify-to-rej-absorption-theorem.md`](eps-verify-to-rej-absorption-theorem.md)
for `Theorem V4-eps-verify-to-eps-rej-absorption`.

## Purpose
<a id="eps-verify-rejection-absorption-purpose"></a>

This route records the byte-level obligations that must be closed before
`eps_verify` can be absorbed into `eps_rej`. The conservative decision remains
to carry `eps_verify` separately until `Theorem V3-verifier-rejection-absorption`
is proved.

The target theorem must show that every verifier disagreement event charged to
`eps_verify` is either exactly the same event as a rejection-predicate event
already charged to `eps_rej`, or remains outside absorption as a visible
residual. No verifier event may be hidden by notation before the byte-level
candidate tuple is fixed.

## Byte-Level Equality Obligations
<a id="eps-verify-rejection-absorption-byte-obligations"></a>

Absorption is available only after the proof establishes all obligations below
over the same candidate tuple consumed by aggregate acceptance, standard
verification, and rejection-predicate evaluation.

1. Sigma byte equality:
   the byte string emitted as the aggregate signature must be identical to the
   byte string supplied to the standard verifier. This includes all packed
   signature fields, canonical encoding choices, field ordering, length
   boundaries, and rejection of alternate encodings. Residual:
   `eps_verify_byte_eq`.

2. Challenge equality:
   the verifier challenge derived from the aggregate candidate must equal the
   challenge derived by the standard verifier from the same bytes. The proof
   must align hash inputs, domain separation, context handling, deterministic
   expansion, challenge packing, and any parse-before-hash boundary. Residual:
   `eps_verify_challenge_eq`.

3. Highbits/hint equality:
   high-bit reconstruction and hint processing must agree byte for byte. The
   proof must align the reconstructed high bits, hint bytes, hint ordering,
   hint count, malformed-hint handling, and all boundary checks used by the
   rejection predicate and the standard verifier. Residual:
   `eps_verify_hint_eq`.

4. Message-to-mu binding:
   the message `M` consumed by aggregate acceptance must bind to the same `mu`
   value consumed by standard verification. The proof must align public-key
   inclusion, context string, pre-hash mode, message bytes, domain separation,
   and transcript ordering. Residual: `eps_verify_mu_bind`.

5. Public key binding:
   the public key bytes used by aggregate acceptance, challenge computation,
   `mu` derivation, and standard verification must be the same bytes under the
   same canonical parse. Residual: `eps_verify_pk_bind`.

6. Malformed encoding agreement:
   aggregate acceptance, standard verification, and rejection-predicate
   evaluation must reject the same malformed encodings at the same boundary.
   This covers malformed public keys, malformed signatures, non-canonical
   field encodings, length errors, invalid hint encodings, and parse failures
   before challenge or `mu` derivation. Residual: `eps_verify_malformed`.

7. Rejection predicate agreement:
   once byte equality, challenge equality, highbits/hint equality, `mu`
   binding, public-key binding, and malformed-boundary agreement are fixed, the
   event classified as verifier rejection must equal the event classified by
   the rejection predicate. Residual: `eps_verify_rej_absorb`.

8. No double counting:
   each bad event must be assigned exactly once. Events absorbed into `eps_rej`
   through `eps_verify_rej_absorb` may not also remain in `eps_verify`, while
   any verifier disagreement not covered by the absorption theorem must remain
   explicitly charged to `eps_verify`.

## Residual Accounting Route
<a id="eps-verify-rejection-absorption-residual-accounting"></a>

The closure route tracks the following verifier residual terms:

- `eps_verify_byte_eq`
- `eps_verify_challenge_eq`
- `eps_verify_hint_eq`
- `eps_verify_mu_bind`
- `eps_verify_pk_bind`
- `eps_verify_malformed`
- `eps_verify_rej_absorb`
- `eps_verify`

Before `Theorem V3-verifier-rejection-absorption` is proved, the final bound
must carry `eps_verify` visibly and must not replace it with `eps_rej`. After a
future proof, only the subevents discharged by `eps_verify_rej_absorb` may move
into `eps_rej`; all surviving verifier disagreement must remain in
`eps_verify`.

## Conservative Decision
<a id="eps-verify-rejection-absorption-conservative-decision"></a>

Carry `eps_verify` separately until `Theorem V3-verifier-rejection-absorption`
is proved. This is the conservative Batch D decision because the current route
records proof obligations, not a completed byte-level equality theorem and not a
completed absorption proof.

## Non-Claims
<a id="eps-verify-rejection-absorption-non-claims"></a>

This document does not prove standard verifier compatibility.
It does not absorb `eps_verify` into `eps_rej`.
It makes no zero claim and no negligible claim for `eps_verify` or any verifier
residual subterm.
Implementation evidence is not cryptographic proof; tests, code crosswalks,
and successful verifier experiments are review inputs only.

## Manifest Anchors
<a id="eps-verify-rejection-absorption-manifest-anchors"></a>

Stable strings for manifests, cross-references, and residual tracking:

- `eps-verify-rejection-absorption-closure`
- `eps-verify-rejection-absorption-purpose`
- `eps-verify-rejection-absorption-byte-obligations`
- `eps-verify-rejection-absorption-residual-accounting`
- `eps-verify-rejection-absorption-conservative-decision`
- `eps-verify-rejection-absorption-non-claims`
- `eps-verify-rejection-absorption-manifest-anchors`
- `Theorem V3-verifier-rejection-absorption`
- `eps_verify_byte_eq`
- `eps_verify_challenge_eq`
- `eps_verify_hint_eq`
- `eps_verify_mu_bind`
- `eps_verify_pk_bind`
- `eps_verify_malformed`
- `eps_verify_rej_absorb`
- `eps_verify`
