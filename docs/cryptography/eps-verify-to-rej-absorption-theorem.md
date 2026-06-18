# eps_verify to eps_rej Absorption Theorem Draft
<a id="eps-verify-to-rej-absorption-theorem"></a>

Status: Batch E formal-reduction draft, not a completed verifier absorption proof.

Theorem target name: `Theorem V4-eps-verify-to-eps-rej-absorption`

## Theorem Target
<a id="eps-verify-to-rej-theorem-target"></a>

`Theorem V4-eps-verify-to-eps-rej-absorption` targets the exact conditions under
which a verifier disagreement event can be moved from `eps_verify` into
`eps_rej`. The conservative route remains unchanged: `eps_verify` remains
separate until V4 is proved. After V4, only discharged subevents move to
`eps_rej`, and `eps_verify_survive` remains visible in the final accounting.

## Candidate Tuple
<a id="eps-verify-to-rej-candidate-tuple"></a>

The candidate tuple is:

```text
C = (pk_bytes, M, ctx, prehash_mode, mu, sigma_bytes, c_tilde, z, h, w1)
```

The theorem draft requires aggregate acceptance, standard verifier evaluation,
threshold acceptance evaluation, and rejection-predicate evaluation to consume
the same candidate tuple under the same parsing, domain separation, and
byte-boundary rules.

## Predicates
<a id="eps-verify-to-rej-predicates"></a>

Standard verifier predicate:

```text
Verify_std(C) = 1
```

means the ML-DSA standard verifier accepts `sigma_bytes` for `pk_bytes`, `M`,
`ctx`, and `prehash_mode`, after deriving the same `mu`, challenge, highbits,
and hint interpretation specified for the candidate tuple.

Threshold acceptance predicate:

```text
Accept_thr(C) = 1
```

means the threshold aggregation transcript accepts and emits `sigma_bytes` as
the aggregate candidate for the same public key, message, context, pre-hash
mode, `mu`, challenge, highbits, and hint bytes.

Rejection predicate:

```text
Reject_pred(C) = 1
```

means the rejection theorem classifies the same candidate tuple as rejected by a
bound, malformed-boundary, challenge, hint, or reconstruction condition already
accounted for by `eps_rej`.

## Premises
<a id="eps-verify-to-rej-premises"></a>

Byte equality premises:

- `eps_verify_byte_eq`: the aggregate-emitted `sigma_bytes` are identical to
  the bytes consumed by `Verify_std`.
- `eps_verify_challenge_eq`: challenge bytes, hash inputs, domain separation,
  deterministic expansion, and challenge packing are identical.
- `eps_verify_hint_eq`: hint bytes, hint count, hint ordering, highbit
  reconstruction inputs, and hint handling are identical.
- `eps_verify_mu_bind`: `M`, `ctx`, `prehash_mode`, and public-key inclusion
  bind to the same `mu`.
- `eps_verify_pk_bind`: all predicates use the same canonical public-key bytes
  and parse result.

Malformed-boundary premises:

- `eps_verify_malformed`: malformed public keys, malformed signatures,
  non-canonical encodings, length errors, invalid hint encodings, and parse
  failures are rejected at the same boundary before later derived values are
  used.

No-double-counting rule:

- Every bad event is assigned exactly once. A subevent moved into `eps_rej`
  through V4 is removed from `eps_verify`; any verifier disagreement not
  discharged by V4 remains in `eps_verify_survive`.

Absorption rule:

```text
Accept_thr(C) = 1 and Verify_std(C) = 0
  ==> Reject_pred(C) = 1 or C belongs to eps_verify_survive.
```

Only the `Reject_pred(C) = 1` branch is eligible for absorption into
`eps_rej`. The surviving branch remains visible as `eps_verify_survive`.

## Proof Skeleton
<a id="eps-verify-to-rej-proof-skeleton"></a>

V4-H0: Real verifier-disagreement game.

Start from the event where threshold acceptance and standard verification
disagree on the candidate tuple. This event is charged to `eps_verify`.

V4-H1: Sigma byte alignment.

Replace aggregate-emitted signature bytes with the exact verifier input bytes.
The transition is charged to `eps_verify_byte_eq`.

V4-H2: Challenge and transcript alignment.

Align challenge bytes, transcript inputs, domain separation, deterministic
expansion, and challenge packing. The transition is charged to
`eps_verify_challenge_eq`, `eps_verify_mu_bind`, and `eps_verify_pk_bind`.

V4-H3: Hint and highbit alignment.

Align hint bytes, hint ordering, hint count, highbit reconstruction, and
malformed-hint handling. The transition is charged to `eps_verify_hint_eq`.

V4-H4: Malformed-boundary alignment.

Align parse failures, non-canonical encodings, length checks, malformed public
keys, malformed signatures, and malformed hints so all predicates reject at the
same boundary. The transition is charged to `eps_verify_malformed`.

V4-H5: Rejection absorption partition.

Partition the remaining verifier-disagreement event into the branch already
classified by `Reject_pred(C)` and the surviving verifier-only branch. The
absorbed branch is charged through `eps_verify_rej_absorb` and then moves to
`eps_rej`; the surviving branch remains charged to `eps_verify_survive`.

## Residual Accounting
<a id="eps-verify-to-rej-residual-accounting"></a>

The V4 draft tracks these residual terms:

- `eps_verify_byte_eq`
- `eps_verify_challenge_eq`
- `eps_verify_hint_eq`
- `eps_verify_mu_bind`
- `eps_verify_pk_bind`
- `eps_verify_malformed`
- `eps_verify_rej_absorb`
- `eps_verify_survive`
- `eps_verify`
- `eps_rej`

Before V4 is proved, `eps_verify` remains separate and must not be hidden
inside `eps_rej`. After V4 is proved, only discharged subevents move to
`eps_rej`; `eps_verify_survive` remains visible and must still be carried.

## Non-Claims
<a id="eps-verify-to-rej-non-claims"></a>

This draft does not prove standard verifier compatibility.
It does not absorb `eps_verify` today.
It does not prove `eps_verify_survive = 0`.
It makes no zero claim and no negligible claim.
Implementation evidence is not cryptographic proof.

## Manifest Anchors
<a id="eps-verify-to-rej-manifest-anchors"></a>

Stable strings for manifests, cross-references, and residual tracking:

- `eps-verify-to-rej-absorption-theorem`
- `eps-verify-to-rej-theorem-target`
- `eps-verify-to-rej-candidate-tuple`
- `eps-verify-to-rej-predicates`
- `eps-verify-to-rej-premises`
- `eps-verify-to-rej-proof-skeleton`
- `eps-verify-to-rej-residual-accounting`
- `eps-verify-to-rej-non-claims`
- `eps-verify-to-rej-manifest-anchors`
- `Theorem V4-eps-verify-to-eps-rej-absorption`
- `V4-H0`
- `V4-H1`
- `V4-H2`
- `V4-H3`
- `V4-H4`
- `V4-H5`
- `eps_verify_byte_eq`
- `eps_verify_challenge_eq`
- `eps_verify_hint_eq`
- `eps_verify_mu_bind`
- `eps_verify_pk_bind`
- `eps_verify_malformed`
- `eps_verify_rej_absorb`
- `eps_verify_survive`
- `eps_verify`
- `eps_rej`
