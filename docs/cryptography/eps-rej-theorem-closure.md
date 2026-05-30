# eps_rej Theorem Closure Batch
<a id="eps-rej-theorem-closure"></a>

Status: theorem-closure batch for `eps_rej`, not a completed
rejection-predicate proof.

This document refines the `RSTC-4` route from
[rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md).
It fixes the same-candidate predicate-equivalence obligations required before
the threshold aggregate rejection predicate can be substituted for centralized
ML-DSA-65 rejection.

It does not prove `Reject_T = Reject_0`, does not absorb `eps_verify`, and
does not claim accepted-distribution equivalence. Implementation evidence is
not cryptographic proof.

## ERTC-0. Scope and Non-Claim
<a id="ertc-scope-non-claim"></a>

The route applies only after a candidate tuple has been fixed:

```text
(pk, mu, c_tilde, c, z, LowBits(w - c*s2), c*t0, h)
```

It does not cover mask distribution, commitment hiding, random-oracle
programming, retry conditioning, or selective abort. Those terms remain
separate as `eps_mask`, `eps_commit`, `eps_ro`, and `eps_withhold`.

## ERTC-1. Theorem Statement
<a id="ertc-theorem-statement"></a>

Target statement:

```text
Theorem R-close-rejection-predicate.
Conditioned on H1 shared-secret reconstruction, H4 partial-response
reconstruction, and one exact candidate tuple, the threshold predicate
Reject_T and centralized ML-DSA-65 predicate Reject_0 differ only on the
displayed bad events:

eps_rej
 <= eps_bound_encoding
  + eps_lowbits_decomposition
  + eps_ct0_reconstruction
  + eps_hint_encoding
  + eps_challenge_encoding
  + eps_active_set_mismatch
  + eps_signature_encoding
  + eps_verify_mismatch.
```

The zero form is valid only if every bad event is proved impossible under the
fixed production transcript and verifier semantics.

## ERTC-2. Centered Representatives and Bounds
<a id="ertc-centered-bound-representatives"></a>

The proof must show identical centered coefficient interpretation for:

```text
||z||_inf < gamma1_65 - beta_65
||LowBits(w - c*s2)||_inf < gamma2_65 - beta_65
||c*t0||_inf < gamma2_65
weight(h) <= omega_65
weight(c) = tau_65
```

Any strictness, boundary, module-dimension, or centered-representative mismatch
is charged to:

```text
eps_bound_encoding
```

## ERTC-3. LowBits and ct0 Equality
<a id="ertc-lowbits-ct0-equality"></a>

The aggregate values must equal centralized candidate values coefficient by
coefficient:

```text
LowBits_T(masking.w - secret.cs2) = LowBits_0(w - c*s2)
ct0_T = c*t0
```

Residuals:

```text
eps_lowbits_decomposition
eps_ct0_reconstruction
```

These terms cannot hide active-set mismatch; active-set mismatch must remain
visible as `eps_active_set_mismatch` or `eps_collect`.

## ERTC-4. Hint Canonicality
<a id="ertc-hint-canonicality"></a>

The proof must align:

```text
h = MakeHint(-c*t0, w - c*s2 + c*t0)
```

with the threshold construction, hint ordering, offset encoding, unused slots,
hint weight, malformed hint rejection, and `UseHint` verifier reconstruction.

Any mismatch is charged to:

```text
eps_hint_encoding
```

## ERTC-5. Challenge Sampling
<a id="ertc-challenge-sampling"></a>

The threshold challenge seed and challenge polynomial must match ML-DSA-65:

```text
c = SampleInBall(c_tilde)
weight(c) = tau_65
```

The challenge input must be the same canonical byte string used by the final
standard verifier path, or the mismatch is charged to:

```text
eps_challenge_encoding
```

## ERTC-6. Active-Set Equality
<a id="ertc-active-set-equality"></a>

The same active set `A` must be bound into:

- commitments;
- challenge derivation;
- contribution validation;
- reconstruction of `cs1`, `cs2`, and `ct0`;
- aggregate rejection;
- signature release and evidence records.

Any mismatch is charged to:

```text
eps_active_set_mismatch
```

unless it is already included in `eps_collect`; the final theorem must choose
one accounting path.

## ERTC-7. Signature Encoding and Verification
<a id="ertc-signature-encoding-verification"></a>

The final wire signature must satisfy:

```text
sigma = Encode(c_tilde, z, h)
MLDSA65.Verify(pk, M, sigma) = accept
```

or the theorem must keep verifier mismatch visible:

```text
eps_signature_encoding
eps_verify_mismatch
```

`eps_verify` may be absorbed into `eps_rej` only after the proof shows that
aggregate acceptance includes unmodified standard ML-DSA-65 verification or an
exactly equivalent predicate.

## ERTC-8. Epsilon Final Form
<a id="ertc-epsilon-final-form"></a>

The route exports:

```text
eps_rej
 <= eps_bound_encoding
  + eps_lowbits_decomposition
  + eps_ct0_reconstruction
  + eps_hint_encoding
  + eps_challenge_encoding
  + eps_active_set_mismatch
  + eps_signature_encoding
  + eps_verify_mismatch
```

No term in this expression is claimed negligible or zero by this document.

## ERTC-9. Code Crosswalk
<a id="ertc-code-crosswalk"></a>

Current evidence:

- hazmat finalization checks `z`, low-bit, `ct0`, hint, and challenge
  consistency paths;
- signature packing/unpacking tests cover selected examples;
- standard-verifying hazmat tests exercise supported accepted paths.

These artifacts are regression evidence only. They do not prove byte-level
predicate equivalence for all accepted threshold candidates.

## ERTC-10. Acceptance Criteria
<a id="ertc-acceptance-criteria"></a>

This batch is acceptable only if it:

- keeps `eps_rej` scoped to same-candidate predicate mismatch;
- keeps `eps_mask`, `eps_withhold`, `eps_commit`, and `eps_ro` separate;
- makes the `eps_verify` decision explicit;
- covers centered bounds, low bits, `ct0`, hints, challenge sampling, active
  set, signature encoding, and verifier compatibility;
- says implementation evidence is not cryptographic proof.

## ERTC-11. Non-Claims
<a id="ertc-non-claims"></a>

This document does not claim:

- `eps_rej = 0`;
- `Reject_T = Reject_0` has been proved;
- standard verification compatibility is fully proved;
- accepted threshold signatures match centralized ML-DSA-65 rejection;
- tests replace theorem-level byte, algebra, and boundary proofs;
- the repository is production-ready.

## ERTC-12. Manifest Anchors
<a id="ertc-manifest-anchors"></a>

Stable anchors and text markers:

- `# eps_rej Theorem Closure Batch`
- `eps-rej-theorem-closure`
- `Status: theorem-closure batch for eps_rej`
- `ERTC-0. Scope and Non-Claim`
- `ERTC-1. Theorem Statement`
- `ERTC-2. Centered Representatives and Bounds`
- `ERTC-3. LowBits and ct0 Equality`
- `ERTC-4. Hint Canonicality`
- `ERTC-5. Challenge Sampling`
- `ERTC-6. Active-Set Equality`
- `ERTC-7. Signature Encoding and Verification`
- `ERTC-8. Epsilon Final Form`
- `ERTC-9. Code Crosswalk`
- `ERTC-10. Acceptance Criteria`
- `ERTC-11. Non-Claims`
- `ERTC-12. Manifest Anchors`
- `Theorem R-close-rejection-predicate`
- `Reject_T`
- `Reject_0`
- `eps_bound_encoding`
- `eps_lowbits_decomposition`
- `eps_ct0_reconstruction`
- `eps_hint_encoding`
- `eps_challenge_encoding`
- `eps_active_set_mismatch`
- `eps_signature_encoding`
- `eps_verify_mismatch`
- `eps_verify`
- `implementation evidence is not cryptographic proof`
- `not a completed rejection-predicate proof`
- `not production-ready`
