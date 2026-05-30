# eps_rej Predicate Sublemma Route
<a id="eps-rej-predicate-sublemma-route"></a>

Status: predicate-equivalence roadmap for eps_rej, not a completed proof of
predicate equality.

This document decomposes the same-candidate rejection-predicate obligation
from `eps-rej-theorem-closure.md` into reviewable sublemmas. It is a route for
proving where `Reject_T` and `Reject_0` can differ; it does not prove that the
difference is zero or negligible.

## R1-0. Objects and Boundary
<a id="r1-objects-boundary"></a>

Candidate tuple:

```text
(z, c, h, w1, mu, pk)
```

where:

- `z` is the response vector decoded with the ML-DSA-65 centered
  representative convention.
- `c` is the challenge polynomial sampled from the challenge seed and checked
  with the ML-DSA-65 challenge weight.
- `h` is the hint vector with canonical ordering and weight constraints.
- `w1` is the verifier-facing high-bit reconstruction value.
- `mu` is the message representative used in challenge and verifier inputs.
- `pk` is the public key byte string and decoded public key used by the
  standard verifier path.

Active set:

```text
T
```

is the exact participant set whose commitments, contribution validations,
partial responses, reconstructed `cs1`, reconstructed `cs2`, reconstructed
`ct0`, aggregate rejection checks, signature release, and evidence records are
claimed to define the same candidate tuple.

Predicates:

```text
Reject_T(z, c, h, w1, mu, pk, T)
```

is the threshold aggregate rejection predicate evaluated on the fixed candidate
and active set.

```text
Reject_0(z, c, h, w1, mu, pk)
```

is the centralized ML-DSA-65 rejection predicate evaluated on the same decoded
candidate and public inputs.

Byte-encoding boundary: the comparison is made at the boundary where decoded
threshold objects are serialized into the byte strings consumed by
ML-DSA-65-style challenge derivation, signature packing, and verification.
Any mismatch between algebraic objects and their canonical byte encodings must
remain visible in the residual accounting below.

## R1-1. Theorem Target
<a id="r1-theorem-target"></a>

```text
Theorem R1-reject-predicate-equivalence.
For one fixed candidate tuple (z, c, h, w1, mu, pk) and one fixed active set T,
the event Reject_T(z, c, h, w1, mu, pk, T) != Reject_0(z, c, h, w1, mu, pk)
is contained in the union of the visible residual subterms:

eps_bound_encoding
eps_lowbits_decomposition
eps_ct0_reconstruction
eps_hint_encoding
eps_challenge_encoding
eps_active_set_mismatch
eps_signature_encoding
eps_verify_mismatch.
```

The intended final shape is an inclusion or epsilon bound, not an unstated
equality proof:

```text
Pr[Reject_T != Reject_0]
 <= eps_bound_encoding
  + eps_lowbits_decomposition
  + eps_ct0_reconstruction
  + eps_hint_encoding
  + eps_challenge_encoding
  + eps_active_set_mismatch
  + eps_signature_encoding
  + eps_verify_mismatch.
```

## R1-2. Visible Residual Subterms
<a id="r1-visible-residual-subterms"></a>

`eps_bound_encoding` covers strictness, centered representative, coefficient
range, module dimension, norm-bound, challenge weight, hint weight, and
byte-decoding boundary differences for the fixed tuple.

`eps_lowbits_decomposition` covers any mismatch between threshold reconstructed
low bits and centralized `LowBits(w - c*s2)` for the same candidate.

`eps_ct0_reconstruction` covers any mismatch between threshold reconstructed
`ct0` and centralized `c*t0`, including coefficient ordering and ring/module
interpretation.

`eps_hint_encoding` covers `h` canonicality, hint ordering, offset encoding,
unused slots, malformed hint rejection, `MakeHint` compatibility, and `UseHint`
compatibility.

`eps_challenge_encoding` covers challenge seed input construction,
`SampleInBall`, challenge weight, challenge polynomial encoding, and equality
between the threshold challenge bytes and the standard verifier challenge
bytes.

`eps_active_set_mismatch` covers any disagreement about which participant set
defines commitments, challenge derivation, contribution validation,
reconstruction, aggregate rejection, signature release, or evidence records.

`eps_signature_encoding` covers final signature packing and unpacking:

```text
sigma = Encode(c_tilde, z, h)
```

including canonical byte length, rejection of malformed encodings, and equality
between the threshold-produced wire signature and the standard ML-DSA-65
signature object.

`eps_verify_mismatch` covers any residual gap between aggregate acceptance and
the unmodified standard verifier predicate:

```text
MLDSA65.Verify(pk, mu, sigma)
```

or the exact verifier-input variant chosen by the enclosing theorem.

## R1-3. Sublemma Route
<a id="r1-sublemma-route"></a>

The route should be reviewed as separate obligations:

```text
Lemma R1.1-bound-encoding.
Outside eps_bound_encoding, Reject_T and Reject_0 use identical centered
representatives, dimensions, strict inequalities, and bound encodings.

Lemma R1.2-lowbits-decomposition.
Outside eps_lowbits_decomposition, the low-bit value consumed by Reject_T is
coefficientwise equal to the centralized LowBits(w - c*s2) value.

Lemma R1.3-ct0-reconstruction.
Outside eps_ct0_reconstruction, the threshold ct0 value is coefficientwise
equal to centralized c*t0 under the same ring and module interpretation.

Lemma R1.4-hint-encoding.
Outside eps_hint_encoding, h is exactly the canonical hint object accepted by
the centralized predicate and by the verifier UseHint path.

Lemma R1.5-challenge-encoding.
Outside eps_challenge_encoding, c and its seed/input bytes are exactly the
ML-DSA-65 challenge value for the fixed tuple.

Lemma R1.6-active-set-consistency.
Outside eps_active_set_mismatch, every threshold predicate component is bound
to the same active set T.

Lemma R1.7-signature-encoding.
Outside eps_signature_encoding, the released signature bytes decode to the
same (c_tilde, z, h) object used by the predicate comparison.

Lemma R1.8-verifier-compatibility.
Outside eps_verify_mismatch, aggregate acceptance implies the same standard
verifier decision as the centralized ML-DSA-65 verification path.
```

The theorem target should then combine the sublemmas by a union bound or by a
deterministic containment argument over the displayed residual events.

## R1-4. Open Verification Accounting
<a id="r1-open-verification-accounting"></a>

The route intentionally leaves the `eps_verify_mismatch` accounting decision
open.

One possible closure is to fold `eps_verify_mismatch` into `eps_rej` if the
rejection predicate is defined to include unmodified standard ML-DSA-65
verification, and if the proof shows that aggregate acceptance is exactly the
same predicate over the same `(pk, mu, sigma)` bytes.

The conservative closure is to keep `eps_verify_mismatch` as `eps_verify`.
That is required if verifier compatibility depends on a later theorem, a
different input convention, a message-vs-`mu` boundary, signature decoding
semantics not yet proved equivalent, or any implementation-only evidence.

This document does not choose between those closures.

## R1-5. Acceptance Criteria
<a id="r1-acceptance-criteria"></a>

This slice is acceptable only if it:

- states that it is a predicate-equivalence roadmap, not a completed proof;
- defines `Reject_T`, `Reject_0`, `(z, c, h, w1, mu, pk)`, `T`, and the
  byte-encoding boundary;
- names `Theorem R1-reject-predicate-equivalence`;
- keeps all residual subterms visible:
  `eps_bound_encoding`, `eps_lowbits_decomposition`,
  `eps_ct0_reconstruction`, `eps_hint_encoding`,
  `eps_challenge_encoding`, `eps_active_set_mismatch`,
  `eps_signature_encoding`, and `eps_verify_mismatch`;
- discusses whether `eps_verify_mismatch` can be folded into `eps_rej` or must
  remain as `eps_verify`;
- avoids any statement that the predicate equality has been proved.

## R1-6. Non-Claims
<a id="r1-non-claims"></a>

This document does not claim:

- `Reject_T = Reject_0` has been proved;
- no predicate equality proved;
- no negligible claim;
- no zero claim;
- predicate equality is established;
- any residual term is negligible;
- any residual term is zero;
- the route is production-ready;
- not production-ready;
- implementation evidence is not cryptographic proof;
- tests, traces, or verifier fixtures replace byte-level and algebraic proof
  obligations.

## R1-7. Manifest Anchors
<a id="r1-manifest-anchors"></a>

Stable anchors and text markers:

- `# eps_rej Predicate Sublemma Route`
- `eps-rej-predicate-sublemma-route`
- `Status: predicate-equivalence roadmap for eps_rej`
- `R1-0. Objects and Boundary`
- `R1-1. Theorem Target`
- `R1-2. Visible Residual Subterms`
- `R1-3. Sublemma Route`
- `R1-4. Open Verification Accounting`
- `R1-5. Acceptance Criteria`
- `R1-6. Non-Claims`
- `R1-7. Manifest Anchors`
- `Theorem R1-reject-predicate-equivalence`
- `Reject_T`
- `Reject_0`
- `(z, c, h, w1, mu, pk)`
- `T`
- `byte-encoding boundary`
- `eps_bound_encoding`
- `eps_lowbits_decomposition`
- `eps_ct0_reconstruction`
- `eps_hint_encoding`
- `eps_challenge_encoding`
- `eps_active_set_mismatch`
- `eps_signature_encoding`
- `eps_verify_mismatch`
- `eps_verify`
- `predicate-equivalence roadmap`
- `not a completed proof`
- `no predicate equality proved`
- `no negligible claim`
- `no zero claim`
- `not production-ready`
- `implementation evidence is not cryptographic proof`
