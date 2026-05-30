# Rejection Predicate Equivalence Worksheet
<a id="rejection-predicate-equivalence"></a>

Date: 2026-05-27

Status: conservative proof worksheet. This file states the intended
`eps_rej` predicate-equivalence theorem and the evidence needed to prove it;
it does not claim that the equivalence is fully proven.

This worksheet refines the H4 -> H5 route in
[`rejection-sampling-hybrid-proof.md`](rejection-sampling-hybrid-proof.md) and
the `eps_rej` term in
[`rejection-sampling-bounds.md`](rejection-sampling-bounds.md). It is scoped to
the rejection predicate only. Mask distribution, selective aborts, retry
conditioning, commitment binding, and random-oracle programming remain separate
proof obligations unless explicitly listed as predicate bad events below.

The focused theorem-closure batch for this route is
[eps-rej-theorem-closure.md](eps-rej-theorem-closure.md).

## Theorem Target
<a id="rpe-theorem-target"></a>

Target theorem for `eps_rej`:

```text
For one fixed reconstructed signing candidate with the same public key, mu,
active set, aggregate mask transcript, challenge seed c_tilde, challenge
polynomial c = SampleInBall(c_tilde), aggregate response z, low-bit candidate
r0 = LowBits(w - c*s2), ct0 = c*t0, and hint h:

  Reject_T(pk, mu, A, transcript, c_tilde, c, z, r0, ct0, h)
    =
  Reject_0(pk, mu, c_tilde, c, z, r0, ct0, h)

except on explicitly enumerated bad events.
```

The intended bound shape is:

```text
eps_rej
  = Delta(1[Reject_T], 1[Reject_0])
 <= Pr[B_bound_encoding
       or B_lowbits_decomposition
       or B_ct0_reconstruction
       or B_hint_encoding
       or B_challenge_encoding
       or B_active_set_mismatch
       or B_signature_encoding
       or B_verify_mismatch]
```

The zero-bad-event specialization may be asserted only after every bad event is
proved impossible or assigned a concrete negligible bound. Until then,
`eps_rej` remains symbolic.

## Non-Claims
<a id="rpe-non-claims"></a>

This worksheet does not claim:

- `Reject_T = Reject_0` has been proved for the current code.
- `eps_rej = 0`, negligible, or numerically bounded.
- The aggregate mask distribution matches centralized ML-DSA-65 masking.
- Selective aborts, retry limits, participant-specific abort labels, or
  withholding leakage have been simulated.
- The threshold protocol emits only standard-verifying ML-DSA-65 signatures in
  all production paths.
- Current tests are a substitute for the missing theorem-level byte, algebra,
  and boundary proofs.

## Predicate Map
<a id="rpe-predicate-map"></a>

The centralized predicate should be read as the ML-DSA-65 signing rejection
predicate over the same candidate values:

```text
Reject_0 =
    (c != SampleInBall(c_tilde))
 or (weight(c) != tau_65)
 or (||z||_inf >= gamma1_65 - beta_65)
 or (||LowBits(w - c*s2)||_inf >= gamma2_65 - beta_65)
 or (||c*t0||_inf >= gamma2_65)
 or (h != MakeHint(-c*t0, w - c*s2 + c*t0))
 or (weight(h) > omega_65)
 or (Encode(c_tilde, z, h) is noncanonical)
```

The threshold predicate currently suggested by the hazmat finalization path is:

```text
Reject_T =
    (secret.challenge != H_c(mu, masking.w1))
 or (||masking.y + secret.cs1||_inf >= MLDSA65_Z_NORM_BOUND)
 or (||LowBits(masking.w - secret.cs2)||_inf
        >= MLDSA65_GAMMA2 - MLDSA65_BETA)
 or (||secret.ct0||_inf >= MLDSA65_GAMMA2)
 or (MakeHint(-secret.ct0, masking.w - secret.cs2 + secret.ct0)
        cannot be encoded canonically)
 or (weight(h) > MLDSA65_OMEGA)
 or (pack_signature(secret.challenge, z, h) fails)
```

The proof must justify the following exact map before using the predicates
interchangeably:

| Centralized object | Threshold-code object | Required equality or condition |
| --- | --- | --- |
| `c_tilde` | `secret.challenge` and `H_c(mu, masking.w1)` | The challenge seed used in the threshold transcript is exactly the standard challenge seed for the candidate high bits. |
| `c = SampleInBall(c_tilde)` | `sample_in_ball(secret.challenge)` | The sampler is the FIPS 204 challenge sampler and always yields weight `tau_65`. |
| `z = y + c*s1` | `masking.y + secret.cs1` after centered conversion | Reconstruction and centering are bit-for-bit equal to the centralized `z` candidate. |
| `LowBits(w - c*s2)` | `low_bits_vector_k(masking.w - secret.cs2)` | The aggregate `w` and reconstructed `cs2` are the centralized values and use the same decomposition. |
| `c*t0` | `secret.ct0` | The threshold secret contribution equals the centralized `c*t0` term with the same active set and coefficient representation. |
| `h = MakeHint(-c*t0, w - c*s2 + c*t0)` | `hint_vector_from_make_hint(-secret.ct0, masking.w - secret.cs2 + secret.ct0)` | `make_hint` and canonical hint-vector construction match the standard predicate. |
| `Encode(c_tilde, z, h)` | `pack_signature(secret.challenge, z, h)` | Signature packing is canonical and rejects or excludes every malformed hint representation. |
| Verifier reconstruction of `w1` | `unpack_signature`, `compute_verification_w1`, `use_hint` | Accepted signatures reconstruct the same `w1` that was used to derive `c_tilde`, or any mismatch is charged to `B_verify_mismatch`. |

## Bad Event Decomposition
<a id="rpe-bad-events"></a>

The equivalence proof should decompose all remaining gaps into named events:

| Event | Meaning | Current status |
| --- | --- | --- |
| `B_bound_encoding` | A norm check uses a different centered representative, strictness convention, dimension coverage, or bound than ML-DSA-65. | Open. Code evidence shows strict `>=` rejection for `z`, low bits, and `ct0`, but the full representation proof is missing. |
| `B_lowbits_decomposition` | `low_bits` or decomposition in the threshold path differs from the centralized ML-DSA value on any coefficient. | Open. Needs a coefficient-level proof for `masking.w - secret.cs2`. |
| `B_ct0_reconstruction` | `secret.ct0` is not exactly the centralized `c*t0` for the same active set and key material. | Open. Depends on active-set and reconstruction proofs outside this file. |
| `B_hint_encoding` | `MakeHint`, hint ordering, offsets, unused slots, or hint weight differ between threshold and standard encodings. | Open. Code has canonical hint construction and unpacking checks, but the theorem is not closed. |
| `B_challenge_encoding` | The challenge seed, challenge sampler, or challenge-weight condition differs from FIPS 204. | Open. `sample_in_ball` is present; the FIPS-level sampler proof and challenge-input proof remain. |
| `B_active_set_mismatch` | Different active sets are used for `cs1`, `cs2`, `ct0`, mask aggregation, or transcript challenge derivation. | Open. Must be tied to session and contribution validation. |
| `B_signature_encoding` | `pack_signature` emits bytes that standard `unpack_signature` or an external ML-DSA verifier would reject, or vice versa. | Open. Needs byte-level round-trip and canonicality proof. |
| `B_verify_mismatch` | The aggregate predicate accepts a signature whose standard ML-DSA-65 verification predicate rejects. | Open. May be set to zero only after final-wire verification equivalence is proved. |

## Code-to-FIPS/Test Crosswalk
<a id="rpe-code-fips-crosswalk"></a>

| Predicate component | Code reference | FIPS/proof obligation | Test/evidence status |
| --- | --- | --- | --- |
| Challenge consistency | `src/low_level/mldsa65.rs::finalize_mldsa65_threshold_response` checks `secret.challenge == compute_challenge_from_mu(mu, masking.w1)`. | Prove this is the same challenge input used by ML-DSA-65 for the candidate signature theorem statement. | Existing rejection-sampling docs cite stale-challenge and internal-`mu` coverage; this worksheet does not treat that as complete proof. |
| `z` rejection | `finalize_mldsa65_threshold_response` computes `z = masking.y + secret.cs1` and rejects `vector_l_infinity_norm_mod_q(&z) >= MLDSA65_Z_NORM_BOUND`. | Prove `MLDSA65_Z_NORM_BOUND = gamma1_65 - beta_65`, centered conversion matches FIPS, and all `l` polynomials are covered. | Evidence only; boundary and representation proof remain. |
| Low-bit rejection | `finalize_mldsa65_threshold_signature_attempt` computes `low_bits_vector_k(masking.w - secret.cs2)` and rejects `>= MLDSA65_GAMMA2 - MLDSA65_BETA`. | Prove the low-bit decomposition and aggregate algebra match centralized `LowBits(w - c*s2)`. | Evidence only; coefficient-level equivalence remains. |
| `ct0` rejection | `finalize_mldsa65_threshold_signature_attempt` rejects `vector_k_infinity_norm_mod_q(&secret.ct0) >= MLDSA65_GAMMA2`. | Prove `secret.ct0` is exactly centralized `c*t0` for the same active set and representation. | Evidence only; reconstruction proof remains. |
| Hint predicate and weight | `hint_vector_from_make_hint`, `make_hint`, and `finalize_mldsa65_threshold_signature_attempt` build hints and reject `hint.weight() > MLDSA65_OMEGA`. | Prove `make_hint/use_hint` match FIPS 204 and that `omega_65` ordering, offsets, and unused slots are canonical. | Evidence only; malformed-boundary proof remains. |
| Signature encoding | `pack_signature` encodes `c_tilde`, `z`, and `h`; `unpack_signature` decodes and validates hint structure. | Prove encoded threshold signatures are exactly standard ML-DSA-65 signatures for accepted candidates. | Evidence only; full round-trip and external verifier equivalence remain. |
| Verification high bits | `compute_verification_w1`, `sample_in_ball`, and `use_hint` reconstruct verifier-side `w1`. | Prove reconstructed `w1` equals the signing-side `masking.w1` used in the challenge, or account for mismatch in `eps_rej`. | Evidence only; final-wire verification theorem remains open. |

Tests should be used as regression evidence for these rows, not as theorem
closure. Any future test references should name the exact fixture and the bad
event it excludes.

## Remaining Proof Blockers

1. Cite the normative ML-DSA-65/FIPS 204 predicate and parameters used for
   `gamma1_65`, `gamma2_65`, `beta_65`, `tau_65`, and `omega_65`.
2. Prove byte-level challenge-domain equality between the threshold transcript
   and the centralized challenge seed.
3. Prove coefficient-level equality for reconstructed `z`, `LowBits(w-c*s2)`,
   and `c*t0` under the same active set.
4. Prove strict inequality and centered-representative equivalence at every
   rejection boundary.
5. Prove hint canonicality: ordering, offsets, unused slots, weight, and
   `MakeHint`/`UseHint` compatibility.
6. Prove `pack_signature`/`unpack_signature` canonical round-trip equivalence
   for every accepted threshold candidate.
7. Decide whether standard verification is part of `Reject_T` or a separate
   `eps_verify` term, then state the accounting without double-counting.
8. Connect this predicate-only theorem back to the H4 -> H5 hybrid without
   absorbing mask-distribution, retry, or selective-abort losses into
   `eps_rej`.

Until these blockers are discharged, `rejection-predicate-equivalence` remains
a worksheet and not a completed proof.
