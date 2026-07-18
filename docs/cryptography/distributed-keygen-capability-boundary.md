# Distributed Key-Generation Capability Boundary

Status: implementation capability record for the first FIPS public-key
derivation batch. This is not a distributed key-generation proof, theorem
promotion, production-security claim, or audit result.

Date: 2026-07-18

## Purpose

The no-single-holder protocol requires more than producing the ordinary
ML-DSA-65 public-key bytes. Section PS-4 of
[`threshold-mldsa-protocol-spec.md`](threshold-mldsa-protocol-spec.md) requires
an exact joint secret distribution, private persistent signing state, and a
malicious-secure DKG realization. This document separates those requirements
so a public-output implementation increment cannot be mistaken for complete
distributed key generation.

## Implemented Public-Output Increment

The batch adds an engineering path for deriving the exact 1,952-byte
ML-DSA-65 public key from **supplied module-secret shares**. For a public
context containing `rho` and a caller-supplied ceremony digest, each
participant-side computation forms a public contribution to

```text
t = A(rho) * s1 + s2
```

using the exact FIPS arithmetic path. The aggregator combines a complete set
of public `t` contributions, applies exact `Power2Round` to the combined `t`,
and encodes `pk = rho || t1` using the standard ML-DSA-65 encoding. Depending
on the input sharing mode, contribution combination is either additive or
Shamir interpolation at zero. Every contribution and the aggregate are bound
to the exact same context; mismatched ceremony digests fail closed.

This capability is valuable conformance evidence: when supplied shares encode
the same `s1` and `s2` as a centralized reference fixture, the resulting public
key can be compared byte-for-byte with that reference. It also demonstrates
that computing the public key does not inherently require reconstructing `s1`
or `s2` at the aggregator.

The implementation is
[`src/crypto/fips_public_key.rs`](../../src/crypto/fips_public_key.rs). Its
fixed-seed, additive-share, Shamir-subset, malformed-input, and rounding-order
checks are in
[`tests/fips_keygen_conformance.rs`](../../tests/fips_keygen_conformance.rs).
The separate in-process encrypted receiver-custody seam is implemented in
[`src/crypto/receiver_custody.rs`](../../src/crypto/receiver_custody.rs), with
functional failure tests in
[`tests/receiver_custody.rs`](../../tests/receiver_custody.rs) and
[`tests/receiver_custody_adversarial.rs`](../../tests/receiver_custody_adversarial.rs).

The capability is intentionally named **exact public-key derivation from
supplied shares**, not exact distributed key generation. Its inputs are an
assumption supplied by the caller. Fixed-seed tests that obtain those inputs
from the repository's centralized `keygen_from_seed` routine are conformance
fixtures only.

## Capability Split

| Capability | Batch state | Exact boundary |
| --- | --- | --- |
| FIPS `ExpandA` and public-key arithmetic | implemented engineering guard | Exact public `A(rho)`, module arithmetic, `Power2Round`, and 1,952-byte encoding are exercised from supplied shares. |
| Exact public-key bytes from supplied shares | implemented engineering guard | The output `pk` matches the centralized ML-DSA-65 provider byte-for-byte for the fixed-seed additive and Shamir conformance fixtures; this says nothing about how production shares are sampled or delivered. |
| Ceremony-context equality enforcement | implemented engineering guard | Each public contribution binds `rho` and a caller-supplied ceremony digest; aggregation rejects a context mismatch. |
| Ceremony construction and authentication | open | This component does not construct or authenticate the epoch, validator set, threshold, accepted-commitment, and protocol-version transcript represented by the opaque digest. |
| Exact joint `ExpandS` / secret sampling | open | No protocol jointly derives `rho_prime`, `s1`, or `s2` with the exact FIPS distribution while keeping them shared. Additive independently sampled dealer secrets are not automatically the `ExpandS` distribution. |
| Joint unbiasable `rho` generation | open | The public-key derivation accepts caller-supplied `rho`; it does not provide a coin-toss or MPC protocol preventing last-mover bias. |
| Distributed secret `K` generation | open | The FIPS signing seed `K` is not generated or retained in shares by this public-output path. |
| Retained `t0` signing state | open | The current public-output path derives and returns exact `t0`, but it does not bind retained public or authenticated shared `t0` state into the finalized epoch and signing protocol. |
| Encrypted receiver-custody seam | implemented engineering guard | A dealer-side API consumes the clear sharing, uses a separately provisioned key for each `(dealer, receiver)` pair, emits only context-, dealer-, commitment-, and receiver-bound authenticated ciphertext bundles to coordinator-facing code, and a receiver-pinned vault verifies decrypted shares before retention. |
| Production PQ private-share transport | open | The seam uses the PSK-based SHAKE256 reference transport; it is not ML-KEM key exchange, a reviewed production AEAD, or forward-secure transport. |
| Process-isolated per-receiver custody | open | An in-process API and test fixtures do not show that each validator alone holds its share, that temporary inputs are erased, or that crash/debug paths cannot expose them. |
| Persistent replay and sequence state | open | Accepted-envelope memory is in process only; restart-safe ceremony/dealer sequence storage and rollback resistance are not implemented. |
| Malicious-secure DKG proof | open | Binding, hiding, extractability, public/secret consistency, complaint soundness, anti-framing, agreement, robustness, and key-bias proofs remain incomplete. |
| VSS, shortness, and public/secret relation proofs | open | The derivation trusts supplied module shares and public contributions; it does not prove that they are short, correctly distributed, commitment-bound, or computed from the committed secrets. |
| Authenticated complaint and recovery | open | Pairwise-PSK frame authentication exists, but there are no signed public dealer frames, non-repudiable complaints, or complete exclusion and recovery protocol. |
| Shared signing state | open | Exact shared `K` and `tr`, plus epoch-bound retained `t0` state required by `Sign_internal`, are not produced. |
| Exact distributed ML-DSA-65 key generation | open | This umbrella capability remains false until all secret-sampling, custody, consistency, signing-state, and proof requirements close together. |

## Why Public `t` Is a Boundary

`Power2Round` is nonlinear because of coefficient carries. Implementations
must combine contributions into `t` before rounding; summing dealer-local
`t1` values is not equivalent to `Power2Round(sum(t_d))`.

The public-output batch therefore makes combined `t` available to the
aggregator before exact rounding and reveals the corresponding `t0`. This is
permitted by the selected model because [FIPS 204 Section
6.1](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) does not require
the low bits of `t` to remain secret. It does not reveal `s1` or `s2` merely by
construction.

The remaining boundary is state and proof, not `t0` secrecy: the current path
does not bind exact retained `t0` state into the finalized epoch or signing
protocol, prove that supplied shares came from the required distribution, or
prove the public contributions consistent with accepted VSS commitments. It
must not be wired into signing as though those requirements were met.

The encrypted receiver-custody seam is similarly narrower than process
isolation. It keeps coordinator-facing bundle types free of plaintext shares
and gives each in-process vault only one receiver's verified material, but the
dealer necessarily sees clear shares before sealing. The API cannot prove that
memory was never copied, that callbacks did not retain a receiver share, or
that separate processes or HSMs enforce the boundary. Its pre-shared-key
SHAKE256 transport also assumes key establishment and nonce uniqueness outside
the seam. Its MAC authenticates frames only under the provisioned pairwise
dealer key; it is not a signed public dealer identity or a complete complaint
and recovery protocol. Replay detection is also memory-local and does not
survive process restart or storage rollback.

## Non-Promotion Rule

This increment is an `engineering_guard_only` result. It does not promote any
of the five hypothesis criteria and does not discharge FST-T1, FST-T2, or
FST-L1 through FST-L9. In particular:

- `partial_contribution_soundness` remains `partially_met` because the DKG
  binding, hiding, consistency, custody, and leakage obligations are open;
- `aggregate_rejection_equivalence` remains `partially_met` because no real
  partial response, hint, rejection, or signature output is produced; and
- `unauthorized_aggregate_reduction` remains `partially_met` because there is
  no malicious-secure DKG reduction, simulator, or threshold EUF-CMA proof.

The umbrella capability `fips204_exact_distributed_key_generation`, the claim
`claims_no_single_holder_threshold_signing`, and every theorem-closure claim
remain false.

## Promotion Requirements

The key-generation stage can be promoted beyond this public-output engineering
guard only after one digest-bound implementation and proof package supplies:

1. exact joint derivation of `rho`, `rho_prime`, `K`, `s1`, and `s2`, or a
   reviewed distribution-equivalent DKG;
2. authenticated encrypted share delivery and process-isolated receiver
   custody with erasure and rollback rules;
3. exact retained `t0` signing state, publicly epoch-bound or authenticated in
   shares, with the representation used by `Sign_internal` specified;
4. public/secret consistency and shortness proofs for every accepted dealer or
   input share;
5. malicious-secure VSS/DKG proofs covering agreement, robustness,
   extractability, complaints, anti-framing, and key bias;
6. exact shared signing state bound to the finalized epoch; and
7. adversarial and differential evidence tied to the selected protocol and
   proof parameters.

Until all seven exist, campaign manifests and closure assessors must treat the
key-generation gate as open.
