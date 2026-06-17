# Algebraic Correctness Lemmas for Threshold ML-DSA-65 Scaffold

Date: 2026-05-27

## Scope

This note states the algebraic correctness obligations for the current
threshold ML-DSA-65 scaffold. It is a proof plan, not a completed security
proof.

The available implementation evidence is:

- `src/crypto/interpolation.rs`
- `src/crypto/vss.rs`
- `src/low_level/poly.rs`
- `src/backend.rs`
- `src/aggregation.rs`
- `src/transcript.rs`
- `src/collections.rs`
- `docs/cryptography/phase-1-noise-bound-model.md`

The following requested inputs were not present in this checkout at the time of
writing: `src/low_level/mldsa65.rs`,
`tests/hazmat_mldsa65_threshold_bridge.rs`,
`docs/cryptography/noise-bound-proof-outline.md`, and
`docs/cryptography/threshold-mldsa-protocol-spec.md`. Lemmas that depend on
those missing artifacts are stated as obligations for a future real backend.

## Notation

Let `q = 8_380_417`, matching `Q` in `src/low_level/poly.rs`. Let
`F = Z_q`. Since `q` is prime, `F` is a field. Let
`R_q = F[X] / (X^256 + 1)`. A `Poly` value represents an element of `R_q` by
its 256 coefficients.

For a threshold `t`, let participant identifiers be nonzero, pairwise distinct
field elements `x_i in F`. In the implementation these are one-based `u16`
indices converted into `F`. For an active set `A` with `|A| >= t`, define the
Lagrange coefficient at zero:

```text
lambda_i(A) = product_{j in A, j != i} x_j / (x_j - x_i) mod q.
```

Division means multiplication by the field inverse in `F`.

## Lemma 1: Field Inversion Soundness

Statement: For every nonzero `a in F`, `modular_inverse(a)` returns `a^{-1}`
such that:

```text
a * modular_inverse(a) = 1 mod q.
```

Required preconditions:

- `q` is prime.
- `a != 0 mod q`.
- The input is interpreted canonically modulo `q`.

Implementation mapping: `interpolation::modular_inverse` computes
`a^(q - 2) mod q`. By Fermat's little theorem, this equals `a^{-1}` for
nonzero `a`.

Remaining proof work:

- Show all callers only request inverses of nonzero denominators.
- Replace timing comments with a real constant-time analysis before production
use.

## Lemma 2: Lagrange Basis at Zero

Statement: Let `A` be a set of pairwise distinct nonzero participant indices.
For each `i in A`, `compute_lagrange_coefficient(A, i)` returns
`lambda_i(A)`. For every polynomial `f(Y) in F[Y]` with
`degree(f) < |A|`:

```text
sum_{i in A} lambda_i(A) * f(x_i) = f(0) mod q.
```

Required preconditions:

- Each `x_i` is nonzero in `F`.
- The `x_i` values are pairwise distinct modulo `q`.
- `|A| < q`, which is immediate for `u16` validator indices.

Implementation mapping: `interpolation::compute_lagrange_coefficient`
implements the product formula above.

Remaining proof work:

- Enforce uniqueness of active interpolation indices at the function boundary
  or prove all callers provide canonical duplicate-free sets.
- Enforce `current_index in A`; otherwise the function computes a product that
  has no reconstruction meaning.

## Lemma 3: Coefficient-Lane Shamir Reconstruction over `R_q`

Statement: Let `P(Y) = a_0 + a_1 Y + ... + a_{t-1} Y^{t-1}` where each
`a_k in R_q`. Let shares be `s_i = P(x_i)` for each `i in A`, computed
coefficient-wise over `F`. If `|A| >= t` and the identifiers in `A` are
pairwise distinct and nonzero, then:

```text
sum_{i in A} lambda_i(A) * s_i = a_0 in R_q.
```

Equivalently, for every coefficient lane `ell`:

```text
sum_{i in A} lambda_i(A) * s_i[ell] = a_0[ell] mod q.
```

Implementation mapping:

- `vss::evaluate_polynomial_at` evaluates `P(x_i)` with Horner's method in each
  coefficient lane.
- `interpolation::reconstruct_secret_poly` scales each share by
  `lambda_i(A)` and adds the scaled polynomials modulo `q`.

Remaining proof work:

- Add a proof that `Poly::add_assign` is correct for canonical inputs in
  `[0, q)`.
- Add input validation for duplicate active shares and malformed indices, or
  prove such inputs are rejected before this layer.
- Replace deterministic test masks in `split_secret_poly` with sampled masks
  for any privacy claim.

## Lemma 4: Canonical Collection Determinism

Statement: For any valid validator universe `V`, threshold `t`, and network
multiset of commitments or partial shares with no duplicate validator IDs and
at least `t` entries from `V`, `CommitmentSet::new` and `PartialShareSet::new`
produce a canonical order independent of network arrival order.

Required preconditions:

- `0 < t <= |V|`.
- Validator IDs are unique in `V`.
- Each submitted commitment or partial share is attributed to a member of `V`.

Implementation mapping: `collections.rs` stores validators in `BTreeSet` and
submitted data in `BTreeMap`, then iteration occurs in key order.

Remaining proof work:

- Define canonical validator ID serialization as part of the wire protocol.
- Prove all transcript and aggregation hash inputs use the canonical iterator.

## Lemma 5: Transcript Challenge Binding

Statement: If `SigningTranscript::new` succeeds, its challenge is a
deterministic function of exactly:

```text
protocol label,
protocol version,
session ID,
threshold,
canonical validator set,
public key,
message,
canonical commitment set.
```

Consequently, any change to one of those encoded fields changes the random
oracle input.

Implementation mapping: `transcript::derive_challenge` hashes those fields in
that order with fixed-size encodings for scalar fields and a message length
prefix.

Remaining proof work:

- Specify domain separation and encoding collision resistance in the protocol
  spec.
- Prove the commitment set supplied to the transcript is the same set used by
  all partial-signing participants.

## Lemma 6: Threshold Response Aggregation Correctness

Statement for a real ML-DSA-65 threshold backend: Let each honest participant
`i in A` hold Shamir share `s_i` of the signing secret `s`. For a common
transcript-derived challenge `c` and committed local mask share `y_i`, suppose
the partial response has algebraic form:

```text
z_i = y_i + c * s_i
```

or the backend-specific equivalent in the ML-DSA module/module-vector domain.
If the aggregator computes:

```text
z = sum_{i in A} lambda_i(A) * z_i,
y = sum_{i in A} lambda_i(A) * y_i,
s = sum_{i in A} lambda_i(A) * s_i,
```

then:

```text
z = y + c * s.
```

Required preconditions:

- All partial shares bind to the same transcript and challenge.
- The active signer set used for `lambda_i(A)` is exactly the set aggregated.
- Partial-share verification proves each `z_i` matches the committed `y_i` and
  secret-share commitment.
- All arithmetic is in the same ML-DSA ring/module representation.

Implementation mapping: The current `SimulatedBackend` does not implement this
algebra; it hashes partial-share bytes into deterministic test signatures. This
lemma is therefore a requirement for the missing real backend.

Remaining proof work:

- Specify the exact ML-DSA-65 module dimensions, NTT/coefficient-domain
  conventions, and share encoding.
- Prove partial-share verification against commitments.
- Prove aggregation uses the same active set for all module/vector components.

## Lemma 7: Standard ML-DSA Verification Compatibility

Statement for a real ML-DSA-65 threshold backend: If all accepted partial
responses satisfy their local verification equations and rejection checks, and
if aggregation constructs `(c, z, h)` exactly as single-signer ML-DSA-65 would
construct it for public key `pk` and message `m`, then the standard ML-DSA-65
verification algorithm accepts the aggregate signature:

```text
MLDSA65.Verify(pk, m, sigma) = accept.
```

Required preconditions:

- The transcript challenge is bit-for-bit equal to the challenge derived by the
  standard ML-DSA verifier from the reconstructed verifier inputs.
- The aggregate `z` and hint `h` satisfy the ML-DSA-65 norm and hint bounds.
- Public key encoding and signature encoding are standard ML-DSA-65 encodings.
- No threshold-only metadata appears in the final standard signature.

Implementation mapping: `Mldsa65Backend::verify_standard` is part of the
backend contract, but `SimulatedBackend::verify_standard` returns
`BackendUnavailable`.

Remaining proof work:

- Implement or bind to a real standard ML-DSA-65 verifier.
- Add a bridge test showing threshold aggregate signatures verify under that
  standard verifier.
- Prove threshold transcript derivation yields the same challenge bytes as the
  standard signature format requires, or specify a compatible construction that
  makes it so.

## Lemma 8: Infinity-Norm Bound Preservation under Accepted Aggregation

Statement for a real ML-DSA-65 threshold backend: Let the aggregate response be
`z = y + c * s`. If the protocol's rejection predicate accepts only executions
where:

```text
||z||_inf < B_z
```

and where all hint and challenge bounds required by ML-DSA-65 hold, then the
final aggregate signature satisfies the standard verifier's norm predicates.

Required preconditions:

- The aggregate check is performed on the aggregate response actually encoded
  in the final signature.
- Centered coefficient interpretation is used for norm checks.
- The bound `B_z` is the ML-DSA-65 bound for the selected parameter set.

Implementation mapping: `Poly::check_noise_bounds` checks a single polynomial's
centered coefficient magnitudes against a caller-supplied bound. It is not a
complete ML-DSA-65 norm proof.

Remaining proof work:

- Define the exact ML-DSA-65 `gamma1`, `gamma2`, `beta`, `omega`, and response
  bounds used by the backend.
- Extend the scalar `Poly` check to module/vector response and hint checks.
- Prove all accepted aggregate signatures pass the standard verifier's bound
  checks.

## Summary of Current Status

Implemented and test-scaffolded:

- Coefficient-lane polynomial arithmetic over modulus `q`.
- Shamir-style polynomial evaluation over `R_q`.
- Lagrange reconstruction at zero for polynomial shares.
- Canonical commitment and partial-share collection ordering.
- Transcript binding for the simulation API.

Not implemented or not proven:

- Production-random VSS masks and commitments.
- Real ML-DSA-65 partial-share equations.
- Real threshold aggregation into standard ML-DSA signatures.
- Standard verifier compatibility.
- Rejection-sampling distribution preservation.
- Constant-time and side-channel guarantees.
