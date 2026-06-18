# Algebraic Correctness Lemmas for Threshold ML-DSA-65 Scaffold

Date: 2026-05-27

## Scope

This note states strengthened algebraic correctness obligations for the current
threshold ML-DSA-65 scaffold. It is intentionally closer to a formal proof than
the surrounding implementation crosswalk, but it is still not a completed
security theorem and must not be read as a production-readiness claim.

The current repository contains deterministic simulation paths plus
feature-gated hazmat ML-DSA-65 arithmetic, standard verification surfaces, VSS
soundness checks, and threshold bridge tests. Those artifacts support specific
engineering invariants. They do not prove the full theorem in
`formal-security-theorem.md`, the rejection-sampling distribution obligations in
`noise-rejection-proof-plan.md`, or the production protocol requirements in
`threshold-mldsa-protocol-spec.md`.

The available implementation evidence is:

- `src/crypto/interpolation.rs`
- `src/crypto/vss.rs`
- `src/low_level/poly.rs`
- `src/low_level/mldsa65.rs`
- `src/backend.rs`
- `src/aggregation.rs`
- `src/transcript.rs`
- `src/collections.rs`
- `docs/cryptography/formal-security-theorem.md`
- `docs/cryptography/threshold-mldsa-protocol-spec.md`
- `docs/cryptography/noise-rejection-proof-plan.md`
- `docs/cryptography/proof-implementation-crosswalk.md`
- `tests/hazmat_mldsa65_threshold_bridge.rs`
- `tests/dkg_vss_soundness.rs`

Lemmas that depend on a completed production threshold backend are stated as
conditional obligations even when hazmat tests exercise a production-shaped
path.

## Notation

Let `q = 8_380_417`, matching `Q` in `src/low_level/poly.rs`. Let
`F = Z_q`. Since `q` is prime, `F` is a field. Let
`R_q = F[X] / (X^256 + 1)`. A `Poly` value represents an element of `R_q` by
its 256 coefficient lanes.

For a threshold `t`, let participant identifiers be nonzero, pairwise distinct
field elements `x_i in F`. In the implementation these are one-based `u16`
indices converted into `F`. For an active set `A` with `|A| >= t`, define the
Lagrange coefficient at zero:

```text
lambda_i(A) = product_{j in A, j != i} x_j / (x_j - x_i) mod q.
```

Division means multiplication by the field inverse in `F`. Equalities over
`Poly` values are coefficientwise equalities modulo `q` unless stated
otherwise.

<a id="lemma-field-inversion"></a>

## Lemma 1: Field Inversion Soundness

Statement: For every nonzero `a in F`, `modular_inverse(a)` returns `a^{-1}`
such that:

```text
a * modular_inverse(a) = 1 mod q.
```

Assumptions and preconditions:

- `q = 8_380_417` is prime.
- The caller supplies `a != 0 mod q`.
- The input integer is interpreted by reduction to the canonical representative
  in `[0, q)`.
- Multiplication in the exponentiation loop is performed in a type wide enough
  to avoid overflow before reduction. The implementation uses `i64`, and
  `(q - 1)^2` fits in `i64`.

Proof sketch:

1. `canonical_i64(a)` maps the integer input to the field element `a mod q`.
2. Because `q` is prime and `a != 0`, Fermat's little theorem gives
   `a^(q - 1) = 1 mod q`.
3. Multiplying both sides by `a^{-1}` in `F` gives
   `a^(q - 2) = a^{-1} mod q`.
4. `modular_inverse` is exponentiation by squaring with exponent `q - 2`.
   The standard loop invariant is that the product of the accumulated
   `result` and the remaining powers represented by `factor^exponent` equals
   the original `a^(q - 2)` modulo `q`.
5. When the loop terminates, `exponent = 0`, so `result = a^(q - 2) = a^{-1}`.

Implementation mapping: `interpolation::modular_inverse` computes
`a^(q - 2) mod q` using fixed public exponent `Q - 2`.

Current evidence vs remaining proof:

- Evidence: `interpolation_tests::test_modular_inverse_soundness` checks one
  representative inverse.
- Evidence: checked reconstruction paths reject duplicate and zero indices
  before computing Lagrange denominators.
- Remaining proof: prove all production callers either use checked entry points
  or independently establish nonzero denominators.
- Remaining proof: replace scaffold timing comments with a real constant-time
  analysis before any production claim.

<a id="lemma-lagrange-reconstruction"></a>

## Lemma 2: Lagrange Basis at Zero

Statement: Let `A` be a set of pairwise distinct nonzero participant indices.
For each `i in A`, `compute_lagrange_coefficient(A, i)` returns
`lambda_i(A)`. For every polynomial `f(Y) in F[Y]` with
`degree(f) < |A|`:

```text
sum_{i in A} lambda_i(A) * f(x_i) = f(0) mod q.
```

Assumptions and preconditions:

- Each `x_i` is nonzero in `F`.
- The `x_i` values are pairwise distinct modulo `q`.
- `current_index in A`.
- `|A| < q`; this is immediate for `u16` validator indices.
- The active set supplied to the coefficient computation is exactly the active
  set used for reconstruction.

Proof sketch:

1. For every `i in A`, define the ordinary Lagrange basis polynomial
   `L_i(Y) = product_{j in A, j != i} (Y - x_j) / (x_i - x_j)`.
2. Pairwise distinctness gives `x_i - x_j != 0`, so every denominator is
   invertible by Lemma 1.
3. The basis satisfies `L_i(x_i) = 1` and `L_i(x_j) = 0` for every
   `j in A, j != i`.
4. Evaluating at zero gives
   `L_i(0) = product_{j != i} (-x_j) / (x_i - x_j)`.
   Since each denominator term is also negated,
   `(-x_j)/(x_i - x_j) = x_j/(x_j - x_i)`, so `L_i(0) = lambda_i(A)`.
5. For any `f` with `degree(f) < |A|`, the interpolation polynomial
   `g(Y) = sum_i f(x_i) L_i(Y)` has the same values as `f` on all points in
   `A` and degree less than `|A|`. Uniqueness of interpolation over a field
   implies `g = f`, and evaluating at `Y = 0` gives the statement.

Implementation mapping: `interpolation::compute_lagrange_coefficient`
implements the product formula. The checked reconstruction path uses
`try_compute_lagrange_coefficient` after validating active share indices.

Current evidence vs remaining proof:

- Evidence: `tests/dkg_vss_soundness.rs` covers duplicate, zero, empty, and
  insufficient checked reconstruction inputs, plus successful threshold subset
  reconstruction.
- Evidence: `src/crypto/interpolation.rs` has an end-to-end interpolation unit
  test over deterministic VSS shares.
- Remaining proof: the public unchecked helper still assumes, rather than
  enforces, duplicate-free nonzero indices and `current_index in A`.
- Remaining proof: production aggregation must prove the same active set is
  used consistently for every ML-DSA module component.

<a id="lemma-coefficient-lane-shamir"></a>

## Lemma 3: Coefficient-Lane Shamir Reconstruction over `R_q`

Statement: Let

```text
P(Y) = a_0 + a_1 Y + ... + a_{d} Y^d
```

where `d < t` and each `a_k in R_q`. Let shares be `s_i = P(x_i)` for each
`i in A`, computed coefficientwise over `F`. If `|A| >= t` and the identifiers
in `A` are pairwise distinct and nonzero, then:

```text
sum_{i in A} lambda_i(A) * s_i = a_0 in R_q.
```

Equivalently, for every coefficient lane `ell`:

```text
sum_{i in A} lambda_i(A) * s_i[ell] = a_0[ell] mod q.
```

Assumptions and preconditions:

- The coefficient polynomials have degree in the share variable less than `t`.
- Active shares are indexed by a nonempty duplicate-free set `A` of nonzero
  validator indices.
- `|A| >= t`, and the proof uses any fixed active set supplied to
  interpolation. If `|A| > t`, the degree condition still gives
  `degree(P_ell) < |A|` for every lane.
- `Poly::add_assign` is applied to canonical coefficients in `[0, q)` or to
  values reduced into that interval before accumulation.
- Share validation has already ruled out malformed or mismatched share domains.

Proof sketch:

1. For each coefficient lane `ell`, define the scalar polynomial
   `P_ell(Y) = a_0[ell] + a_1[ell]Y + ... + a_d[ell]Y^d in F[Y]`.
2. `vss::evaluate_polynomial_at` implements Horner evaluation. Its loop
   invariant is that after processing a suffix of coefficients, `result[ell]`
   equals the value of that suffix polynomial at `x_i` modulo `q`.
3. Therefore `s_i[ell] = P_ell(x_i)` for every active share and lane.
4. Since `degree(P_ell) < t <= |A|`, Lemma 2 applies:
   `sum_i lambda_i(A) * P_ell(x_i) = P_ell(0) = a_0[ell]`.
5. The reconstruction function scales each `Poly` lane by `lambda_i(A)` modulo
   `q` and accumulates with `Poly::add_assign`, so the vector of 256 scalar
   equalities gives equality in `R_q`.

Implementation mapping:

- `vss::evaluate_polynomial_at` evaluates `P(x_i)` with Horner's method in
  each coefficient lane.
- `interpolation::try_reconstruct_secret_poly_with_threshold` validates empty,
  duplicate, zero-index, and insufficient-share cases before reconstructing.
- `interpolation::reconstruct_secret_poly` performs the unchecked scaling and
  accumulation used by lower-level scaffolding.

Current evidence vs remaining proof:

- Evidence: `tests/dkg_vss_soundness.rs` checks threshold round trips and
  malformed active sets.
- Evidence: `tests/hazmat_mldsa65_threshold_bridge.rs` checks reconstruction
  of expanded ML-DSA-65 secret components and secret contribution components
  in the feature-gated hazmat path.
- Remaining proof: `Poly::add_assign` needs a small arithmetic proof over its
  branch-free reduction path and explicit canonical-input preconditions.
- Remaining proof: deterministic masks in `split_secret_poly` must be replaced
  by cryptographically sampled masks for any privacy or DKG security claim.

<a id="lemma-canonical-collection-determinism"></a>

## Lemma 4: Canonical Collection Determinism

Statement: For any valid validator universe `V`, threshold `t`, and network
multiset of commitments or partial shares with no duplicate validator IDs and
at least `t` entries from `V`, `CommitmentSet::new` and `PartialShareSet::new`
produce a canonical order independent of network arrival order.

Assumptions and preconditions:

- `0 < t <= |V|`.
- Validator IDs are unique in `V`.
- Each submitted commitment or partial share is attributed to a member of `V`.
- The `ValidatorId` ordering used by `BTreeSet` and `BTreeMap` is the protocol
  ordering intended for transcripts and aggregation.
- The wire protocol encodes validator IDs canonically and the transport layer
  binds peer identity to the claimed validator ID.

Proof sketch:

1. `set_from_validators` inserts every validator into a `BTreeSet`; duplicate
   insertion fails, and successful construction yields a sorted set determined
   only by the IDs in `V`.
2. Each submitted item is inserted into a `BTreeMap` keyed by `ValidatorId`.
   Unknown validators and duplicate keys are rejected.
3. A `BTreeMap` iterator yields keys in the total order defined by
   `ValidatorId`, so iteration is a pure function of the key-value map, not of
   insertion order.
4. Therefore any two arrival permutations of the same valid attributed inputs
   produce equal maps and equal canonical iteration sequences.

Implementation mapping: `src/collections.rs` stores validators in `BTreeSet`
and submitted data in `BTreeMap`; transcript and aggregation paths consume
these validated collections through their canonical iterators.

Current evidence vs remaining proof:

- Evidence: `tests/transcript_determinism.rs` checks challenge independence
  from commitment arrival order.
- Evidence: `tests/validation.rs` and `tests/simulated_flow.rs` cover several
  duplicate, unknown-validator, and insufficient-set errors.
- Remaining proof: the production wire protocol must make validator ID
  serialization and peer authentication part of the proof model.
- Remaining proof: every production hash and aggregation input must be audited
  to confirm it uses canonical iterators, not network-order vectors.

<a id="lemma-transcript-challenge-binding"></a>

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
oracle input. Under the transcript collision and random-oracle assumptions in
`formal-security-theorem.md`, a valid partial or aggregate signature cannot be
reinterpreted as binding to a distinct typed transcript tuple except with the
allowed negligible probability.

Assumptions and preconditions:

- The canonical encoding of the listed typed fields is injective.
- Fixed-width fields have exactly one byte representation; variable-length
  fields are length-prefixed where needed.
- `CommitmentSet` was constructed with the same validator universe and
  threshold supplied to the transcript.
- The commitment set is fixed before challenge derivation.
- The production proof models SHAKE256 either as the selected random oracle or
  through an explicit collision-resistance/XOF assumption.

Proof sketch:

1. `SigningTranscript::new` canonicalizes the validator set and rejects
   threshold or validator-universe mismatch with the commitment set.
2. `derive_challenge` appends the protocol label, protocol version, session ID,
   threshold, validator-count prefix, ordered validator IDs, public key bytes,
   message length, message bytes, commitment-count prefix, and ordered
   `(validator ID, commitment)` pairs.
3. Under the injective encoding precondition, distinct typed transcript tuples
   have distinct byte strings before hashing.
4. SHAKE256 is deterministic, so identical byte strings give identical
   challenges. In the random-oracle model, distinct byte strings are distinct
   oracle queries; binding failure then reduces to the stated hash/encoding
   assumption rather than to network ordering.

Implementation mapping: `src/transcript.rs::derive_challenge` hashes these
fields in order. The current protocol label is
`dytallix-threshold-mldsa65`, with protocol version `1`.

Current evidence vs remaining proof:

- Evidence: `tests/transcript_determinism.rs` checks binding to message,
  session ID, public key, threshold, validator set, and commitment bytes, and
  checks order independence for equivalent commitment sets.
- Evidence: `proof-implementation-crosswalk.md` maps transcript binding to
  `src/transcript.rs`, `src/protocol.rs`, and backend boundaries.
- Remaining proof: provide a byte-level injectivity proof for every production
  transcript encoding, including retry or attempt counters.
- Remaining proof: prove the commitment set supplied to the transcript is the
  same set whose openings or contribution proofs are verified by all honest
  partial signers.

<a id="lemma-threshold-response-aggregation"></a>

## Lemma 6: Threshold Response Aggregation Correctness

Statement for a real ML-DSA-65 threshold backend: Let each honest participant
`i in A` hold Shamir share `s_i` of the signing secret component `s`. For a
common transcript-derived challenge `c` and committed local mask share `y_i`,
suppose the partial response has algebraic form:

```text
z_i = y_i + c * s_i
```

or the backend-specific equivalent in the ML-DSA module-vector domain. If the
aggregator computes:

```text
z = sum_{i in A} lambda_i(A) * z_i,
y = sum_{i in A} lambda_i(A) * y_i,
s = sum_{i in A} lambda_i(A) * s_i,
```

then:

```text
z = y + c * s.
```

Assumptions and preconditions:

- All partial shares bind to the same transcript and challenge.
- The active signer set used for `lambda_i(A)` is exactly the set aggregated.
- Partial-share verification proves each `z_i` matches the committed mask
  material and the signer's verified secret-share metadata.
- All arithmetic is in one agreed ML-DSA coefficient or NTT representation, and
  conversions preserve the modeled ring operations.
- The same challenge polynomial or challenge representation `c` is used for
  every partial response and for final verification.

Proof sketch:

1. Substitute each local equation into the aggregate:
   `sum_i lambda_i z_i = sum_i lambda_i(y_i + c*s_i)`.
2. Distributivity in the ML-DSA ring/module domain gives
   `sum_i lambda_i y_i + c * sum_i lambda_i s_i`.
3. By the definitions of reconstructed `y` and `s`, this is `y + c*s`.
4. Lemma 3 supplies the reconstruction step for any Shamir-shared secret
   component represented as coefficient lanes. The backend proof must lift the
   same argument to every ML-DSA-65 vector component actually used by signing.

Implementation mapping: The default `SimulatedBackend` does not implement this
algebra; it hashes partial-share bytes into deterministic test signatures. The
hazmat path contains production-shaped masking, secret contribution, response,
and session APIs in `src/low_level/mldsa65.rs`, but those remain hazmat
surfaces and not a completed production proof.

Current evidence vs remaining proof:

- Evidence: `tests/hazmat_mldsa65_threshold_bridge.rs` checks that partial
  secret contributions interpolate to centralized signing terms, mismatched
  challenges are rejected, and threshold responses carry the derived challenge.
- Evidence: hazmat session tests reject duplicate masking or secret
  contributions and out-of-order secret contributions.
- Remaining proof: specify the exact ML-DSA-65 module dimensions,
  coefficient/NTT conventions, challenge multiplication, and share encodings.
- Remaining proof: prove partial-share verification against production
  commitments or contribution proofs, not deterministic scaffold digests.
- Remaining proof: prove aggregation uses the same active set for all
  response, hint, and verification components.

<a id="lemma-standard-verification"></a>

## Lemma 7: Standard ML-DSA Verification Compatibility

Statement for a real ML-DSA-65 threshold backend: If all accepted partial
responses satisfy their local verification equations and rejection checks, and
if aggregation constructs `(c_tilde, z, h)` exactly as single-signer
ML-DSA-65 would construct it for public key `pk` and message `m`, then the
standard ML-DSA-65 verification algorithm accepts the aggregate signature:

```text
MLDSA65.Verify(pk, m, sigma) = accept.
```

Assumptions and preconditions:

- The transcript challenge is bit-for-bit equal to the challenge derived by the
  standard ML-DSA verifier from the reconstructed verifier inputs, or the
  protocol specifies an internal-mu path proven equivalent to the standard
  external API.
- The aggregate `z` and hint `h` satisfy the ML-DSA-65 norm, hint, and
  challenge-weight predicates.
- Public key encoding and signature encoding are standard ML-DSA-65 encodings.
- No threshold-only metadata appears in the final standard signature.
- The public key corresponds to the reconstructed public signing relation for
  the threshold secret shares.

Proof sketch:

1. The standard verifier parses `sigma` as `(c_tilde, z, h)` and recomputes the
   verifier challenge from `pk`, `m` or `mu`, the unpacked response, and hint
   data according to ML-DSA-65.
2. By Lemma 6, the aggregate response satisfies the same algebraic relation as
   a single-signer response for the reconstructed signing secret.
3. By Lemma 8, the aggregate response and hints satisfy the same bound
   predicates checked by the standard verifier.
4. By transcript compatibility, the verifier's recomputed challenge equals the
   challenge packed into `sigma`.
5. Therefore every verifier predicate matches the corresponding single-signer
   ML-DSA predicate, so `MLDSA65.Verify(pk, m, sigma) = accept`.

Implementation mapping: `src/low_level/mldsa65.rs` exposes standard signature
packing and verification helpers under the hazmat feature. The default backend
still has simulation behavior and cannot establish this lemma.

Current evidence vs remaining proof:

- Evidence: `tests/hazmat_mldsa65_threshold_bridge.rs` includes
  `threshold_signature_attempt_packs_and_verifies_with_standard_internal_mu_path`
  and `threshold_session_ideal_3_of_5_flow_emits_standard_verifying_signature`
  behind `hazmat-real-mldsa`.
- Evidence: expanded secret reconstruction tests show reconstructed expanded
  secret bytes preserve deterministic signing behavior in the hazmat path.
- Remaining proof: finish the production threshold backend and decide whether
  the public theorem uses an external-message or internal-mu verification
  statement.
- Remaining proof: prove threshold transcript derivation yields the same
  verifier challenge bytes as the standard signature format requires, or
  specify and prove a compatible construction.
- Remaining proof: obtain independent cryptographic review before treating
  standard-verifying hazmat tests as security evidence.

<a id="lemma-infinity-norm-preservation"></a>

## Lemma 8: Infinity-Norm Bound Preservation under Accepted Aggregation

Statement for a real ML-DSA-65 threshold backend: Let the aggregate response be
`z = y + c * s`. If the protocol's aggregate rejection predicate accepts only
executions where:

```text
||z||_inf < B_z
```

and where all hint and challenge predicates required by ML-DSA-65 hold, then
the final aggregate signature satisfies the standard verifier's norm
predicates.

More formally, for final signature `sigma = Encode(c_tilde, z, h)`, acceptance
by the threshold backend implies:

```text
forall coefficients a of z: |center(a)| < B_z
hint_count(h) <= omega
challenge_weight(c) = tau
```

with the exact strictness and constants required by ML-DSA-65.

Assumptions and preconditions:

- The aggregate check is performed on the aggregate response actually encoded
  in the final signature.
- Centered coefficient interpretation is used for norm checks.
- `B_z = gamma1 - beta` for ML-DSA-65, with the parameter values selected by
  the production backend.
- Hint encoding is canonical and enforces the ML-DSA-65 `omega` limit.
- Challenge encoding enforces the ML-DSA-65 challenge-size and challenge-weight
  rules.

Proof sketch:

1. The backend acceptance predicate is assumed to inspect the final aggregate
   `z`, not only individual partial responses.
2. For every encoded coefficient, the predicate computes the same centered
   representative that the standard verifier uses for its infinity-norm check.
3. Since acceptance requires `|center(a)| < B_z` for all coefficients, the
   verifier's `z` bound check succeeds.
4. The same acceptance predicate requires the standard hint and challenge
   predicates. If encoding is canonical, the verifier parses the same `h` and
   `c_tilde` that the backend checked.
5. Therefore all standard verifier-side bound predicates covered by this lemma
   hold for accepted aggregate signatures.

Implementation mapping: `Poly::check_noise_bounds` checks one polynomial's
coefficient magnitudes against a caller-supplied bound. The hazmat ML-DSA-65
path defines `MLDSA65_GAMMA1`, `MLDSA65_GAMMA2`, `MLDSA65_BETA`,
`MLDSA65_OMEGA`, and `MLDSA65_Z_NORM_BOUND`, and exposes standard packing and
verification helpers. This is not a complete distribution or side-channel
proof.

Current evidence vs remaining proof:

- Evidence: `tests/hazmat_mldsa65_threshold_bridge.rs` checks that hazmat
  threshold responses satisfy `Poly::check_noise_bounds(MLDSA65_Z_NORM_BOUND)`
  in a deterministic bridge scenario.
- Evidence: `noise-rejection-proof-plan.md` identifies aggregate rejection,
  hint bounds, challenge checks, and abort distribution as separate proof
  obligations.
- Remaining proof: define exact centered conversion, strict-vs-nonstrict
  inequalities, hint-count bound, challenge weight, and malformed-encoding
  rejection for the production backend.
- Remaining proof: lift the scalar `Poly` check to all ML-DSA-65 module-vector
  response and hint checks.
- Remaining proof: prove rejection-sampling distribution preservation, not just
  verifier-side bound preservation.

## Summary of Current Status

Implemented and test-scaffolded:

- Coefficient-lane polynomial arithmetic over modulus `q`.
- Checked and unchecked Shamir-style polynomial evaluation over `R_q`.
- Lagrange reconstruction at zero for polynomial shares.
- Canonical commitment and partial-share collection ordering.
- Transcript binding for the simulation API.
- Feature-gated hazmat ML-DSA-65 bridge tests for reconstructed secret
  components, threshold response construction, rejection checks, and
  standard-verifying internal-mu threshold artifacts.

Not implemented or not proven:

- Production-random VSS masks and binding/hiding commitments.
- A completed malicious-secure production threshold ML-DSA-65 backend.
- Production partial-share verification and contribution proofs.
- A full proof that threshold aggregation into standard ML-DSA signatures
  preserves the single-signer signing distribution.
- Rejection-sampling distribution preservation and abort leakage bounds.
- Byte-level formal transcript injectivity for every production field and
  retry attempt.
- Constant-time and side-channel guarantees.
- The full theorem in `formal-security-theorem.md`.
