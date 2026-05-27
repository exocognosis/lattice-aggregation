# Rejection-Sampling Hybrid Proof Skeleton
<a id="rejection-hybrid-proof"></a>

Date: 2026-05-27

Status: proof sketch and dependency map, not a completed distribution proof.

Distribution equivalence is not complete. This document gives the next proof
layer for ML-DSA rejection sampling, abort behavior, and accepted-signature
distribution in the threshold setting. It is intended to refine
`noise-rejection-proof-plan.md`, `formal-security-theorem.md`, and
`random-oracle-game.md`, while preserving the explicit non-claim that the
current repository has not proved threshold distribution equivalence.

## RSH-0. Scope and Non-Claims

The target is a hybrid chain from ordinary centralized ML-DSA-65 signing to an
accepted threshold aggregate signature. The chain isolates the obligations
needed for FST-A5, FST-L7, and FST-G5 in `formal-security-theorem.md`.

The current hazmat code exposes useful implementation checkpoints:

- `src/low_level/mldsa65.rs` contains ML-DSA-65 constants including
  `MLDSA65_Z_NORM_BOUND`, `MLDSA65_GAMMA2`, `MLDSA65_BETA`, and
  `MLDSA65_OMEGA`.
- `finalize_mldsa65_threshold_response` checks challenge consistency and the
  aggregate `z` bound.
- `finalize_mldsa65_threshold_signature_attempt` checks low-bit, `ct0`, and
  hint-weight rejection conditions before packing a standard-size signature.
- `begin_mldsa65_threshold_attempt`,
  `derive_mldsa65_session_challenge_once_quorum_met`,
  `submit_mldsa65_masking_contribution`, and
  `submit_mldsa65_secret_contribution` model a commit-before-challenge phase
  order for hazmat tests.
- `tests/hazmat_mldsa65_threshold_bridge.rs` and
  `tests/hazmat_mldsa65_actor.rs` exercise reconstruction, duplicate
  rejection, stale-challenge rejection, rejection-sampling failures, and
  standard internal-`mu` verification for accepted examples.

Those checkpoints are conformance evidence only. They do not prove that
threshold masks have the ML-DSA signing distribution, that selective aborts are
simulatable, or that accepted aggregate signatures are distributed exactly like
centralized ML-DSA signatures.

## RSH-1. Notation

Let `pk` be the ML-DSA-65 public key, `sk` the centralized secret key, `m` the
message, and `mu` the ML-DSA message-binding digest. Let `A` be the active
signer set with `|A| >= t`, and let `lambda_i(A)` be the Lagrange coefficient
for signer `i`.

For a threshold attempt:

```text
y      aggregate mask reconstructed or added from local masking contributions
w1     high bits used for challenge derivation
c      challenge derived from mu and w1
cs1    reconstructed c*s1 contribution
cs2    reconstructed c*s2 contribution
ct0    reconstructed c*t0 contribution
z      y + cs1
h      hint vector
sigma  Encode(c, z, h)
```

The rejection predicate must include all ML-DSA-65 checks on `z`, low bits,
`ct0`, challenge consistency, and hint weight. The proof must specify whether
the threshold protocol signs raw `m`, `mu`, or both, consistently with
`random-oracle-game.md`.

## RSH-2. Hybrid Chain Overview

The intended chain is:

```text
H0 centralized ML-DSA
H1 shared secret decomposition
H2 shared mask generation
H3 commit-before-challenge
H4 partial response reconstruction
H5 aggregate rejection predicate
H6 accepted-signature distribution
```

Each transition must supply a distinguishing bound. This document records the
shape of those transitions and marks which parts are proof sketches versus
open obligations.

The aggregate accepted-distribution loss is stated in
[`rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound`](rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound)
as:

```text
Delta_accept <= eps_mask + eps_rej + eps_withhold + eps_ro + eps_commit
```

That theorem is conditional. This hybrid document identifies where each term is
used; the bounds worksheet records the current sub-lemmas and remaining
missing steps.

## RSH-2.1. Hybrid-to-Epsilon Map

| Hybrid transition | Epsilon term used | Role in the bound |
| --- | --- | --- |
| H1 -> H2 shared mask generation | `eps_mask` | Pays for replacing centralized ML-DSA mask sampling with aggregate threshold mask generation before conditioning on rejection. |
| H2 -> H3 commit-before-challenge | `eps_commit` and `eps_ro` | Pays for commitment binding/non-adaptivity and for typed random-oracle challenge derivation over `Com`. |
| H3 -> H4 partial response reconstruction | no new rejection epsilon if H1/H4 algebra holds | Algebraic reconstruction is intended to be exact; failures remain correctness obligations in `correctness-lemmas.md`. |
| H4 -> H5 aggregate rejection predicate | `eps_rej` | Pays for any mismatch between threshold aggregate rejection and centralized ML-DSA rejection on the same candidate values. |
| H5 -> H6 accepted-signature distribution | `eps_withhold`, plus carried terms | Pays for conditioning on accepted attempts in the presence of withholding, retries, abort labels, and bounded retry policies. |
| Random-oracle and replay steps across H2-H6 | `eps_ro` | Pays for prior oracle queries, replay, transcript collision, domain separation, and simulator-programming losses. |

<a id="rsh-h0-centralized-mldsa"></a>

## H0. Centralized ML-DSA

Game: The challenger runs ordinary ML-DSA-65 signing with centralized `sk`.
The signer samples the ML-DSA mask, derives the challenge from the standard
message and public high-bit data, computes `(z, h)`, and restarts according to
the standard rejection predicate until an accepted `sigma` is produced.

Proof sketch:

- This is the reference distribution used by the ML-DSA security theorem.
- All later hybrids must preserve either this accepted-signature distribution
  or a quantified distance from it.

Open:

- The repository must identify the exact FIPS 204 theorem, parameter set, and
  random-oracle interpretation that serves as the external reference.

<a id="rsh-h1-shared-secret-decomposition"></a>

## H1. Shared Secret Decomposition

Change from H0: Replace centralized secret components with Shamir shares and
reconstruct challenge-dependent secret terms from any authorized active set
`A`.

Required equivalence:

```text
sum_{i in A} lambda_i(A) * s1_i = s1
sum_{i in A} lambda_i(A) * s2_i = s2
sum_{i in A} lambda_i(A) * t0_i = t0
```

Proof sketch:

- `correctness-lemmas.md` Lemma 2 and Lemma 3 state the coefficient-lane
  Shamir reconstruction obligation over `R_q`.
- The hazmat bridge tests check that partial secret contributions interpolate
  to centralized signing terms and reject challenge mismatches.

Open:

- Prove all secret components used by the production backend are shared with
  matching polynomial degree, identifier domain, and commitment verification.
- Prove malformed, duplicate, or subthreshold contribution sets cannot enter
  reconstruction.
- Prove sharing secrecy and active-security properties through the selected
  VSS/DKG construction.

<a id="rsh-h2-shared-mask-generation"></a>

## H2. Shared Mask Generation

Change from H1: Replace centralized ML-DSA mask sampling with threshold mask
generation. The aggregate mask is computed from participant contributions.

Bound term: this transition is charged to `eps_mask` in
[`rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound`](rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound).
The concrete proof obligation is Sub-Lemma M in the bounds worksheet: compare
`(Y_T, HighBits(PublicMatrix*Y_T))` with the centralized ML-DSA-65
`(Y_0, HighBits(PublicMatrix*Y_0))` before conditioning on rejection.

Candidate relation:

```text
y = CombineMask({y_i}_{i in A})
w = CombinePublicMask({w_i}_{i in A})
w1 = HighBits(w)
```

Proof sketch:

- The current hazmat path adds masking contributions and derives `w1` before
  challenge derivation.
- Tests check validator-domain separation for masking contributions and
  aggregate consistency for selected examples.

Open:

- Define the production distribution for each `y_i` and prove `y` has the
  centralized ML-DSA mask distribution, or state and prove an acceptable
  statistical-distance bound.
- Prove Lagrange or additive combination does not widen the effective mask
  distribution in a way that changes rejection probabilities.
- Prove corrupted validators cannot bias honest mask shares beyond the model's
  abort allowance.
- Define retry counters, fresh mask sampling, and transcript binding for every
  rejected attempt.

<a id="rsh-h3-commit-before-challenge"></a>

## H3. Commit-Before-Challenge

Change from H2: Insert explicit commitments to masking material before the
challenge oracle can be queried.

Bound terms: this transition uses `eps_commit` for commitment binding,
opening-set equality, and non-adaptivity, and `eps_ro` for the typed
random-oracle challenge query. Rushing and selective withholding after
commitment publication are not hidden inside `eps_commit`; they are charged to
`eps_withhold` in H6 unless the final proof shows they are denial of service
only.

Required ordering:

```text
commitments fixed -> canonical commitment set Com -> c = H_c(sid, t, V, pk, mu or m, Com)
```

Proof sketch:

- `random-oracle-game.md` ROG-D2 and ROG-D3 define the commitment and
  challenge oracle obligations.
- The hazmat session state machine rejects secret contributions before the
  challenge phase and rejects stale challenge contributions.

Open:

- Instantiate a binding and hiding commitment relation for `w_i`, `y_i`, or
  the selected protocol-specific statement.
- Prove a participant cannot equivocate after seeing `c`, except with public
  evidence.
- Prove the exact commitment set used for `H_c` is the one used by partial
  verification and aggregation.
- Quantify rushing-adversary effects from `active-adversary-model.md`.

<a id="rsh-h4-partial-response-reconstruction"></a>

## H4. Partial Response Reconstruction

Change from H3: Replace centralized response computation with reconstruction
from challenge-bound partial secret contributions.

Bound term: no additional rejection-sampling epsilon is intended for this
transition if the reconstruction equations below hold exactly. Algebraic or
partial-verification failures remain open correctness obligations; if a future
construction proves them only up to a probability loss, that loss must be added
to the theorem rather than silently absorbed into `eps_rej`.

Required equation:

```text
z = y + c*s1
  = CombineMask({y_i}) + sum_{i in A} lambda_i(A) * (c*s1_i)
```

and similarly for the secret terms used to compute low bits and hints:

```text
cs2 = sum_{i in A} lambda_i(A) * (c*s2_i)
ct0 = sum_{i in A} lambda_i(A) * (c*t0_i)
```

Proof sketch:

- `correctness-lemmas.md` Lemma 6 states the response aggregation identity.
- The hazmat bridge tests check reconstruction of `cs1`, `cs2`, and `ct0`
  against centralized contribution derivation for fixed challenges.
- Stale challenge contribution tests provide regression coverage for
  challenge binding at the API boundary.

Open:

- Specify and prove the production partial-verification relation.
- Prove accepted partials bind to one validator, one share, one active set, one
  challenge, and one commitment.
- Prove contribution proofs do not leak secret-share material beyond the
  selected zero-knowledge or witness-hiding claim.

<a id="rsh-h5-aggregate-rejection-predicate"></a>

## H5. Aggregate Rejection Predicate

Change from H4: Replace centralized rejection checks with aggregate checks over
the reconstructed threshold values.

Bound term: this transition is charged to `eps_rej` as defined in
[`rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound`](rejection-sampling-bounds.md#theorem-conditional-accepted-distribution-bound).
The intended endpoint is equality between `Reject_T` and `Reject_0` for the
same candidate `z`, low bits, `ct0`, hint vector, challenge, and signature
encoding. Until the standard-verifier compatibility question is closed, any
remaining verifier mismatch must stay visible as part of `eps_rej` or as a
separate `eps_verify` term.

Required predicate:

```text
AggregateAccept(pk, mu, A, Com, c, z, h) =
    c == H(mu, w1)
    and ||z||_inf < gamma1 - beta
    and ||LowBits(w - cs2)||_inf < gamma2 - beta
    and ||ct0||_inf < gamma2
    and weight(h) <= omega
    and sigma = Encode(c, z, h)
    and MLDSA65.Verify(pk, m or mu, sigma) = accept
```

Proof sketch:

- `finalize_mldsa65_threshold_response` checks challenge consistency and the
  aggregate `z` rejection bound.
- `finalize_mldsa65_threshold_signature_attempt` checks low-bit, `ct0`, and
  hint-weight rejection paths before packing.
- Hazmat tests exercise accepted standard internal-`mu` verification and
  rejected attempts that return `RejectionSamplingFailed`.

Open:

- Prove the aggregate predicate is exactly the centralized ML-DSA predicate for
  the same verifier inputs, not merely sufficient for sampled tests.
- Add complete boundary tests for `gamma1 - beta`, `gamma2 - beta`, `gamma2`,
  `omega`, malformed hints, and challenge weight.
- Prove all accepted signatures pass an unmodified standard ML-DSA-65 verifier
  using the final wire encoding.

<a id="rsh-h6-accepted-signature-distribution"></a>

## H6. Accepted-Signature Distribution

Change from H5: Condition on aggregate acceptance and compare the output
distribution to H0.

Bound terms: H6 consumes the carried `eps_mask`, `eps_commit`, `eps_ro`, and
`eps_rej` losses from H2 through H5, and adds `eps_withhold` for selective
withholding, abort-label leakage, retry limits, and timeout or evidence
observables. This is the point at which the conditional theorem's
`Delta_accept` statement applies.

Desired statement:

```text
Dist(H6 accepted sigma | pk, m) ~= Dist(H0 accepted sigma | pk, m)
```

where `~=` must be replaced by either exact equality or an explicit
statistical/computational distance bound.

Proof sketch:

- If H1 reconstructs the same secret terms, H2 supplies the same pre-rejection
  mask distribution, H3 prevents challenge-adaptive masks, H4 reconstructs the
  same response algebra, and H5 checks the same rejection event, then the
  accepted distribution follows by conditioning on the same event as H0.

Open:

- This implication is not yet proved for this repository.
- The mask distribution proof in H2 and the abort-simulation proof below are
  prerequisites.
- The proof must handle selective aborts by corrupted validators after seeing
  commitments or challenges.
- The proof must quantify whether retry limits, exclusion policies, telemetry,
  evidence, timing, or participant-specific abort labels change the adversary's
  view.

## RSH-3. Abort Distribution and Selective-Abort Obligations

For FST-G5, the adversary may try to bias accepted signatures by causing
sessions to abort after observing public data. A complete proof must define the
observable abort transcript:

- local honest rejection without publication, if the protocol permits it
- corrupted-party withholding after commitments
- aggregate rejection after reconstructing threshold values
- retry count and retry session identifiers
- evidence records for invalid, duplicate, stale, or malformed contributions
- timing and message-size leakage included in the active-adversary model

Required proof obligations:

- Simulate every honest abort observable from public information or hide it
  until the aggregate decision.
- Prove retries use fresh mask material and domain-separated transcript inputs.
- Bound the adversary's ability to condition future challenges on previous
  aborts.
- State availability and denial-of-service limits separately from distribution
  preservation.

Bound term: these obligations instantiate `eps_withhold`. The current
documents formalize the observable categories and symbolic decomposition, but
the simulator and retry-limit bound remain open.

## RSH-4. Current Classification

| Layer | Current status | Bound status |
| --- | --- | --- |
| H0 centralized ML-DSA | External theorem dependency. | Reference distribution; no threshold epsilon. |
| H1 shared secret decomposition | Proof sketch with hazmat reconstruction tests; production VSS/DKG proof open. | Algebraic precondition for T1. |
| H2 shared mask generation | Open distribution proof. | `eps_mask` formalized symbolically; concrete mask bound open. |
| H3 commit-before-challenge | Proof sketch for ordering; real commitment proof open. | `eps_commit` and `eps_ro` formalized symbolically; commitment instantiation and RO losses open. |
| H4 partial response reconstruction | Proof sketch for algebra; production partial-verification proof open. | Intended exact step; any probabilistic failure must become an explicit additional term. |
| H5 aggregate rejection predicate | Proof sketch with hazmat rejection checks; exact verifier-equivalence proof open. | `eps_rej` formalized symbolically; predicate-equivalence proof open. |
| H6 accepted-signature distribution | Open. Distribution equivalence is not complete. | `Delta_accept` theorem shape and `eps_withhold` decomposition formalized; accepted-distribution proof open. |

## RSH-5. Links to Other Proof Documents

- `noise-rejection-proof-plan.md` tracks the noise-bound and rejection
  obligations at the lemma level.
- `correctness-lemmas.md` tracks reconstruction and standard-verifier
  compatibility obligations.
- `random-oracle-game.md` tracks oracle domains for message binding,
  commitments, challenges, and contribution proofs.
- `active-adversary-model.md` tracks rushing, selective aborts, and corruption
  choices.
- `formal-security-theorem.md` records FST-A5, FST-L7, and FST-G5 as proof
  targets, not completed theorem statements.
