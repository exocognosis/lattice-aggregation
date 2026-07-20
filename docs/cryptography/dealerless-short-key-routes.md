# Dealerless short-key generation: routes around the coefficient-growth blocker

**Status: open problem. Nothing in this note is implemented. `no_single_secret_signing_path` remains hard-coded `false`.** This is a design analysis of candidate approaches with honest trade-offs, not a solution and not a commitment to one.

## The blocker, precisely

Standard ML-DSA-65 requires a *short* secret key: every coefficient of `s1 ∈ R_q^5` and `s2 ∈ R_q^6` lies in `[-η, η] = [-4, 4]`. Verification and the rejection-sampling security argument depend on this bound.

Our current threshold key is **dealt-then-shared**: a trusted setup generates one valid short `(s1, s2)`, then Shamir-shares it. That is what the real 3-party aggregation used, and it is honestly *not* dealerless — a dealer transiently holds the whole secret.

The natural dealerless move — each party samples a short contribution and the joint key is their **sum** — does not preserve shortness. Summing `d ≥ 2` independent `[-η, η]` polynomials yields coefficients in `[-dη, dη]`, which almost always exceeds `η`. The resulting joint key is **not a valid FIPS ML-DSA key**.

This is not a hand-wave. It is a committed, passing test:

- `tests/expand_a_reconciliation_dealt_then_shared.rs::expand_a_reconciliation_dkg_joint_key_exceeds_fips_short_bound` asserts that `DkgCoordinator`'s summed joint key has centered ∞-norm **> η**.
- `src/crypto/mldsa_dkg.rs::reconstructed_joint_secret_centered_infinity_norm` exposes that norm so the growth is measurable, with the doc-comment stating the open-problem boundary.

So the question is not "why is it false" — it is "which principled construction produces a *short* key that no single party ever holds."

## Correction to an earlier framing

An earlier off-hand suggestion in this project called a "threshold-Poseidon route" a candidate. That was imprecise: Poseidon is a ZK-friendly hash and is not a mechanism for dealerless short-secret generation. The genuinely relevant literature is (A) MPC-in-keygen and (B) thresholdization-friendly lattice signatures. This note supersedes that framing.

## Route A — MPC-in-keygen (secret-shared rejection sampling)

Run the *entire* ML-DSA KeyGen inside a malicious-secure MPC: sample `ρ`, expand `A`, and — crucially — sample `s1, s2` by **secret-shared rejection sampling** so the coefficients are guaranteed in `[-η, η]` while remaining additively/Shamir-shared. Compute `t = A·s1 + s2`, `Power2Round`, and open only the public key. No party ever learns `(s1, s2)`.

- **Preserves the standard ML-DSA wire format** — the whole point of this project; the emitted signature verifies under the unmodified FIPS verifier. This is the only route that keeps standard verifiability.
- **We already have the hard building block.** The ExpandMask MPC in `mpc/Programs/Source/mldsa65_expandmask.mpc` does exactly the shape of computation route A needs: secret-shared SHAKE + secret-shared bounded sampling + arithmetic-share output, verified byte-exact against the FIPS oracle and run under malicious MAMA. Secret-shared `RejBoundedPoly` for `s1/s2` is the same category of circuit.
- **Cost is the obstacle, not soundness.** Rejection sampling inside MPC means secret-dependent control flow (accept/reject per coefficient) done data-obliviously, which is expensive. Our ExpandMask run already cost ~80 s and ~12 GB per 3-party invocation for one mask; a full keygen circuit is larger. This is a one-time per-epoch cost, not per-signature, which softens it.
- **Open sub-problems:** oblivious rejection sampling of η-bounded coefficients at acceptable cost; secret-shared `Power2Round`/`Decompose`; malicious-secure share hand-off into the custody vault without a reconstruction point.

Route A is the honest continuation of what this repo has built. It does not exist yet.

## Route B — thresholdization-friendly lattice signatures

Give up exact standard-ML-DSA wire compatibility and adopt a scheme *designed* to be thresholded with additive shares plus noise flooding, so the short-joint-key problem never arises. Representative lines of work: Threshold Raccoon (Fiat-Shamir-with-aborts tailored for thresholding), and Sparkle / related lattice threshold constructions.

- **Efficient and genuinely dealerless** — this is what the threshold-lattice literature actually ships.
- **Breaks the project's core invariant:** the output is *not* a byte-compatible FIPS ML-DSA-65 signature, so it fails "one standard-size ML-DSA-65 signature verifiable by the unmodified verifier." Every current gate and artifact is built around that invariant.
- Suitable only if the project's requirement were relaxed from "standard ML-DSA wire signature" to "a post-quantum threshold signature." That is a product decision, not an engineering fix.

## Recommendation

If standard ML-DSA wire compatibility stays a hard requirement (it currently does), **Route A (MPC-in-keygen)** is the only principled path to no-single-secret, and this repo's ExpandMask MPC is a real first component of it. It should be scoped as a research increment with an explicit cost budget, not promised as a quick fix.

Route B is worth a separate spike only if leadership is willing to relax the standard-wire requirement.

## What stays true regardless

Until Route A is actually built, tested, and independently reviewed:

- `no_single_secret_signing_path` stays `false` everywhere (hard-coded in `CustodyDistributedSignPackage`).
- The dealerless-DKG, production-custody, 6667-scale, and theorem-closure gates stay blocked.
- Internal analysis (including this note) is not external independent review.
