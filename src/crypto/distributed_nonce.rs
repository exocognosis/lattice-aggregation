//! Distributed nonce generation for threshold ML-DSA-65 (backend requirement #2).
//!
//! The gateway to threshold partial signing: a set of signers jointly produce
//! the nonce commitment `w` and the challenge `c` so that per-signer partial
//! responses (requirement #3) sum to the standard ML-DSA response `z = y + c*s1`
//! — **without any single party knowing the joint mask `y`**.
//!
//! ## Protocol (two rounds, FROST-style, per the design panel)
//!
//! Public input: the matrix `A` (`mldsa_module::expand_matrix_a`).
//! - **Round 1 (commit).** Each signer samples a *fresh* mask
//!   `y_i in R_q^L` (coefficients uniform in `(-GAMMA1, GAMMA1]`), computes
//!   `w_i = A * y_i in R_q^K`, and broadcasts only a salted hash commitment
//!   `com_i = SHA3-256(domain || salt_i || encode(w_i))`. `y_i` stays secret.
//! - **Round 2 (reveal + aggregate).** Each signer reveals `(w_i, salt_i)`;
//!   every party recomputes `com_i` and **aborts on any mismatch** (fail-closed).
//!   The joint commitment is the *plain sum* `w = sum_i w_i` (Lagrange
//!   coefficients belong in the partial signature, not here), then
//!   `w1 = HighBits(w)` (computed **once** on the summed `w` — `HighBits` is
//!   non-linear, so per-signer high bits cannot be combined),
//!   `c_tilde = H(mu || encode(w1))`, and `c = SampleInBall(c_tilde)`.
//!
//! Each signer retains its own `y_i` for the partial response `z_i = y_i +
//! c * lambda_i * s1_i` (requirement #3).
//!
//! ## Claim boundary — what this does NOT deliver
//!
//! - **epsilon_mask is OPEN (and surfaced here).** The joint mask `y = sum_i
//!   y_i` is a sum of uniforms — support `~ signers * GAMMA1`, bell-shaped —
//!   **not** the uniform `ExpandMask` distribution. So `||y||_inf` typically far
//!   exceeds `GAMMA1`, and under the standard ML-DSA verifier the aggregate
//!   response would be rejected. A negative test
//!   (`aggregate_mask_exceeds_gamma1`) pins this open; nothing here may be read
//!   as closing epsilon_mask. Closing it needs distributed uniform sampling
//!   (heavy MPC) or a distribution change (non-standard verifier).
//! - **Single-use masks.** A `y_i` MUST NOT be reused across two challenges:
//!   nonce reuse leaks `s1` exactly as in Schnorr. Each attempt resamples.
//! - **Residual last-mover abort bias.** Commit-before-reveal stops *intra-round*
//!   adaptive nonce choice, but a committed adversary can still refuse to open to
//!   force a restart and grind the challenge. A quantitative bound is deferred.
//! - No partial response / secret-key touch (#3); no rejection loop, `LowBits`
//!   use, hint, or FIPS wire signature (#5). `A` is uniform (not `ExpandA`) and
//!   `w1` encoding is research-shaped, so `c` is not asserted CAVP-identical.
//! - Closes **zero** of the five hypothesis criteria. This is a distributed
//!   *coordination mechanism*, not a working threshold signature.
//! - Commitments carry no signer identity and [`finalize`] pairs them
//!   positionally, so binding a commitment to a distinct signer and preventing
//!   duplicate submissions is the caller's (coordinator's) responsibility. The
//!   commitment `salt` is derived from the signer seed (deterministic), so it
//!   adds no blinding beyond the secret seed itself.
//!
//! Unlike `backend::module_partial`, the mask is generated additively per signer
//! (no trusted nonce dealer): no party samples or knows the joint `y`.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::{
    mldsa_module::{MODULE_K, MODULE_L},
    mldsa_primitives::{high_bits_poly, sample_gamma1_poly, sample_in_ball},
    module_lattice::{matrix_vec_mul, vec_add},
    poly::Poly,
};

const COMMIT_LABEL: &[u8] = b"lattice-aggregation/distributed-nonce/commit/v1";
const SALT_LABEL: &[u8] = b"lattice-aggregation/distributed-nonce/salt/v1";
const CHALLENGE_LABEL: &[u8] = b"lattice-aggregation/distributed-nonce/challenge/v1";

/// A signer's secret nonce state; never broadcast.
#[derive(Clone, Debug)]
pub struct SignerNonceState {
    mask: Vec<Poly>,
    commitment_w: Vec<Poly>,
    salt: [u8; 32],
}

/// Round-1 public commitment to a signer's nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceCommitment([u8; 32]);

/// Round-2 opening revealed by a signer.
#[derive(Clone, Debug)]
pub struct NonceOpening {
    /// The signer's commitment value `w_i = A * y_i`.
    pub commitment_w: Vec<Poly>,
    /// The commitment salt.
    pub salt: [u8; 32],
}

/// The aggregated joint nonce and derived challenge.
#[derive(Clone, Debug)]
pub struct JointNonce {
    /// Joint commitment `w = sum_i w_i`.
    pub w: Vec<Poly>,
    /// `w1 = HighBits(w)`, computed once on the summed `w`.
    pub w1: Vec<Poly>,
    /// Challenge seed `c_tilde = H(mu || encode(w1))`.
    pub challenge_seed: [u8; 32],
    /// Challenge `c = SampleInBall(c_tilde)`.
    pub challenge: Poly,
}

impl SignerNonceState {
    /// The signer's secret mask `y_i` (retained for the partial response in #3).
    pub fn mask(&self) -> &[Poly] {
        &self.mask
    }

    /// Produce the round-2 opening for this nonce.
    pub fn open(&self) -> NonceOpening {
        NonceOpening {
            commitment_w: self.commitment_w.clone(),
            salt: self.salt,
        }
    }
}

/// Round 1: a signer samples a fresh mask and commits to `w_i = A * y_i`.
///
/// `signer_seed` must be fresh per signing attempt (single-use); reusing it
/// across challenges leaks the secret key.
pub fn commit(
    matrix_a: &[Vec<Poly>],
    signer_seed: &[u8; 32],
) -> (SignerNonceState, NonceCommitment) {
    let mask: Vec<Poly> = (0..MODULE_L)
        .map(|component| sample_gamma1_poly(signer_seed, component as u16))
        .collect();
    let commitment_w = matrix_vec_mul(matrix_a, &mask);
    let salt = derive_salt(signer_seed);
    let commitment = NonceCommitment(commit_digest(&salt, &commitment_w));

    (
        SignerNonceState {
            mask,
            commitment_w,
            salt,
        },
        commitment,
    )
}

/// Verify a round-2 opening against its round-1 commitment (fail-closed).
pub fn verify_opening(commitment: &NonceCommitment, opening: &NonceOpening) -> bool {
    if opening.commitment_w.len() != MODULE_K {
        return false;
    }
    commit_digest(&opening.salt, &opening.commitment_w) == commitment.0
}

/// Two-round finalize: verify every opening against its commitment, then
/// aggregate into the joint nonce and challenge.
///
/// Returns `None` (fail-closed) on a count mismatch, an empty set, or any
/// opening that does not match its commitment.
pub fn finalize(
    commitments: &[NonceCommitment],
    openings: &[NonceOpening],
    message: &[u8],
) -> Option<JointNonce> {
    if commitments.is_empty() || commitments.len() != openings.len() {
        return None;
    }
    for (commitment, opening) in commitments.iter().zip(openings.iter()) {
        if !verify_opening(commitment, opening) {
            return None;
        }
    }
    Some(aggregate(openings, message))
}

/// Aggregate pre-verified openings into the joint nonce and challenge.
///
/// Callers should verify openings against commitments first (see [`finalize`]).
pub fn aggregate(openings: &[NonceOpening], message: &[u8]) -> JointNonce {
    let mut w = vec![Poly::zero(); MODULE_K];
    for opening in openings {
        // Canonicalize each (possibly hostile, non-canonical) opening before
        // summing: `add_assign` assumes canonical `[0, Q)` inputs, and the
        // commitment binds only the canonical residue class. This keeps the sum
        // correct and prevents i32 overflow on crafted openings.
        let canonical: Vec<Poly> = opening.commitment_w.iter().map(Poly::canonical).collect();
        w = vec_add(&w, &canonical);
    }

    // HighBits is applied ONCE to the summed w (it is non-linear).
    let w1: Vec<Poly> = w.iter().map(high_bits_poly).collect();

    let challenge_seed = challenge_seed(message, &w1);
    let challenge = sample_in_ball(&challenge_seed);

    JointNonce {
        w,
        w1,
        challenge_seed,
        challenge,
    }
}

fn squeeze32(hasher: Shake256) -> [u8; 32] {
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn derive_salt(signer_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(SALT_LABEL);
    hasher.update(signer_seed);
    squeeze32(hasher)
}

fn commit_digest(salt: &[u8; 32], commitment_w: &[Poly]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(COMMIT_LABEL);
    hasher.update(salt);
    for poly in commitment_w {
        for coeff in poly.canonical().coeffs {
            hasher.update(&coeff.to_be_bytes());
        }
    }
    squeeze32(hasher)
}

fn challenge_seed(message: &[u8], w1: &[Poly]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(CHALLENGE_LABEL);
    hasher.update(&(message.len() as u64).to_be_bytes());
    hasher.update(message);
    for poly in w1 {
        for coeff in poly.canonical().coeffs {
            hasher.update(&coeff.to_be_bytes());
        }
    }
    squeeze32(hasher)
}

#[cfg(test)]
mod distributed_nonce_tests {
    use super::*;
    use crate::crypto::{
        mldsa_module::expand_matrix_a,
        mldsa_primitives::GAMMA1,
        poly::{N, Q},
    };

    fn matrix() -> Vec<Vec<Poly>> {
        expand_matrix_a(&[9u8; 32])
    }

    #[test]
    fn commit_reveal_finalizes_and_w_equals_sum() {
        let a = matrix();
        let signers = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let states: Vec<_> = signers.iter().map(|s| commit(&a, s)).collect();

        let commitments: Vec<_> = states.iter().map(|(_, c)| c.clone()).collect();
        let openings: Vec<_> = states.iter().map(|(st, _)| st.open()).collect();

        let joint = finalize(&commitments, &openings, b"message").expect("honest openings verify");

        // Joint w equals the plain sum of the per-signer commitments.
        let mut expected = vec![Poly::zero(); MODULE_K];
        for (st, _) in &states {
            expected = vec_add(&expected, &st.commitment_w);
        }
        for (got, want) in joint.w.iter().zip(expected.iter()) {
            assert_eq!(got.canonical().coeffs, want.canonical().coeffs);
        }
    }

    #[test]
    fn joint_commitment_is_a_times_joint_mask() {
        // w = sum(A*y_i) == A*(sum y_i): no single party holds y = sum y_i, but
        // the public w is the image of it under A.
        let a = matrix();
        let s0 = commit(&a, &[4u8; 32]).0;
        let s1 = commit(&a, &[5u8; 32]).0;

        let joint_mask = vec_add(s0.mask(), s1.mask());
        let a_joint = matrix_vec_mul(&a, &joint_mask);
        let w = vec_add(&s0.commitment_w, &s1.commitment_w);

        for (lhs, rhs) in a_joint.iter().zip(w.iter()) {
            assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
        }
    }

    #[test]
    fn tampered_opening_is_rejected_fail_closed() {
        let a = matrix();
        let (state, commitment) = commit(&a, &[7u8; 32]);

        // Tampered w_i.
        let mut bad = state.open();
        bad.commitment_w[0].coeffs[0] ^= 1;
        assert!(!verify_opening(&commitment, &bad));

        // Wrong salt.
        let mut wrong_salt = state.open();
        wrong_salt.salt[0] ^= 1;
        assert!(!verify_opening(&commitment, &wrong_salt));

        // finalize fails closed (no joint nonce) on a bad opening.
        assert!(finalize(&[commitment], &[bad], b"m").is_none());
    }

    #[test]
    fn high_bits_is_non_linear() {
        // Locks in why signers must reveal full w_i: HighBits(sum) != sum(HighBits).
        let a = matrix();
        let w0 = commit(&a, &[11u8; 32]).0.commitment_w;
        let w1v = commit(&a, &[12u8; 32]).0.commitment_w;

        let sum = vec_add(&w0, &w1v);
        let high_of_sum = high_bits_poly(&sum[0]);
        let mut sum_of_high = high_bits_poly(&w0[0]);
        sum_of_high.add_assign(&high_bits_poly(&w1v[0]));

        assert_ne!(
            high_of_sum.canonical().coeffs,
            sum_of_high.canonical().coeffs,
            "HighBits must be applied once to the summed w"
        );
    }

    #[test]
    fn non_canonical_openings_do_not_overflow_finalize() {
        // Regression: openings congruent mod Q but non-canonical still pass
        // verification (the commitment binds the canonical class); finalize must
        // canonicalize before summing so it neither overflows nor perturbs w.
        let a = matrix();
        let s0 = commit(&a, &[31u8; 32]);
        let s1 = commit(&a, &[32u8; 32]);
        let commitments = [s0.1.clone(), s1.1.clone()];

        let honest = finalize(&commitments, &[s0.0.open(), s1.0.open()], b"m").unwrap();

        let mut o0 = s0.0.open();
        let mut o1 = s1.0.open();
        o0.commitment_w[0].coeffs[0] += 255 * Q; // congruent, non-canonical
        o1.commitment_w[0].coeffs[0] += 255 * Q;
        let joint = finalize(&commitments, &[o0, o1], b"m").expect("congruent openings verify");

        for (got, want) in joint.w.iter().zip(honest.w.iter()) {
            assert_eq!(got.canonical().coeffs, want.canonical().coeffs);
        }
        assert_eq!(joint.challenge.coeffs, honest.challenge.coeffs);
    }

    #[test]
    fn challenge_is_deterministic() {
        let a = matrix();
        let openings: Vec<_> = [[1u8; 32], [2u8; 32]]
            .iter()
            .map(|s| commit(&a, s).0.open())
            .collect();
        let c1 = aggregate(&openings, b"same-message").challenge;
        let c2 = aggregate(&openings, b"same-message").challenge;
        assert_eq!(c1.coeffs, c2.coeffs);
    }

    #[test]
    fn aggregate_mask_exceeds_gamma1_epsilon_mask_open() {
        // HONESTY test: the joint mask y = sum y_i is a sum of uniforms, so it
        // leaves the ML-DSA range (-GAMMA1, GAMMA1]. This pins epsilon_mask OPEN
        // -- the aggregate does NOT match ExpandMask, so the standard verifier
        // would reject. CI breaks if anyone claims otherwise.
        let a = matrix();
        let s0 = commit(&a, &[21u8; 32]).0;
        let s1 = commit(&a, &[22u8; 32]).0;

        // Masks are signed in (-GAMMA1, GAMMA1]; the direct sum of two can leave
        // the range. At least one aggregate coefficient exceeds GAMMA1 in
        // magnitude, which a single ExpandMask output cannot.
        let exceeds = (0..MODULE_L).any(|component| {
            (0..N).any(|k| {
                let sum = s0.mask()[component].coeffs[k] + s1.mask()[component].coeffs[k];
                sum.unsigned_abs() > GAMMA1 as u32
            })
        });
        assert!(
            exceeds,
            "aggregate mask must leave the ML-DSA range (epsilon_mask stays open)"
        );
    }
}
