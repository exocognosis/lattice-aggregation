//! BDLOP-style module-lattice commitment over `R_q = Z_q[X]/(X^256 + 1)`.
//!
//! This module implements Increment 2 of the real threshold key material
//! build-out (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! It replaces the perfectly-binding-but-non-hiding Feldman map of
//! [`crate::crypto::vss_real`] with a **computationally hiding and binding**
//! commitment in the style of Baum-Damgard-Lyubashevsky-Oechsner-Peikert
//! (BDLOP, 2018).
//!
//! ## Construction (single message slot, `ell = 1`)
//!
//! Public key: uniform matrices `A1 in R_q^{KAPPA x K}` and `a2 in R_q^{1 x K}`
//! expanded from a public seed. To commit to a message `m in R_q` with short
//! randomness `r in R_q^K` (coefficients in `{-1, 0, 1}`):
//!
//! ```text
//! t1 = A1 * r          (binding part, height KAPPA)
//! t2 = <a2, r> + m     (message part)
//! C  = (t1, t2)
//! ```
//!
//! The commitment is additively homomorphic in `(m, r)` and scalar-homomorphic
//! by integer factors (the only scaling the verifiable secret sharing layer
//! needs, via the Lagrange/Vandermonde powers `i^j`).
//!
//! ## Security and claim boundary
//!
//! - **Binding** of the commitment reduces to Module-SIS on `A1`, but **only
//!   for short openings**: opening one commitment to two messages needs a short
//!   nonzero `A1(r - r') = 0`. The shortness bound is enforced by
//!   [`CommitmentKey::verify_opening`]; a caller that accepts an unbounded `r`
//!   (as the VSS share check does, by necessity) gets homomorphic consistency,
//!   not binding — see [`crate::crypto::vss_bdlop`].
//! - **Hiding** reduces (computationally) to Module-LWE: `(A1 r, <a2, r>)` is
//!   pseudorandom for short `r`, so `t2` masks `m`. Hiding is computational, not
//!   information-theoretic (`t1` determines `r` for these dimensions).
//!
//! The parameters [`KAPPA`], [`K`], and the `{-1,0,1}` randomness bound are a
//! **chosen research parameter set pending concrete lattice-estimator
//! validation**. The large ML-DSA modulus (`q ~ 2^23`) against ternary
//! randomness makes the hiding (Module-LWE) side the likelier constraint to
//! validate. This module does not claim a specific bit-security level, does not
//! close any hypothesis criterion, and makes no production threshold ML-DSA
//! security claim.

use crate::crypto::{
    module_lattice::{inner_product, matrix_vec_mul, sample_uniform_matrix, vec_add},
    poly::Poly,
};

/// Module-SIS binding height (rows of `A1`).
pub const KAPPA: usize = 4;
/// Randomness width: number of short ring elements in an opening.
pub const K: usize = 12;
/// Infinity-norm bound on honest commitment randomness (`{-1, 0, 1}`).
pub const RANDOMNESS_INF_NORM: i32 = 1;

const PUBLIC_MATRIX_LABEL: &[u8] = b"lattice-aggregation/bdlop/public-matrix/a1";
const MESSAGE_ROW_LABEL: &[u8] = b"lattice-aggregation/bdlop/public-matrix/a2";

/// Public commitment key: the uniform matrices `A1` and `a2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentKey {
    a1: Vec<Vec<Poly>>,
    a2: Vec<Poly>,
}

/// A BDLOP commitment `C = (t1, t2)` with `t1 in R_q^{KAPPA}` and `t2 in R_q`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// Binding part `t1 = A1 * r`.
    pub t1: Vec<Poly>,
    /// Message part `t2 = <a2, r> + m`.
    pub t2: Poly,
}

impl CommitmentKey {
    /// Derive a commitment key deterministically from a public seed.
    ///
    /// The seed is public parameter material; different seeds yield independent
    /// commitment keys.
    pub fn from_seed(public_seed: &[u8]) -> Self {
        let mut matrix_seed = PUBLIC_MATRIX_LABEL.to_vec();
        matrix_seed.extend_from_slice(public_seed);
        let a1 = sample_uniform_matrix(&matrix_seed, KAPPA, K);

        let mut row_seed = MESSAGE_ROW_LABEL.to_vec();
        row_seed.extend_from_slice(public_seed);
        let a2 = sample_uniform_matrix(&row_seed, 1, K).remove(0);

        Self { a1, a2 }
    }

    /// Public binding matrix `A1 in R_q^{KAPPA x K}`.
    pub fn binding_matrix(&self) -> &[Vec<Poly>] {
        &self.a1
    }

    /// Public message row `a2 in R_q^K`.
    pub fn message_row(&self) -> &[Poly] {
        &self.a2
    }

    /// Commit to `message` with short `randomness`.
    ///
    /// # Panics
    ///
    /// Panics if `randomness.len() != K`.
    pub fn commit(&self, message: &Poly, randomness: &[Poly]) -> Commitment {
        assert_eq!(randomness.len(), K, "randomness must have length K");
        let t1 = matrix_vec_mul(&self.a1, randomness);
        let mut t2 = inner_product(&self.a2, randomness);
        t2.add_assign(&message.canonical());
        Commitment { t1, t2 }
    }

    /// Verify an opening `(message, randomness)` against a commitment, including
    /// the shortness bound on `randomness`.
    ///
    /// Returns `true` when the commitment recomputes exactly and every
    /// randomness coefficient is within [`RANDOMNESS_INF_NORM`].
    pub fn verify_opening(
        &self,
        commitment: &Commitment,
        message: &Poly,
        randomness: &[Poly],
    ) -> bool {
        if randomness.len() != K {
            return false;
        }
        if !randomness
            .iter()
            .all(|poly| poly.check_noise_bounds(RANDOMNESS_INF_NORM + 1))
        {
            return false;
        }
        self.commit(message, randomness).canonical() == commitment.canonical()
    }
}

impl Commitment {
    /// Homomorphic sum of two commitments: `commit(m1; r1) + commit(m2; r2)`
    /// equals `commit(m1 + m2; r1 + r2)`.
    pub fn add(&self, other: &Commitment) -> Commitment {
        let mut t2 = self.t2;
        t2.add_assign(&other.t2);
        Commitment {
            t1: vec_add(&self.t1, &other.t1),
            t2,
        }
    }

    /// Scalar-homomorphic multiplication by an integer factor modulo `Q`:
    /// `factor * commit(m; r)` equals `commit(factor * m; factor * r)`.
    pub fn scalar_mul(&self, factor: i64) -> Commitment {
        Commitment {
            t1: self.t1.iter().map(|poly| poly.scalar_mul(factor)).collect(),
            t2: self.t2.scalar_mul(factor),
        }
    }

    /// Return a canonical copy so equality comparisons are representation-safe.
    pub fn canonical(&self) -> Commitment {
        Commitment {
            t1: self.t1.iter().map(Poly::canonical).collect(),
            t2: self.t2.canonical(),
        }
    }
}

#[cfg(test)]
mod bdlop_tests {
    use super::*;
    use crate::crypto::{
        module_lattice::sample_short_vec,
        poly::{N, Q},
    };

    fn message(seed: i32) -> Poly {
        let mut coeffs = [0i32; N];
        for (index, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32) * seed + 1).rem_euclid(Q);
        }
        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn opening_verifies() {
        let key = CommitmentKey::from_seed(b"public");
        let msg = message(11);
        let randomness = sample_short_vec(b"rand", 0, K);
        let commitment = key.commit(&msg, &randomness);
        assert!(key.verify_opening(&commitment, &msg, &randomness));
    }

    #[test]
    fn opening_to_wrong_message_fails() {
        let key = CommitmentKey::from_seed(b"public");
        let randomness = sample_short_vec(b"rand", 0, K);
        let commitment = key.commit(&message(11), &randomness);
        assert!(!key.verify_opening(&commitment, &message(12), &randomness));
    }

    #[test]
    fn opening_with_non_short_randomness_fails() {
        let key = CommitmentKey::from_seed(b"public");
        let msg = message(5);
        // Large (non-short) randomness must be rejected even if it recomputes.
        let mut randomness = sample_short_vec(b"rand", 0, K);
        randomness[0].coeffs[0] = 1000;
        let commitment = key.commit(&msg, &randomness);
        assert!(!key.verify_opening(&commitment, &msg, &randomness));
    }

    #[test]
    fn additively_homomorphic() {
        let key = CommitmentKey::from_seed(b"public");
        let m1 = message(3);
        let m2 = message(7);
        let r1 = sample_short_vec(b"r1", 0, K);
        let r2 = sample_short_vec(b"r2", 0, K);

        let combined = key.commit(&m1, &r1).add(&key.commit(&m2, &r2));

        let mut m_sum = m1;
        m_sum.add_assign(&m2);
        let r_sum = vec_add(&r1, &r2);
        let direct = key.commit(&m_sum, &r_sum);

        assert_eq!(combined.canonical(), direct.canonical());
    }

    #[test]
    fn scalar_homomorphic() {
        let key = CommitmentKey::from_seed(b"public");
        let msg = message(9);
        let randomness = sample_short_vec(b"r", 0, K);
        let factor = 5i64;

        let scaled = key.commit(&msg, &randomness).scalar_mul(factor);
        let direct = key.commit(
            &msg.scalar_mul(factor),
            &crate::crypto::module_lattice::vec_scalar_mul(&randomness, factor),
        );

        assert_eq!(scaled.canonical(), direct.canonical());
    }

    #[test]
    fn commitment_hides_message_bytes() {
        // Structural hiding smoke check: the message part t2 is masked, so a
        // commitment does not equal the raw message.
        let key = CommitmentKey::from_seed(b"public");
        let msg = message(4);
        let randomness = sample_short_vec(b"r", 0, K);
        let commitment = key.commit(&msg, &randomness);
        assert_ne!(commitment.t2.canonical().coeffs, msg.canonical().coeffs);
    }
}
