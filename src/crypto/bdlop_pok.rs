//! BDLOP proof of knowledge of a short opening (Fiat-Shamir with aborts).
//!
//! Increment 2b of the real threshold key material build-out
//! (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! A non-interactive zero-knowledge proof, in the Lyubashevsky
//! Fiat-Shamir-with-aborts style, that a prover knows a **short** `r in R_q^K`
//! with `A1 * r = t1` — the binding part of a BDLOP commitment
//! ([`crate::crypto::bdlop`]). This is the well-formedness premise a receiver
//! cannot check directly (revealing `r` would reveal the committed message).
//!
//! ## Protocol (per the locked design spec)
//!
//! Sigma-protocol repeated `REPETITIONS = 15` times under a single (joint)
//! Fiat-Shamir challenge for grinding resistance:
//! - masking `y in R_q^K` with coefficients uniform in `[-B, B]`, `B = 2^16`;
//! - challenge set `{ +-X^i : 0 <= i < 256 }` (size 512), a *monomial
//!   subtractive set* whose differences are invertible in this fully-splitting
//!   ring, so special soundness yields a genuine (relaxed) witness;
//! - response `z = y + d * r`, accepted only if `||z||_inf <= B - 1` (rejection
//!   sampling; global restart on any repetition's abort, ~2 attempts expected);
//! - `t = 15` gives knowledge error `512^-15 ~= 2^-135`.
//!
//! The verifier recomputes `w = A1*z - d*t1` from the responses (so `w` is not
//! transmitted), re-derives the challenge, and checks the norm bound.
//!
//! ## What this closes — and what it does NOT (claim boundary)
//!
//! Proving each commitment's `t1_j` well-formed certifies it is a genuine
//! **relaxed** MSIS image (there exist a short `r_bar_j` and a short invertible
//! slack `c_bar_j` with `A1*r_bar_j = c_bar_j*t1_j`), so a malicious dealer
//! cannot post an out-of-image `t1_j` and equivocate that single commitment.
//! This is a **necessary building block** for malicious-dealer binding.
//!
//! It does **not** by itself deliver VSS extractability. Residual gaps
//! (unchanged by this increment):
//! - **Slack reconciliation:** each `C_j` is extracted with its own slack
//!   `c_bar_j`; per-coefficient slacks do not combine into one sharing
//!   polynomial, so a single `P(x)` is not pinned without a batched / common-
//!   challenge proof.
//! - **Share norm gap:** this bounds the dealer's per-coefficient `rho_j`, not
//!   the aggregated `rho(i)` receivers hold; `verify_share` still enforces no
//!   bound (see `verify_share_does_not_enforce_randomness_shortness`), so
//!   share-binding still needs a norm bound or small evaluation points.
//! - **Public-value link:** the DKG `t^(d) = A s1 + s2` binding is untouched.
//! - MSIS hardness at the relaxed witness norm is parameter-pending (like the
//!   rest of the BDLOP parameter set). Closes no hypothesis criterion; no
//!   production threshold ML-DSA security claim.
//!
//! This is a standalone primitive in this increment: it is not yet wired into
//! [`crate::crypto::vss_bdlop`] or the DKG dealer-acceptance path.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::{
    bdlop::{Commitment, CommitmentKey, K, KAPPA},
    module_lattice::matrix_vec_mul,
    poly::{Poly, N},
};

/// Masking bound `B`: mask coefficients are uniform in `[-B, B]`.
pub const MASK_BOUND: i32 = 1 << 16;
/// Acceptance bound on the response: `||z||_inf <= B - 1`.
pub const RESPONSE_BOUND: i32 = MASK_BOUND - 1;
/// Parallel repetitions; knowledge error `512^-REPETITIONS ~= 2^-135`.
pub const REPETITIONS: usize = 15;
/// Maximum rejection-sampling restarts before giving up (astronomically large
/// margin; honest prover accepts in ~2 attempts).
const RESTART_CAP: usize = 128;

const TRANSCRIPT_LABEL: &[u8] = b"lattice-aggregation/bdlop-pok/transcript/v1";
const CHALLENGE_LABEL: &[u8] = b"lattice-aggregation/bdlop-pok/challenge/v1";
const MASK_LABEL: &[u8] = b"lattice-aggregation/bdlop-pok/mask/v1";
const MASK_SEED_LABEL: &[u8] = b"lattice-aggregation/bdlop-pok/mask-seed/v1";

/// One challenge `d = sign * X^shift` from the monomial set.
#[derive(Clone, Copy, Debug)]
struct Challenge {
    sign: i32,
    shift: usize,
}

/// A non-interactive proof of knowledge of a short opening of `t1`.
///
/// Carries the Fiat-Shamir seed and the `REPETITIONS` response vectors in
/// signed form; the commitments `w` are recomputed by the verifier.
#[derive(Clone, Debug)]
pub struct OpeningProof {
    challenge_seed: [u8; 32],
    responses: Vec<Vec<Poly>>,
}

/// Prove knowledge of the short opening `randomness` (`A1*randomness =
/// commitment.t1`).
///
/// `prover_seed` supplies the masking randomness; distinct attempts derive
/// independent masks so rejection sampling makes progress. Returns `None` only
/// if [`RESTART_CAP`] attempts all abort (probability far below any relevant
/// threshold for an honest prover).
///
/// `randomness` must be a **short** opening (`||randomness||_inf <= 1`, as
/// produced by the hiding VSS): a non-short witness makes every attempt exceed
/// the response bound and `prove` returns `None`.
///
/// # Panics
///
/// Panics if `randomness.len() != K`.
pub fn prove(
    key: &CommitmentKey,
    commitment: &Commitment,
    randomness: &[Poly],
    prover_seed: &[u8; 32],
) -> Option<OpeningProof> {
    assert_eq!(randomness.len(), K, "randomness must have length K");
    let a1 = key.binding_matrix();
    // Bind the masking randomness to the statement and witness so that reusing
    // `prover_seed` across different proofs cannot reuse a mask (which would leak
    // the witness). See the zero-knowledge note in the module docs.
    let mask_seed = derive_mask_seed(prover_seed, &commitment.t1, randomness);

    for attempt in 0..RESTART_CAP {
        let masks: Vec<Vec<Poly>> = (0..REPETITIONS)
            .map(|rep| sample_mask_vector(&mask_seed, attempt, rep))
            .collect();
        let commitments: Vec<Vec<Poly>> =
            masks.iter().map(|mask| matrix_vec_mul(a1, mask)).collect();

        let seed = fiat_shamir_seed(key, &commitment.t1, &commitments);
        let challenges = derive_challenges(&seed);

        let mut responses = Vec::with_capacity(REPETITIONS);
        let mut accepted = true;
        for (mask, challenge) in masks.iter().zip(challenges.iter()) {
            let response = response_vector(mask, *challenge, randomness);
            if !within_response_bound(&response) {
                accepted = false;
                break;
            }
            responses.push(response);
        }

        if accepted {
            return Some(OpeningProof {
                challenge_seed: seed,
                responses,
            });
        }
    }
    None
}

/// Verify an opening proof for `commitment.t1` under `key`.
pub fn verify(key: &CommitmentKey, commitment: &Commitment, proof: &OpeningProof) -> bool {
    if proof.responses.len() != REPETITIONS {
        return false;
    }
    if proof.responses.iter().any(|z| z.len() != K) {
        return false;
    }
    if commitment.t1.len() != KAPPA {
        return false;
    }
    // Norm bound on the signed responses, before any canonicalization.
    if !proof.responses.iter().all(|z| within_response_bound(z)) {
        return false;
    }

    let a1 = key.binding_matrix();
    let challenges = derive_challenges(&proof.challenge_seed);

    // Recompute w = A1*z - d*t1 for each repetition. `t1` is attacker-controlled,
    // so canonicalize it before the monomial multiply to keep coefficients in
    // range (a raw i32::MIN coefficient would otherwise overflow the multiply).
    let recomputed: Vec<Vec<Poly>> = proof
        .responses
        .iter()
        .zip(challenges.iter())
        .map(|(z, &challenge)| {
            let a1_z = matrix_vec_mul(a1, z);
            a1_z.iter()
                .zip(commitment.t1.iter())
                .map(|(a1_z_row, t1_row)| {
                    let mut w = a1_z_row.canonical();
                    w.sub_assign(&monomial_mul(challenge, &t1_row.canonical()).canonical());
                    w
                })
                .collect()
        })
        .collect();

    let recomputed_seed = fiat_shamir_seed(key, &commitment.t1, &recomputed);
    recomputed_seed == proof.challenge_seed
}

/// `z = y + d * r`, component-wise, kept in signed form.
fn response_vector(mask: &[Poly], challenge: Challenge, randomness: &[Poly]) -> Vec<Poly> {
    mask.iter()
        .zip(randomness.iter())
        .map(|(y, r)| {
            let shifted = monomial_mul(challenge, r);
            let mut coeffs = [0i32; N];
            for (out, (&yc, &sc)) in coeffs
                .iter_mut()
                .zip(y.coeffs.iter().zip(shifted.coeffs.iter()))
            {
                *out = yc + sc;
            }
            Poly::from_coeffs(coeffs)
        })
        .collect()
}

/// Multiply `poly` by the monomial challenge `sign * X^shift` (a signed
/// negacyclic rotation), preserving small signed coefficients.
fn monomial_mul(challenge: Challenge, poly: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (j, &value) in poly.coeffs.iter().enumerate() {
        let degree = challenge.shift + j;
        let (index, wrap) = if degree < N {
            (degree, 1)
        } else {
            (degree - N, -1)
        };
        coeffs[index] += challenge.sign * wrap * value;
    }
    Poly::from_coeffs(coeffs)
}

/// True when every coefficient of every component satisfies `|coeff| <=
/// RESPONSE_BOUND` on the signed representative.
fn within_response_bound(response: &[Poly]) -> bool {
    response.iter().all(|poly| {
        poly.coeffs
            .iter()
            .all(|&c| i64::from(c).abs() <= i64::from(RESPONSE_BOUND))
    })
}

/// Fiat-Shamir seed: hash the key, the statement `t1`, and all commitments `w`.
fn fiat_shamir_seed(key: &CommitmentKey, t1: &[Poly], commitments: &[Vec<Poly>]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, TRANSCRIPT_LABEL);
    // Bind the structural dimensions so the byte stream stays unambiguous.
    for dimension in [KAPPA, K, N, REPETITIONS] {
        hasher.update(&(dimension as u64).to_be_bytes());
    }
    for row in key.binding_matrix() {
        for poly in row {
            absorb_poly(&mut hasher, poly);
        }
    }
    for poly in key.message_row() {
        absorb_poly(&mut hasher, poly);
    }
    for poly in t1 {
        absorb_poly(&mut hasher, poly);
    }
    hasher.update(&(commitments.len() as u64).to_be_bytes());
    for commitment in commitments {
        for poly in commitment {
            absorb_poly(&mut hasher, poly);
        }
    }

    let mut seed = [0u8; 32];
    hasher.finalize_xof().read(&mut seed);
    seed
}

/// Expand the Fiat-Shamir seed into `REPETITIONS` monomial challenges.
fn derive_challenges(seed: &[u8; 32]) -> Vec<Challenge> {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, CHALLENGE_LABEL);
    absorb(&mut hasher, seed);
    let mut reader = hasher.finalize_xof();

    let mut challenges = Vec::with_capacity(REPETITIONS);
    let mut buf = [0u8; 2];
    for _ in 0..REPETITIONS {
        reader.read(&mut buf);
        let shift = usize::from(buf[0]); // 0..256 uniform
        let sign = if buf[1] & 1 == 0 { 1 } else { -1 };
        challenges.push(Challenge { sign, shift });
    }
    challenges
}

/// Derive the masking seed, bound to the prover seed, statement `t1`, and
/// witness, so that reusing `prover_seed` across different proofs never reuses a
/// mask (which would leak the witness).
fn derive_mask_seed(prover_seed: &[u8; 32], t1: &[Poly], randomness: &[Poly]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, MASK_SEED_LABEL);
    absorb(&mut hasher, prover_seed);
    for poly in t1 {
        absorb_poly(&mut hasher, poly);
    }
    for poly in randomness {
        absorb_poly(&mut hasher, poly);
    }
    let mut seed = [0u8; 32];
    hasher.finalize_xof().read(&mut seed);
    seed
}

/// Sample a length-`K` masking vector with coefficients uniform in `[-B, B]`.
fn sample_mask_vector(seed: &[u8; 32], attempt: usize, rep: usize) -> Vec<Poly> {
    (0..K)
        .map(|component| sample_mask_poly(seed, attempt, rep, component))
        .collect()
}

fn sample_mask_poly(seed: &[u8; 32], attempt: usize, rep: usize, component: usize) -> Poly {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, MASK_LABEL);
    absorb(&mut hasher, seed);
    hasher.update(&(attempt as u64).to_be_bytes());
    hasher.update(&(rep as u64).to_be_bytes());
    hasher.update(&(component as u64).to_be_bytes());
    let mut reader = hasher.finalize_xof();

    let two_b = 2 * MASK_BOUND; // 131072, fits in 18 bits
    let mut coeffs = [0i32; N];
    let mut filled = 0usize;
    let mut buf = [0u8; 3];
    while filled < N {
        reader.read(&mut buf);
        let candidate = (i32::from(buf[0]) | (i32::from(buf[1]) << 8) | (i32::from(buf[2]) << 16))
            & 0x0003_ffff; // 18 bits: 0..262143
        if candidate <= two_b {
            coeffs[filled] = candidate - MASK_BOUND; // [-B, B]
            filled += 1;
        }
    }
    Poly::from_coeffs(coeffs)
}

fn absorb(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn absorb_poly(hasher: &mut Shake256, poly: &Poly) {
    for coeff in poly.canonical().coeffs {
        hasher.update(&coeff.to_be_bytes());
    }
}

#[cfg(test)]
mod bdlop_pok_tests {
    use super::*;
    use crate::crypto::{module_lattice::sample_short_vec, poly::Q};

    fn setup() -> (CommitmentKey, Commitment, Vec<Poly>) {
        let key = CommitmentKey::from_seed(b"public");
        let randomness = sample_short_vec(b"witness", 0, K);
        let message = {
            let mut coeffs = [0i32; N];
            for (i, c) in coeffs.iter_mut().enumerate() {
                *c = ((i as i32) * 7 + 1).rem_euclid(Q);
            }
            Poly::from_coeffs(coeffs)
        };
        let commitment = key.commit(&message, &randomness);
        (key, commitment, randomness)
    }

    #[test]
    fn honest_proof_verifies() {
        let (key, commitment, randomness) = setup();
        for seed in 0..4u8 {
            let proof = prove(&key, &commitment, &randomness, &[seed; 32]).unwrap();
            assert_eq!(proof.responses.len(), REPETITIONS);
            assert!(verify(&key, &commitment, &proof));
        }
    }

    #[test]
    fn honest_responses_respect_bound() {
        let (key, commitment, randomness) = setup();
        let proof = prove(&key, &commitment, &randomness, &[9u8; 32]).unwrap();
        for response in &proof.responses {
            assert!(within_response_bound(response));
        }
    }

    #[test]
    fn tampered_response_is_rejected() {
        let (key, commitment, randomness) = setup();
        let mut proof = prove(&key, &commitment, &randomness, &[1u8; 32]).unwrap();
        proof.responses[0][0].coeffs[0] += 1;
        assert!(!verify(&key, &commitment, &proof));
    }

    #[test]
    fn out_of_bound_response_is_rejected() {
        let (key, commitment, randomness) = setup();
        let mut proof = prove(&key, &commitment, &randomness, &[2u8; 32]).unwrap();
        proof.responses[0][0].coeffs[0] = MASK_BOUND; // exceeds RESPONSE_BOUND
        assert!(!verify(&key, &commitment, &proof));
    }

    #[test]
    fn tampered_seed_is_rejected() {
        let (key, commitment, randomness) = setup();
        let mut proof = prove(&key, &commitment, &randomness, &[3u8; 32]).unwrap();
        proof.challenge_seed[0] ^= 1;
        assert!(!verify(&key, &commitment, &proof));
    }

    #[test]
    fn proof_for_wrong_commitment_is_rejected() {
        let (key, commitment, randomness) = setup();
        let proof = prove(&key, &commitment, &randomness, &[4u8; 32]).unwrap();

        let other_randomness = sample_short_vec(b"other-witness", 0, K);
        let other = key.commit(&Poly::zero(), &other_randomness);
        assert!(!verify(&key, &other, &proof));
    }

    #[test]
    fn proof_under_wrong_key_is_rejected() {
        let (key, commitment, randomness) = setup();
        let proof = prove(&key, &commitment, &randomness, &[5u8; 32]).unwrap();
        let other_key = CommitmentKey::from_seed(b"different");
        assert!(!verify(&other_key, &commitment, &proof));
    }

    #[test]
    fn fiat_shamir_is_deterministic() {
        let (key, commitment, randomness) = setup();
        let a = prove(&key, &commitment, &randomness, &[7u8; 32]).unwrap();
        let b = prove(&key, &commitment, &randomness, &[7u8; 32]).unwrap();
        assert_eq!(a.challenge_seed, b.challenge_seed);
        for (za, zb) in a.responses.iter().zip(b.responses.iter()) {
            for (pa, pb) in za.iter().zip(zb.iter()) {
                assert_eq!(pa.coeffs, pb.coeffs);
            }
        }
    }

    #[test]
    fn extractor_yields_short_relaxed_opening_with_invertible_slack() {
        // Two transcripts sharing mask y but with distinct challenges d, d' give
        // r_bar = z - z' and c_bar = d - d' with A1*r_bar == c_bar*t1, where
        // c_bar is a short INVERTIBLE slack and r_bar is short (relaxed opening).
        let key = CommitmentKey::from_seed(b"public");
        let a1 = key.binding_matrix();
        let randomness = sample_short_vec(b"witness", 0, K);
        let t1 = matrix_vec_mul(a1, &randomness);

        let mask = sample_mask_vector(&[42u8; 32], 0, 0);
        let d = Challenge { sign: 1, shift: 3 };
        let d_prime = Challenge {
            sign: -1,
            shift: 200,
        };

        let z = response_vector(&mask, d, &randomness);
        let z_prime = response_vector(&mask, d_prime, &randomness);

        // r_bar = z - z'
        let r_bar: Vec<Poly> = z
            .iter()
            .zip(z_prime.iter())
            .map(|(a, b)| {
                let mut coeffs = [0i32; N];
                for (out, (&ac, &bc)) in coeffs.iter_mut().zip(a.coeffs.iter().zip(b.coeffs.iter()))
                {
                    *out = ac - bc;
                }
                Poly::from_coeffs(coeffs)
            })
            .collect();

        // The extracted opening is short: ||r_bar||_inf <= 2*(B+1).
        let relaxed_bound = 2 * i64::from(MASK_BOUND + 1);
        for poly in &r_bar {
            assert!(poly
                .coeffs
                .iter()
                .all(|&c| i64::from(c).abs() <= relaxed_bound));
        }

        // A1 * r_bar == c_bar * t1 with c_bar = d - d'.
        let lhs = matrix_vec_mul(a1, &r_bar);
        let rhs: Vec<Poly> = t1
            .iter()
            .map(|t1_row| {
                let mut value = monomial_mul(d, &t1_row.canonical()).canonical();
                value.sub_assign(&monomial_mul(d_prime, &t1_row.canonical()).canonical());
                value
            })
            .collect();
        for (l, r) in lhs.iter().zip(rhs.iter()) {
            assert_eq!(l.canonical().coeffs, r.canonical().coeffs);
        }

        // The slack c_bar = d - d' = X^3 + X^200 is invertible in R_q: its NTT
        // has no zero coordinate (fully-splitting ring => exceptional set).
        let mut c_bar = [0i32; N];
        c_bar[3] = 1;
        c_bar[200] = 1;
        crate::low_level::ntt::ntt(&mut c_bar);
        assert!(
            c_bar.iter().all(|&slot| slot != 0),
            "challenge-difference slack must be invertible"
        );
    }
}
