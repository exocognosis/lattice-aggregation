//! Honest DKG→MPC input-binding layer for exact-ExpandMask ML-DSA-65 signing.
//!
//! This module is the data-flow seam between the no-dealer DKG (which produces
//! XOR shares of the private seed `K` and the per-signature randomness `rnd`)
//! and the secret-shared `mldsa65_expandmask` MP-SPDZ circuit (which recomputes
//! `rhopp = SHAKE256(K || rnd || mu)` on secret bits and never opens `K`, `rnd`,
//! or `rhopp`).
//!
//! # Circuit input contract (confirmed)
//!
//! For each signer `p` the circuit reads, from `Input-P{p}-0`, 32 XOR-share
//! bytes of `K` followed by 32 XOR-share bytes of `rnd`, as space-separated
//! integers in `0..=255` (one per byte). Player 0 additionally appends the
//! public 64 `mu` bytes. The XOR of every signer's `K`-share equals `K`; the
//! XOR of every signer's `rnd`-share equals `rnd`. See
//! [`mpc_input_assignment`] for the exact per-player integer sequence the
//! orchestrator writes, which mirrors `write_inputs` in
//! `scripts/run_exact_expandmask_mpc_equivalence.py`.
//!
//! # What the coordinator holds
//!
//! The coordinator carries only *commitments*: per-signer XOR-share commitments
//! ([`share_commitment`] / [`kshare_set_commitments`]) and a single public
//! [`rhopp_commitment`] that stands in for the clear `rhopp`. It binds the
//! chosen MPC mask attempt through [`dkg_mpc_input_binding_digest`] without ever
//! learning `rhopp`.
//!
//! # Honesty boundary
//!
//! This is *not* a claim that the coordinator is rhopp-blind end to end. In the
//! current test harness the [`designated_checker_rhopp`] path reconstructs the
//! clear secret to check functional equivalence against the FIPS oracle. A
//! production deployment replaces that check with the MAMA malicious-security
//! guarantee and never runs it. The no-single-secret gate
//! ([`DkgMpcInputBinding::no_single_secret_signing_path`]) therefore stays
//! `false`.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::backend::fips_sign::SigningSetMember65;

/// Number of bytes in one XOR share of `K` or `rnd` (32 = seed width).
pub const XOR_SHARE_BYTES: usize = 32;
/// Number of public `mu` bytes appended to player 0's MPC input.
pub const MU_BYTES: usize = 64;

/// One XOR-share set for a 32-byte secret: exactly one 32-byte share per signer.
///
/// The XOR of every signer's share reconstructs the shared secret, matching the
/// `input_xor_shared_bytes` accumulation performed inside the
/// `mldsa65_expandmask` circuit. Used for both `K` and `rnd`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XorShareSet32 {
    /// One 32-byte XOR share per signer, in signer (player) order.
    pub shares: Vec<[u8; XOR_SHARE_BYTES]>,
}

impl XorShareSet32 {
    /// Build a share set from a vector of per-signer shares.
    pub fn new(shares: Vec<[u8; XOR_SHARE_BYTES]>) -> Self {
        Self { shares }
    }

    /// Number of signers contributing to this share set.
    pub fn signer_count(&self) -> usize {
        self.shares.len()
    }

    /// Reconstruct the shared 32-byte secret by XORing every signer's share.
    ///
    /// This is the plaintext reconstruction the MPC circuit performs only on
    /// secret bits; calling it in the clear necessarily learns the secret and is
    /// meant for tests / designated-checker equivalence, never for the
    /// coordinator on a production path.
    pub fn xor_reconstruct(&self) -> [u8; XOR_SHARE_BYTES] {
        let mut out = [0u8; XOR_SHARE_BYTES];
        for share in &self.shares {
            for (accumulator, byte) in out.iter_mut().zip(share.iter()) {
                *accumulator ^= *byte;
            }
        }
        out
    }
}

/// Domain-separated commitment to one signer's 32-byte XOR share.
///
/// Binds the share bytes, the signer index, and a caller label (for example
/// `"K"` or `"rnd"`) so a `K`-share and a `rnd`-share at the same signer index
/// never collide. The coordinator can hold and compare commitments without ever
/// seeing the clear share.
pub fn share_commitment(
    share: &[u8; XOR_SHARE_BYTES],
    signer_index: usize,
    label: &str,
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/dkg-mpc-binding/share-commitment/v1");
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update(&(signer_index as u64).to_be_bytes());
    hasher.update(share);
    let mut digest = [0u8; 32];
    hasher.finalize_xof().read(&mut digest);
    digest
}

/// Per-signer commitments for an entire XOR-share set, in signer order.
///
/// Applies [`share_commitment`] to every share, tagging each with its signer
/// index and the shared `label`.
pub fn kshare_set_commitments(set: &XorShareSet32, label: &str) -> Vec<[u8; 32]> {
    set.shares
        .iter()
        .enumerate()
        .map(|(index, share)| share_commitment(share, index, label))
        .collect()
}

/// The exact integer sequence written to `Input-P{player}-0` for the
/// `mldsa65_expandmask` circuit.
///
/// The layout is 32 `K`-share bytes, then 32 `rnd`-share bytes, and — for
/// player 0 only — the public 64 `mu` bytes appended. Each value is a byte in
/// `0..=255` returned as a `u16` (MP-SPDZ reads these as space-separated
/// integers). A non-zero player yields 64 values; player 0 yields 128. This is
/// the byte-for-byte Rust equivalent of `write_inputs` in the Python
/// equivalence runner and is what the orchestrator serializes to disk.
pub fn mpc_input_assignment(
    player: usize,
    k: &XorShareSet32,
    rnd: &XorShareSet32,
    mu: &[u8; MU_BYTES],
) -> Vec<u16> {
    let mut values = Vec::with_capacity(if player == 0 {
        2 * XOR_SHARE_BYTES + MU_BYTES
    } else {
        2 * XOR_SHARE_BYTES
    });
    for &byte in &k.shares[player] {
        values.push(u16::from(byte));
    }
    for &byte in &rnd.shares[player] {
        values.push(u16::from(byte));
    }
    if player == 0 {
        for &byte in mu.iter() {
            values.push(u16::from(byte));
        }
    }
    values
}

/// PUBLIC commitment the coordinator holds INSTEAD of the clear `rhopp`.
///
/// Binds the per-signer `K`-share and `rnd`-share commitments together with the
/// public `mu`. It never touches the clear `K`, `rnd`, or `rhopp`, so the
/// coordinator can carry this value while remaining blind to the secret PRF
/// output that the MPC computes internally. Changing any share commitment or
/// `mu` changes the result.
pub fn rhopp_commitment(
    k_commitments: &[[u8; 32]],
    rnd_commitments: &[[u8; 32]],
    mu: &[u8; MU_BYTES],
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/dkg-mpc-binding/rhopp-commitment/v1");
    hasher.update(&(k_commitments.len() as u64).to_be_bytes());
    for commitment in k_commitments {
        hasher.update(commitment);
    }
    hasher.update(&(rnd_commitments.len() as u64).to_be_bytes());
    for commitment in rnd_commitments {
        hasher.update(commitment);
    }
    hasher.update(mu);
    let mut digest = [0u8; 32];
    hasher.finalize_xof().read(&mut digest);
    digest
}

/// TEST / DESIGNATED-CHECKER ONLY. Reconstructs the clear secret
/// `rhopp = SHAKE256(K || rnd || mu)`.
///
/// This path XORs every signer's share back into the clear `K` and `rnd` and
/// recomputes `rhopp` in the clear. It therefore *necessarily learns the
/// secret*: it exists solely so a designated checker can verify functional
/// equivalence of the MPC circuit against the FIPS 204 oracle in tests. A
/// production deployment replaces this check with the MAMA malicious-security
/// guarantee, so the coordinator never runs it and never learns `rhopp`. The
/// name is deliberately alarming to make any coordinator-side use obviously
/// wrong.
pub fn designated_checker_rhopp(
    k: &XorShareSet32,
    rnd: &XorShareSet32,
    mu: &[u8; MU_BYTES],
) -> [u8; 64] {
    let key = k.xor_reconstruct();
    let randomness = rnd.xor_reconstruct();
    let mut hasher = Shake256::default();
    hasher.update(&key);
    hasher.update(&randomness);
    hasher.update(mu);
    let mut rhopp = [0u8; 64];
    hasher.finalize_xof().read(&mut rhopp);
    rhopp
}

/// Bind the committed DKG `K`/`rnd` shares, the retry counter `kappa_base`, and
/// the ordered signing set into one public digest — WITHOUT any
/// coordinator-known `rhopp`.
///
/// This is the DKG-side analogue of
/// [`crate::backend::fips_sign::additive_mask_input_binding_digest`]: that
/// function binds the secret `rhopp`; this one binds only the per-signer share
/// commitments plus `mu` (or a digest of it), so it ties the DKG shares to a
/// specific MPC mask attempt while the coordinator stays rhopp-blind. The
/// `mu_or_digest` argument accepts either the raw 64-byte `mu` or a digest of
/// it; it is length-prefixed so the two never alias.
pub fn dkg_mpc_input_binding_digest(
    k_commitments: &[[u8; 32]],
    rnd_commitments: &[[u8; 32]],
    mu_or_digest: &[u8],
    kappa_base: u16,
    signing_set: &[SigningSetMember65],
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/dkg-mpc-binding/input-binding/v1");
    hasher.update(&(k_commitments.len() as u64).to_be_bytes());
    for commitment in k_commitments {
        hasher.update(commitment);
    }
    hasher.update(&(rnd_commitments.len() as u64).to_be_bytes());
    for commitment in rnd_commitments {
        hasher.update(commitment);
    }
    hasher.update(&(mu_or_digest.len() as u64).to_be_bytes());
    hasher.update(mu_or_digest);
    hasher.update(&kappa_base.to_le_bytes());
    hasher.update(&(signing_set.len() as u64).to_be_bytes());
    for member in signing_set {
        hasher.update(&member.validator.0.to_be_bytes());
        hasher.update(&member.x.to_be_bytes());
        hasher.update(&member.lagrange_weight.to_le_bytes());
    }
    let mut digest = [0u8; 32];
    hasher.finalize_xof().read(&mut digest);
    digest
}

/// Honest-state summary of the DKG→MPC input-binding layer.
///
/// The flags record exactly what this data-flow layer does and, just as
/// importantly, what it does not. In particular
/// [`DkgMpcInputBinding::coordinator_learns_rhopp_via_designated_checker_in_test`]
/// is `true` because the current test harness reconstructs `rhopp` to check
/// equivalence, and [`DkgMpcInputBinding::no_single_secret_signing_path`] is
/// hard-coded `false`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgMpcInputBinding {
    /// DKG-produced `K`/`rnd` XOR shares are bound to the exact MPC inputs.
    pub dkg_k_shares_bound_to_mpc_inputs: bool,
    /// The coordinator holds only the public `rhopp` commitment, not `rhopp`.
    pub coordinator_holds_rhopp_commitment_only: bool,
    /// TEST ONLY: the designated checker reconstructs `rhopp` in the clear to
    /// verify equivalence against the FIPS oracle. Documented, not production.
    pub coordinator_learns_rhopp_via_designated_checker_in_test: bool,
    /// FAIL-CLOSED. Always `false`: this data-flow layer never establishes a
    /// no-single-secret production signing path on its own.
    pub no_single_secret_signing_path: bool,
}

impl DkgMpcInputBinding {
    /// The honest current state of this layer.
    ///
    /// `no_single_secret_signing_path` is hard-coded `false`; no production /
    /// no-single-secret flag is ever set `true` here.
    pub const fn honest_current() -> Self {
        Self {
            dkg_k_shares_bound_to_mpc_inputs: true,
            coordinator_holds_rhopp_commitment_only: true,
            coordinator_learns_rhopp_via_designated_checker_in_test: true,
            no_single_secret_signing_path: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValidatorId;

    /// The public equivalence fixture: `key = 0..32`, `rnd = 32..64`,
    /// `mu = 64..128`, matching `fixture` in the Python runner.
    fn fixture_secrets() -> ([u8; 32], [u8; 32], [u8; 64]) {
        let mut key = [0u8; 32];
        let mut rnd = [0u8; 32];
        let mut mu = [0u8; 64];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in rnd.iter_mut().enumerate() {
            *byte = (32 + index) as u8;
        }
        for (index, byte) in mu.iter_mut().enumerate() {
            *byte = (64 + index) as u8;
        }
        (key, rnd, mu)
    }

    /// Replicates `xor_shares` from the Python runner so tests exercise a real
    /// multi-signer XOR split whose reconstruction returns `secret`.
    fn xor_split(secret: &[u8; 32], count: usize, label: &[u8]) -> XorShareSet32 {
        let mut shares = Vec::with_capacity(count);
        let mut aggregate = [0u8; 32];
        for player in 0..count - 1 {
            let mut hasher = Shake256::default();
            hasher.update(label);
            hasher.update(&(player as u32).to_le_bytes());
            let mut share = [0u8; 32];
            hasher.finalize_xof().read(&mut share);
            for (accumulator, byte) in aggregate.iter_mut().zip(share.iter()) {
                *accumulator ^= *byte;
            }
            shares.push(share);
        }
        let mut last = [0u8; 32];
        for (index, byte) in last.iter_mut().enumerate() {
            *byte = secret[index] ^ aggregate[index];
        }
        shares.push(last);
        XorShareSet32::new(shares)
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len() / 2)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
            .collect()
    }

    fn shake256_bytes(inputs: &[&[u8]], out_len: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        for input in inputs {
            hasher.update(input);
        }
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; out_len];
        reader.read(&mut out);
        out
    }

    #[test]
    fn xor_shares_reconstruct_known_secret() {
        let (key, _rnd, _mu) = fixture_secrets();
        let shares = xor_split(&key, 4, b"mldsa-expandmask-key-share");
        assert_eq!(shares.signer_count(), 4);
        assert_eq!(shares.xor_reconstruct(), key);

        // A hand-built two-signer split also reconstructs.
        let a = [0xAAu8; 32];
        let mut b = [0u8; 32];
        for (index, byte) in b.iter_mut().enumerate() {
            *byte = key[index] ^ a[index];
        }
        let manual = XorShareSet32::new(vec![a, b]);
        assert_eq!(manual.xor_reconstruct(), key);
    }

    #[test]
    fn designated_checker_rhopp_matches_oracle_and_hardcoded_hex() {
        let (key, rnd, mu) = fixture_secrets();
        let key_set = xor_split(&key, 3, b"mldsa-expandmask-key-share");
        let rnd_set = xor_split(&rnd, 3, b"mldsa-expandmask-rnd-share");

        // Independently computed SHAKE256(key || rnd || mu) truncated to 64 B
        // for key = 0..32, rnd = 32..64, mu = 64..128.
        let expected_hex = "8d3a3a49eb989dd9de155fcd66a2c85fb33b9d0576bec9790af31c0565ee15ec\
1de5870ad28d7f48dfcb11e39118b114565fe73ffdcdd8cb4b23263dcc6da15c";
        let expected = decode_hex(expected_hex);

        let rhopp = designated_checker_rhopp(&key_set, &rnd_set, &mu);
        assert_eq!(rhopp.as_slice(), expected.as_slice());

        // Also equals a direct SHAKE256 over the reconstructed clear secrets.
        let direct = shake256_bytes(&[&key, &rnd, &mu], 64);
        assert_eq!(rhopp.as_slice(), direct.as_slice());
    }

    #[test]
    fn mpc_input_assignment_matches_hand_computed_layout() {
        let mut mu = [0u8; 64];
        for (index, byte) in mu.iter_mut().enumerate() {
            *byte = (64 + index) as u8;
        }
        let k = XorShareSet32::new(vec![[0x11u8; 32], [0x33u8; 32]]);
        let rnd = XorShareSet32::new(vec![[0x22u8; 32], [0x44u8; 32]]);

        // Non-zero player: exactly 64 ints, 32 K bytes then 32 rnd bytes.
        let player1 = mpc_input_assignment(1, &k, &rnd, &mu);
        assert_eq!(player1.len(), 64);
        assert!(player1.iter().all(|&value| value <= 255));
        assert!(player1[..32].iter().all(|&value| value == 0x33));
        assert!(player1[32..].iter().all(|&value| value == 0x44));

        // Player 0: exactly 128 ints, K bytes, rnd bytes, then public mu.
        let player0 = mpc_input_assignment(0, &k, &rnd, &mu);
        assert_eq!(player0.len(), 128);
        assert!(player0.iter().all(|&value| value <= 255));
        assert!(player0[..32].iter().all(|&value| value == 0x11));
        assert!(player0[32..64].iter().all(|&value| value == 0x22));
        for (offset, &byte) in mu.iter().enumerate() {
            assert_eq!(player0[64 + offset], u16::from(byte));
        }
    }

    #[test]
    fn changing_a_share_changes_rhopp_and_input_binding_digests() {
        let (key, rnd, mu) = fixture_secrets();
        let key_set = xor_split(&key, 3, b"mldsa-expandmask-key-share");
        let rnd_set = xor_split(&rnd, 3, b"mldsa-expandmask-rnd-share");

        let signing_set = vec![
            SigningSetMember65 {
                validator: ValidatorId(0),
                x: 1,
                lagrange_weight: 3,
            },
            SigningSetMember65 {
                validator: ValidatorId(1),
                x: 2,
                lagrange_weight: -3,
            },
            SigningSetMember65 {
                validator: ValidatorId(2),
                x: 3,
                lagrange_weight: 1,
            },
        ];

        let k_commitments = kshare_set_commitments(&key_set, "K");
        let rnd_commitments = kshare_set_commitments(&rnd_set, "rnd");
        let base_rhopp_commitment = rhopp_commitment(&k_commitments, &rnd_commitments, &mu);
        let base_binding =
            dkg_mpc_input_binding_digest(&k_commitments, &rnd_commitments, &mu, 0, &signing_set);

        // Flip one byte of one K share; commitments, rhopp commitment, and the
        // input-binding digest must all change.
        let mut mutated_key = key_set.clone();
        mutated_key.shares[1][0] ^= 0x01;
        let mutated_k_commitments = kshare_set_commitments(&mutated_key, "K");
        assert_ne!(k_commitments, mutated_k_commitments);
        assert_ne!(
            base_rhopp_commitment,
            rhopp_commitment(&mutated_k_commitments, &rnd_commitments, &mu)
        );
        assert_ne!(
            base_binding,
            dkg_mpc_input_binding_digest(
                &mutated_k_commitments,
                &rnd_commitments,
                &mu,
                0,
                &signing_set,
            )
        );

        // Flip one byte of one rnd share; same sensitivity.
        let mut mutated_rnd = rnd_set.clone();
        mutated_rnd.shares[2][31] ^= 0x80;
        let mutated_rnd_commitments = kshare_set_commitments(&mutated_rnd, "rnd");
        assert_ne!(rnd_commitments, mutated_rnd_commitments);
        assert_ne!(
            base_rhopp_commitment,
            rhopp_commitment(&k_commitments, &mutated_rnd_commitments, &mu)
        );
        assert_ne!(
            base_binding,
            dkg_mpc_input_binding_digest(
                &k_commitments,
                &mutated_rnd_commitments,
                &mu,
                0,
                &signing_set,
            )
        );

        // Changing kappa_base alone also changes the binding digest.
        assert_ne!(
            base_binding,
            dkg_mpc_input_binding_digest(&k_commitments, &rnd_commitments, &mu, 5, &signing_set)
        );
    }

    #[test]
    fn three_signer_set_round_trips() {
        let (key, rnd, mu) = fixture_secrets();
        let key_set = xor_split(&key, 3, b"mldsa-expandmask-key-share");
        let rnd_set = xor_split(&rnd, 3, b"mldsa-expandmask-rnd-share");

        assert_eq!(key_set.signer_count(), 3);
        assert_eq!(rnd_set.signer_count(), 3);
        assert_eq!(key_set.xor_reconstruct(), key);
        assert_eq!(rnd_set.xor_reconstruct(), rnd);

        let k_commitments = kshare_set_commitments(&key_set, "K");
        let rnd_commitments = kshare_set_commitments(&rnd_set, "rnd");
        assert_eq!(k_commitments.len(), 3);
        assert_eq!(rnd_commitments.len(), 3);

        // Each player's MPC input has the expected length and byte range.
        for player in 0..3 {
            let assignment = mpc_input_assignment(player, &key_set, &rnd_set, &mu);
            let expected_len = if player == 0 { 128 } else { 64 };
            assert_eq!(assignment.len(), expected_len);
            assert!(assignment.iter().all(|&value| value <= 255));
        }

        // The public rhopp commitment is stable across recomputation, and the
        // designated checker reproduces the FIPS oracle rhopp.
        let commitment_a = rhopp_commitment(&k_commitments, &rnd_commitments, &mu);
        let commitment_b = rhopp_commitment(&k_commitments, &rnd_commitments, &mu);
        assert_eq!(commitment_a, commitment_b);
        let rhopp = designated_checker_rhopp(&key_set, &rnd_set, &mu);
        assert_eq!(
            rhopp.as_slice(),
            shake256_bytes(&[&key, &rnd, &mu], 64).as_slice()
        );
    }

    #[test]
    fn honest_state_flags_are_documented_and_fail_closed() {
        let state = DkgMpcInputBinding::honest_current();
        assert!(state.dkg_k_shares_bound_to_mpc_inputs);
        assert!(state.coordinator_holds_rhopp_commitment_only);
        assert!(state.coordinator_learns_rhopp_via_designated_checker_in_test);
        // No production / no-single-secret flag is ever true here.
        assert!(!state.no_single_secret_signing_path);
    }
}
