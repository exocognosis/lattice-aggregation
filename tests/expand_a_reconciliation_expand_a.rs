//! Deliverable 1: byte-exact FIPS 204 `ExpandA` in the module layer.
//!
//! `crate::crypto::mldsa_module::expand_a_fips_ntt` must reproduce the wire
//! signing path's `ExpandA` (`SHAKE128(rho || s || r)` with 3-byte rejection into
//! the NTT domain) byte-for-byte. The wire `rej_ntt_poly` is private to
//! `src/backend/fips_sign.rs` (which this work must not modify), so this test
//! compares against an INDEPENDENT known-answer recomputation of the identical
//! FIPS 204 sampling. End-to-end equality against the wire path itself is pinned
//! separately by the public-key reconciliation test, whose byte-match against
//! `keygen_from_seed` transitively proves the two `ExpandA` matrices agree.

use lattice_aggregation::crypto::{
    mldsa_module::{expand_a_fips_ntt, MODULE_K, MODULE_L},
    poly::{N, Q},
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

/// Independent FIPS 204 `ExpandA` entry: `SHAKE128(rho || s || r)` with 3-byte
/// rejection sampling. Written from the FIPS 204 spec, not from either
/// implementation under test.
fn reference_expand_a_entry(rho: &[u8; 32], s: u8, r: u8) -> [u32; N] {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[s]);
    hasher.update(&[r]);
    let mut reader = hasher.finalize_xof();

    let mut out = [0u32; N];
    let mut filled = 0usize;
    let mut buf = [0u8; 3];
    while filled < N {
        reader.read(&mut buf);
        let candidate =
            (u32::from(buf[2] & 0x7f) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[0]);
        if candidate < Q as u32 {
            out[filled] = candidate;
            filled += 1;
        }
    }
    out
}

#[test]
fn expand_a_reconciliation_expand_a_matches_fips204_known_answer() {
    let rhos: [[u8; 32]; 5] = [
        [0x00; 32],
        [0xff; 32],
        [0x80; 32],
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1)),
    ];

    for rho in &rhos {
        let a = expand_a_fips_ntt(rho);
        assert_eq!(a.len(), MODULE_K, "ExpandA must be a K-row matrix");
        for r in 0..MODULE_K {
            assert_eq!(a[r].len(), MODULE_L, "ExpandA rows must be L wide");
            for s in 0..MODULE_L {
                assert_eq!(
                    a[r][s],
                    reference_expand_a_entry(rho, s as u8, r as u8),
                    "A_hat[{r}][{s}] must equal the FIPS 204 ExpandA known answer for rho {rho:02x?}"
                );
            }
        }
    }
}
