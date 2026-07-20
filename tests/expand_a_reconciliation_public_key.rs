#![cfg(feature = "raw-real-mldsa")]

//! Deliverable 2: wire-public-key-from-shares derivation.
//!
//! `wire_public_key_from_module_secret(rho, secret)` must return the identical
//! 1,952-byte ML-DSA-65 public key that `keygen_from_seed` produces for the same
//! `(rho, s1, s2)`. Because the wire public key is `pkEncode(rho, t1)` with
//! `t = A*s1 + s2` and the wire path derives `A` from its own (private) byte-exact
//! `ExpandA`, this byte-equality also transitively proves the module
//! `expand_a_fips_ntt` matrix equals the wire matrix. A second, independent check
//! against the standard `ml-dsa` provider verifying key removes the shared-code
//! escape hatch entirely.

use lattice_aggregation::{
    crypto::mldsa_module::{wire_public_key_from_module_secret, SecretKey},
    keygen_from_seed, MLDSA65_PUBLICKEY_BYTES,
};
use ml_dsa::{Keypair, MlDsa65, SigningKey};

const SEEDS: [[u8; 32]; 5] = [
    [0x00; 32],
    [0x11; 32],
    [0x80; 32],
    seq_seed(),
    inv_seq_seed(),
];

const fn seq_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        seed[i] = i as u8;
        i += 1;
    }
    seed
}

const fn inv_seq_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        seed[i] = 0xffu8.wrapping_sub(i as u8);
        i += 1;
    }
    seed
}

#[test]
fn expand_a_reconciliation_wire_public_key_matches_keygen_and_provider() {
    for seed in SEEDS {
        let wire = keygen_from_seed(&seed).expect("centralized wire KeyGen must succeed");
        let secret = SecretKey {
            s1: wire.s1.to_vec(),
            s2: wire.s2.to_vec(),
        };

        let derived = wire_public_key_from_module_secret(&wire.rho, &secret)
            .expect("module secret -> wire public key derivation");

        assert_eq!(derived.len(), MLDSA65_PUBLICKEY_BYTES);
        assert_eq!(MLDSA65_PUBLICKEY_BYTES, 1_952);
        assert_eq!(
            derived, wire.public_key.0,
            "module-derived wire public key must equal keygen_from_seed for seed {seed:02x?}"
        );

        // Independent ground truth: the standard ml-dsa provider verifying key.
        let provider = SigningKey::<MlDsa65>::from_seed(&seed.into());
        assert_eq!(
            derived.as_slice(),
            provider.verifying_key().encode().as_slice(),
            "module-derived wire public key must equal the standard ml-dsa provider key"
        );
    }
}

#[test]
fn expand_a_reconciliation_wire_public_key_rejects_wrong_shape() {
    let wire = keygen_from_seed(&[0x42; 32]).expect("wire KeyGen");
    let malformed = SecretKey {
        s1: Vec::new(),
        s2: wire.s2.to_vec(),
    };
    assert!(wire_public_key_from_module_secret(&wire.rho, &malformed).is_err());
}
