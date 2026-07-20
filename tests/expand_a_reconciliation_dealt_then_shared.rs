#![cfg(feature = "raw-real-mldsa")]

//! Deliverable 3: the honest boundary — dealt-then-shared, NOT dealerless.
//!
//! What is honestly delivered: a single, VALID, FIPS-204-short secret is dealt
//! once (trusted setup) and Shamir-shared across receivers. The test shows
//! (a) the byte-exact wire public key derives correctly from the shared secret,
//! and (b) each receiver holds only a share — any sub-threshold set fails closed.
//!
//! What remains OPEN and is NOT claimed: the multi-dealer DKG forms the joint key
//! by SUMMING dealer contributions, so the joint `s1`/`s2` coefficients grow past
//! the FIPS-204 bound `[-ETA, ETA] = [-4, 4]`. The second test pins that growth
//! as a public, checkable fact: a summed key is not a valid FIPS ML-DSA secret
//! key, and dealerless generation of a FIPS-valid short secret with no single
//! holder is an open research problem, not solved here.

use lattice_aggregation::{
    crypto::{
        bdlop::CommitmentKey,
        mldsa_dkg::{reconstructed_joint_secret_centered_infinity_norm, DkgCoordinator},
        mldsa_module::{
            deal_secret_key, wire_public_key_from_module_secret, SecretKey, ETA, MODULE_K, MODULE_L,
        },
        poly::Q,
    },
    keygen_from_seed,
};

fn center(value: i32) -> i32 {
    let mut reduced = value.rem_euclid(Q);
    if reduced > Q / 2 {
        reduced -= Q;
    }
    reduced
}

fn is_fips_short(secret: &SecretKey) -> bool {
    secret
        .s1
        .iter()
        .chain(secret.s2.iter())
        .all(|poly| poly.coeffs.iter().all(|&coeff| center(coeff).abs() <= ETA))
}

#[test]
fn expand_a_reconciliation_dealt_then_shared_reconstructs_and_hides() {
    let seed = [0x5cu8; 32];
    let wire = keygen_from_seed(&seed).expect("wire KeyGen");
    let secret = SecretKey {
        s1: wire.s1.to_vec(),
        s2: wire.s2.to_vec(),
    };

    // The dealt secret is a genuine FIPS-204 short secret (from ExpandS).
    assert_eq!(secret.s1.len(), MODULE_L);
    assert_eq!(secret.s2.len(), MODULE_K);
    assert!(
        is_fips_short(&secret),
        "the dealt ExpandS secret must lie within [-ETA, ETA]"
    );

    // (a) The byte-exact wire public key derives from the single valid secret.
    let wire_pk = wire.public_key.0;
    assert_eq!(
        wire_public_key_from_module_secret(&wire.rho, &secret).expect("derive wire pk"),
        wire_pk
    );

    // Shamir-share the valid secret across 5 receivers with threshold 3.
    let commit_key = CommitmentKey::from_seed(b"expand-a-reconciliation/dealt-then-shared/v1");
    let (shared, proofs) = deal_secret_key(&secret, 3, 5, &[0xa7u8; 32], &commit_key)
        .expect("deal valid short secret");
    assert!(shared.verify(&commit_key), "all shares must verify");
    assert!(
        shared.verify_commitment_proofs(&proofs, &commit_key),
        "all commitment proofs must verify"
    );

    // A threshold subset reconstructs the SAME valid short secret, and its wire
    // public key still matches byte-for-byte.
    let recovered = shared
        .reconstruct(&[1, 3, 5])
        .expect("threshold reconstruction");
    assert_eq!(recovered.canonical(), secret.canonical());
    assert!(
        is_fips_short(&recovered),
        "reconstructed secret must still be FIPS-204 short"
    );
    assert_eq!(
        wire_public_key_from_module_secret(&wire.rho, &recovered).expect("derive wire pk"),
        wire_pk,
        "wire public key must derive correctly from the Shamir-shared secret"
    );

    // (b) Each receiver holds only a share: any sub-threshold set fails closed.
    assert!(
        shared.reconstruct(&[1, 2]).is_err(),
        "two shares (< threshold 3) must not reconstruct"
    );
    assert!(
        shared.reconstruct(&[4]).is_err(),
        "a single share must not reconstruct"
    );
}

#[test]
fn expand_a_reconciliation_dkg_joint_key_exceeds_fips_short_bound() {
    // HONEST BOUNDARY: the multi-dealer DKG sums dealer contributions, so the
    // reconstructed joint secret grows past [-ETA, ETA]. This is exactly why a
    // dealerless FIPS-valid short secret is an open problem, not solved here.
    let commit_key = CommitmentKey::from_seed(b"public");
    let coordinator = DkgCoordinator::new([0x31u8; 32], 2, 3, commit_key);
    let contributions = vec![
        coordinator.deal(0, &[0x10u8; 32]).expect("dealer 0"),
        coordinator.deal(1, &[0x11u8; 32]).expect("dealer 1"),
    ];
    let output = coordinator.finalize(&contributions).expect("finalize DKG");

    let joint_norm = reconstructed_joint_secret_centered_infinity_norm(&output, &[1, 3])
        .expect("reconstruct joint secret");
    assert!(
        joint_norm > ETA,
        "summed DKG joint secret must exceed the FIPS-204 short bound ETA={ETA}, got {joint_norm}"
    );
}
