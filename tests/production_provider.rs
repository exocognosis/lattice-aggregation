#![cfg(any(feature = "coordinator-assisted", feature = "hazmat-real-mldsa"))]

use lattice_aggregation::{
    production::provider::{StandardMldsa65Provider, UnavailableMldsa65Provider},
    ThresholdError, ThresholdPublicKey, ThresholdSignature,
};

#[test]
fn unavailable_provider_fails_closed() {
    let public_key = ThresholdPublicKey([0; 1952]);
    let signature = ThresholdSignature([0; 3309]);
    let err = UnavailableMldsa65Provider::verify(&public_key, b"msg", &signature).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "standard ML-DSA provider is not enabled",
        }
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn hazmat_provider_fails_closed_until_kat_backed() {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;

    let public_key = ThresholdPublicKey([0; 1952]);
    let signature = ThresholdSignature([0; 3309]);
    let err = HazmatMldsa65Provider::verify(&public_key, b"msg", &signature).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "hazmat ML-DSA provider wrapper requires KAT-backed implementation",
        }
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
#[ignore = "requires checked-in ACVP/FIPS ML-DSA-65 vectors"]
fn hazmat_provider_verifies_mldsa65_kats() {
    panic!("ACVP/FIPS ML-DSA-65 vectors must be checked in before production promotion");
}
