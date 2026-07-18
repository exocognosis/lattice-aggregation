use lattice_aggregation::crypto::{
    fips_public_key::{
        aggregate_public_key_from_t_shares, evaluate_public_t_share, FipsModuleSecretShare65,
        FipsPublicKeyContext65, ShareAggregation, MLDSA65_K, MLDSA65_L,
    },
    poly::Poly,
};

fn main() {
    let context = FipsPublicKeyContext65::new([0x11; 32], [0x22; 32]);
    let local = FipsModuleSecretShare65::new(
        1,
        [Poly::zero(); MLDSA65_L],
        [Poly::zero(); MLDSA65_K],
    )
    .unwrap();
    let public = evaluate_public_t_share(&context, &local);
    let output = aggregate_public_key_from_t_shares(
        &context,
        &[public],
        ShareAggregation::Additive { expected_shares: 1 },
    )
    .unwrap();

    let _ = output.reconstruct_secret();
    let _ = output.export_secret();
}
