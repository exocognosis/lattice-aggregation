use lattice_aggregation::crypto::{
    fips_public_key::{FipsModuleSecretShare65, MLDSA65_K, MLDSA65_L},
    poly::Poly,
};

fn main() {
    let local = FipsModuleSecretShare65::new(
        1,
        [Poly::zero(); MLDSA65_L],
        [Poly::zero(); MLDSA65_K],
    )
    .unwrap();
    println!("{local:?}");
}
