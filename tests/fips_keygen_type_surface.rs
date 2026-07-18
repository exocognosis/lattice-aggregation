#[test]
fn fips_keygen_secret_and_public_output_surfaces_fail_closed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/fips_keygen_public_output_no_secret_export.rs");
    tests.compile_fail("tests/ui/fips_keygen_secret_share_no_clone.rs");
    tests.compile_fail("tests/ui/fips_keygen_secret_share_no_debug.rs");
    tests.compile_fail("tests/ui/receiver_custody_no_reconstruction.rs");
}
