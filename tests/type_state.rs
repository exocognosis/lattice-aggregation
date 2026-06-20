#[test]
fn invalid_signing_state_calls_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/type_state_invalid_partial.rs");
    tests.compile_fail("tests/ui/type_state_invalid_aggregate.rs");
    #[cfg(feature = "coordinator-assisted")]
    tests.compile_fail("tests/ui/production_simulated_backend_rejected.rs");
}
