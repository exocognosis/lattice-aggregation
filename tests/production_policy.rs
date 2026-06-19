#[test]
fn production_module_is_not_exported_without_gate() {
    assert!(!cfg!(feature = "coordinator-assisted"));
}
