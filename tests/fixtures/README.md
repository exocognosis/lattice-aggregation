# ML-DSA-65 Fixture Directory

Place official ACVP ML-DSA / sigVer / FIPS204 JSON vector sets here.

The ignored integration test `official_mldsa65_sigver_kats_pass` reads:

```text
tests/fixtures/ml_dsa_65_sigver_acvp.json
```

or the path supplied by:

```text
DYTALLIX_MLDSA65_SIGVER_KAT=/path/to/vector-set.json
```

The expected schema follows NIST ACVP ML-DSA `sigVer` vector-set JSON for
`parameterSet = "ML-DSA-65"`. The current gate only consumes pure internal
message-verification vectors because the hazmat API does not yet expose context,
prehash, or external-mu verification entry points.
