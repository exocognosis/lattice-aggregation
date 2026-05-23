# ML-DSA-65 Fixture Directory

Place official ACVP ML-DSA / sigVer / FIPS204 JSON vector sets here.

The integration test `official_mldsa65_sigver_kats_pass` reads:

```text
tests/fixtures/ml_dsa_65_sigver_acvp.json
```

or the path supplied by:

```text
DYTALLIX_MLDSA65_SIGVER_KAT=/path/to/vector-set.json
```

The expected schema follows NIST ACVP ML-DSA `sigVer` vector-set JSON for
`parameterSet = "ML-DSA-65"`. The checked-in fixture is the NIST sample
external/pure group `tgId = 3` from
`usnistgov/ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`.
The current gate covers external pure verification, including non-empty
contexts. It skips prehash, internal, and external-mu vectors because the public
hazmat verifier API does not yet expose those entry points.
