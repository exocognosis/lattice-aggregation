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
`parameterSet = "ML-DSA-65"`. The checked-in fixture contains the NIST sample
groups `tgId = 3`, `tgId = 9`, and `tgId = 10` from
`usnistgov/ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`.
The current gate covers external pure verification, internal message
verification, and internal verification with caller-supplied external `mu`.
It skips external prehash vectors because the public hazmat verifier API does
not yet expose hash OID handling.
