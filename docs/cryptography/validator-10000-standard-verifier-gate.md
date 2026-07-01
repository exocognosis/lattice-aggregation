# 10,000 Validator Standard-Verifier Gate

Status: `blocked_fail_closed`, not standard-verifier equivalence.

Date: 2026-06-30

## Scope

This gate defines the executable target for a 10,000-validator aggregate output
to be treated as one standard-size ML-DSA-65 signature. It is a proof target and
release gate, not evidence that the current deterministic simulation backend
has achieved cryptographic aggregation.

Exact claim boundary:

```text
10,000-validator deterministic fan-in telemetry only; not cryptographic proof; not standard-verifier equivalence; not byte-identical to one validator signature; not production threshold ML-DSA security; blocked until a real threshold ML-DSA backend emits a verifier-accepted aggregate signature
```

## Current Executable Gate

The current test is:

```sh
cargo test --test validator_10000_standard_verifier_gate
```

The gate constructs a deterministic 10,000-validator topology with threshold
6,667 and produces simulated aggregate bytes through `SimulatedBackend`.

Current expected result:

```text
validators = 10000
threshold = 6667
aggregate_signature.len() = 3309
SimulatedBackend::verify_standard(...) = BackendUnavailable
```

This is intentional fail-closed behavior. A passing test today means the repo
correctly refuses to treat deterministic simulated bytes as a standard
ML-DSA-65 signature.

## Future Pass Condition

The cryptographic pass condition is:

```text
aggregate_signature.len() == 3309
MLDSA65.Verify(aggregate_public_key, message, aggregate_signature) == accept
```

In Rust terms, the real backend must satisfy:

```rust
assert_eq!(aggregate_signature.0.len(), 3309);
assert!(HazmatMldsa65Provider::verify(
    &aggregate_public_key,
    message,
    &aggregate_signature
)?);
```

The target is not byte equality with one validator's local signature. The target
is one standard-size aggregate signature that an unmodified ML-DSA-65 verifier
accepts under the aggregate public key and message.

## Promotion Requirements

The gate cannot promote beyond `blocked_fail_closed` until all of the following
are present:

- a real threshold ML-DSA aggregation backend, not `SimulatedBackend`;
- 10,000-validator threshold signing over the selected Profile P1 transcript;
- an aggregate public key and aggregate signature emitted by that backend;
- standard-verifier acceptance through `HazmatMldsa65Provider` or a reviewed
  production provider boundary;
- rejection of mutated message, public key, and aggregate signature bytes;
- linkage to the Criterion 2 standard-verifier compatibility artifact;
- external cryptographic review of the backend and transcript assumptions.

## Real Threshold Backend Emission Gate

The follow-on Criterion 2 contract is the real threshold backend emission ingestion artifact, implemented by
`P1RealThresholdBackendEmissionArtifactPackage`,
`derive_p1_real_threshold_backend_emission_artifact_package`, and
`derive_p1_verified_real_threshold_backend_emission_artifact_package`,
`P1RealThresholdBackendEmissionCapture`, and
`derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture`, and
`assess_p1_real_threshold_backend_emission_artifact` in
`src/production/rejection_equivalence.rs`.

The ingestion artifact is the input path to the stricter threshold verifier
closure contract implemented by `P1RealThresholdVerifierClosurePackage` and
`assess_p1_real_threshold_verifier_closure_contract`. A reviewed emission
certificate can be converted into the closure package with
`to_verifier_closure_package`.

This is a threshold verifier closure contract and real threshold ML-DSA acceptance contract. It requires:

- exactly `validators = 10000` and `threshold = 6667`;
- `aggregate_signature.len() = 3309`;
- `P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa`;
- a backend source package digest, backend implementation digest, and backend
  transcript digest for external review;
- canonical backend-emission capture schema/importer input
  (`lattice-aggregation:p1-real-threshold-backend-emission-capture:v1`) with
  predecessor certificate digests and expected package digest bindings;
- `P1RealThresholdBackendEmissionOutput` material whose public key, message, and
  aggregate signature match the predecessor certificates;
- `MLDSA65.Verify(aggregate_public_key, message, aggregate_signature) == accept`;
- mutated message, public-key, and signature rejection evidence;
- a matching selected-backend threshold-output certificate digest;
- a matching Criterion 2 standard-verifier compatibility artifact digest.

The contract intentionally rejects deterministic simulation as closure evidence.
Claim boundary: real threshold backend emission ingestion only, not ordinary single-key standard-provider output. It is fail-closed, framework/conformance
evidence only, and does not claim production threshold ML-DSA security,
selected-backend proof closure, CAVP/ACVTS validation, FIPS validation,
rejection-distribution preservation, completed standard-verifier compatibility,
or a completed cryptographic proof. It also does not claim a real threshold
backend is implemented in this repository.

The provider-verified backend-output adapter checks standard-verifier
acceptance before deriving a `RealThresholdMldsa` package. That adapter is not a
substitute for backend implementation evidence: without externally generated
real-threshold source, implementation, transcript, accepted aggregate, and
mutation-rejection evidence, the gate remains `blocked_fail_closed`.

The canonical backend-emission capture schema/importer is the JSON handoff for
those externally generated artifacts. It decodes
`P1RealThresholdBackendEmissionCapture`, rejects schema fixtures before tuple
ingestion, requires a nonzero request digest binding, checks predecessor
certificate digests and expected package digests, and feeds the same
provider-verified adapter. This is an executable input gate, not a real
threshold backend and not theorem closure.

Before an external backend emits that capture JSON, the repo can generate the
request it must answer with `scripts/build_backend_emission_request.py`. The
request schema
`lattice-aggregation:p1-real-threshold-backend-emission-request:v1` binds the
message, 10,000-validator target, threshold 6,667, predecessor certificate
digests, required capture schema, required real-threshold backend evidence
class, mutation-rejection requirements, and forbidden localnet/simulation/
fixture sources. This request is a challenge contract for external backend
capture. The capture runner loads the request JSON and rejects backend output
whose embedded request schema/name/SHA-256 binding is missing, stale, or
mismatched; it is not proof closure.

For the current hazmat threshold backend experiment, the repo-owned adapter is
`scripts/run_hazmat_threshold_backend_capture.py`. The adapter requires an
explicit `--backend-crate` path, or
`LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE`, to a `dytallix-pq-threshold` checkout
with `hazmat-real-mldsa`; it then generates a temporary Rust emitter, runs the
10,000-validator threshold session, bridges the session to the standard
external-message verifier boundary, checks backend and repo-provider acceptance,
checks mutated message/public-key/signature rejection, and prints canonical
request-bound capture JSON. It is an opt-in adapter for reviewed backend
capture, not a default CI dependency and not theorem closure.

The checked capture schema fixture at
`tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json`
pins the future capture envelope, but it is explicitly not actual real
threshold backend emission evidence.

The checked fixture harness at
`tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json`
pins this ingestion shape for review and drift detection, but the harness is
classified as `FixtureHarness` and remains blocked from artifact readiness. It
is a harness for future externally captured backend emissions, not actual real
threshold backend emission evidence and not proof closure.

The checked negative-control fixture at
`tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json`
carries actual `ml-dsa`/`HazmatMldsa65Provider` ML-DSA-65 output, including
source, implementation, transcript, accepted signature, and mutation-rejection
digests. The gate still rejects it as `StandardProviderSingleKey`, because a
single-key standard-provider signature is not threshold backend provenance.

The targeted tests are:

```sh
cargo test --features coordinator-assisted --test production_rejection_equivalence p1_real_threshold_backend_emission_ingestion
cargo test --features coordinator-assisted --test production_rejection_equivalence real_threshold_backend_capture
cargo test --features coordinator-assisted --test production_rejection_equivalence real_threshold_backend_emission_artifact_fixture
cargo test --features production-mldsa65-coordinator --test production_rejection_equivalence standard_provider_single_key_emission_fixture
cargo test --features coordinator-assisted --test production_rejection_equivalence p1_real_threshold_verifier_closure_contract
python3 -m unittest script_tests.test_run_hazmat_threshold_backend_capture
```

## Relationship To The Large Simulation Profile

The existing `large` simulation profile already contains `Large Validator Set 10000` with threshold 6,667. That profile is useful for fan-in and byte-count telemetry. It does not provide standard-verifier equivalence because `SimulatedBackend` does not produce or verify real ML-DSA signatures.
