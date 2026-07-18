# Internal Aggregation Campaign Contract

Status: `preregistered_fail_closed`

This contract defines the reproducible aggregation campaign that must precede
an internal theorem-closure assessment. It does not implement threshold ML-DSA,
fabricate backend output, prove distribution compatibility, or claim theorem or
FIPS closure.

## Conventional artifact paths

All campaign handoff files use one stable directory:

```text
artifacts/internal-aggregation-campaign/latest/request.json
artifacts/internal-aggregation-campaign/latest/request-manifest.json
artifacts/internal-aggregation-campaign/latest/capture.json
artifacts/internal-aggregation-campaign/latest/manifest.json
```

The request, capture, and validation schemas are:

```text
lattice-aggregation:internal-aggregation-campaign-request:v1
lattice-aggregation:internal-aggregation-campaign-capture:v1
lattice-aggregation:internal-aggregation-campaign-validation:v1
```

`manifest.json` is the validator output consumed by the internal evidence bundle
and closure assessor. It binds canonical `request_sha256`, `capture_sha256`, an
`evidence_bundle_binding_sha256`, each evidence file role/digest, the reviewed
authorization-verifier identity, and a deterministic validator-authentication
record. Both downstream consumers re-run the validator over the exact request,
capture, and evidence bytes; a hand-authored ready manifest is rejected.

## Preregistered matrix

The request generator fixes:

- authorization population `n = 10000`;
- authorization threshold `t = 6667`;
- MPC committee-size ladder `8, 16, 32, 64`;
- cases `accepted`, `rejected`, `retry`, `abort`, `malicious_share`, and
  `transcript_mutation` at every committee size;
- eight domain-separated 32-byte test seeds;
- a deterministic message for each of the 24 cases;
- ordinary ML-DSA-65 public-key and signature sizes, including the 3,309-byte
  signature wire format.

The committee is not treated as a substitute for the 10,000-validator
authorization layer. A capture must include a digest-bound authorization
certificate with at least 6,667 distinct authorizers, and every execution must
bind that certificate digest.

The v1 validator parses the certificate, checks canonical validator and
committee membership, derives unique in-set authorizer counts, verifies the
request/session bindings, and checks authorization-signature byte digests. It
does **not** yet implement cryptographic verification of those authorization
signatures. Consequently, the production CLI currently always emits the hard blocker
`cryptographic authorization signature verification unavailable` even for a
structurally complete certificate. Removing that blocker requires a reviewed,
preregistered verifier implementation whose identifier and implementation
SHA-256 are bound into `request.json`. The Python API exposes an injected
callback boundary solely so the full fail-closed promotion path can be tested;
the CLI does not supply one. An operator-supplied `verified: true` flag in
`capture.json` is never accepted.

Generate the request with:

```sh
python3 scripts/build_internal_aggregation_campaign_request.py \
  --campaign-id theorem-closure-internal-001
```

The generator is deterministic: the same campaign identifier produces the same
request bytes and request digest.

When a reviewed authorization verifier exists, bind its identity into the
request before handing the campaign to the external backend:

```sh
python3 scripts/build_internal_aggregation_campaign_request.py \
  --campaign-id theorem-closure-internal-001 \
  --authorization-verifier-id reviewed-ed25519-threshold-authorization-v1 \
  --authorization-verifier-implementation-sha256 \
    "$(python3 scripts/threshold_authorization_verifier.py --implementation-sha256)"
```

## Capture gate

The backend operator must write `capture.json` next to `request.json`. The
validator accepts only:

- `evidence_class = actual_distributed_threshold_mldsa_campaign`;
- `execution_mode = actual_distributed_threshold_backend`;
- `core_mode = distributed_threshold_mldsa65_partial_aggregation`;
- `signature_origin = threshold_partial_aggregation`;
- exact distributed key generation with private per-receiver share custody;
- exact distributed `ExpandMask` MPC, not a summed-uniform approximation;
- live distributed nonce generation, partial signing, partial `z_i`/hint
  aggregation, and the FIPS 204 rejection loop over real partials;
- no secret/seed reconstruction, centralized signing oracle, simulation,
  fixture harness, or single-key provider;
- a clean, Git-tracked source commit with an empty diff and no untracked files;
- locally present, nonempty, SHA-256-bound source, implementation, binary, test,
  proof, authorization, toolchain, environment, transcript, standard-verifier,
  and KAT artifacts;
- NIST ACVP/ACVTS ML-DSA `keyGen`, `sigGen`, and `sigVer` vector results with no
  failures;
- unmodified standard-verifier acceptance for every emitted aggregate and
  rejection of mutated message, public key, and signature;
- one exact execution for every preregistered case.

Evidence paths are relative to `capture.json` and cannot escape the campaign
directory. The validator recomputes every file digest.

Run the gate with:

```sh
python3 scripts/validate_internal_aggregation_campaign_capture.py
```

Exit `0` is reserved for a future validator that verifies all 24 real executions,
all evidence bindings, and the authorization signatures. The current v1 exits
`2`, including for a structurally complete capture, because cryptographic
authorization verification is not implemented. It also writes
`campaign_status = blocked_fail_closed` for a missing, dirty, simulated,
reconstructed, incomplete, mutated, or digest-mismatched campaign.

Even a passing manifest is limited to:

```text
campaign_status = internal_campaign_evidence_ready
theorem_status = unclosed_pending_proof_and_independent_review
claims_theorem_closure = false
claims_fips_validation = false
```

The final assessor also recomputes the theorem bundle's canonical digest,
re-hashes every source/artifact inventory entry, and compares the embedded Git
commit/cleanliness record with the current checkout. The campaign manifest is
an input to the proof bundle. It is not a substitute for the five proof
criteria, formal reductions, or later independent review.

## Exact campaign runner

The repo-side runner executes an external exact distributed ML-DSA campaign
backend and promotes output only after the validator accepts it:

```sh
python3 scripts/run_internal_aggregation_campaign_capture.py \
  --root . \
  --request artifacts/internal-aggregation-campaign/latest/request.json \
  --campaign-out artifacts/internal-aggregation-campaign/latest \
  --run-out artifacts/internal-aggregation-campaign-run/latest \
  --evidence-base /outside/reviewed-campaign-evidence \
  --authorization-verifier ed25519-v1 \
  --backend-command /outside/threshold-backend-p1 run-internal-aggregation-campaign \
    --request artifacts/internal-aggregation-campaign/latest/request.json
```

The backend command must write canonical
`lattice-aggregation:internal-aggregation-campaign-capture:v1` JSON to stdout.
The runner rejects repo-local commands and command lines containing smoke,
fixture, simulation, localnet, single-key, or seed-reconstruction markers.

Successful runs write:

```text
artifacts/internal-aggregation-campaign/latest/capture.json
artifacts/internal-aggregation-campaign/latest/manifest.json
artifacts/internal-aggregation-campaign-run/latest/run-manifest.json
```

Failed or non-admissible runs write only the attempt artifacts under
`artifacts/internal-aggregation-campaign-run/latest/`, including command logs
and either parse blockers or `rejected-capture.json` plus
`rejected-validation.json`. The official campaign capture path remains absent
until the exact distributed backend evidence is validator-ready.
