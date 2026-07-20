# Malicious-MAMA 6,667-party scale runner

`scripts/run_mama_6667_scale.py` is a fail-closed production preflight and
external-orchestrator wrapper for the exact ML-DSA-65 ExpandMask circuit. It
does not classify thousands of local labels, ports, or subprocesses as distinct
cryptographic parties.

## Evidence classes

- `local_simulation_or_preflight_only`: missing production roster/custody data,
  loopback or unverifiable execution, or a bounded local MAMA probe.
- `distributed_nonproduction_probe`: the roster preflight passes, but the
  runner-invoked production execution or completion evidence does not.
- `real_malicious_mama_6667_custodial`: all 6,667 identities, endpoints,
  custody attestations, protocol parameters, signed receipts, logs, transcript,
  output shares, and oracle output pass in one runner-bound invocation.

The command exits `0` only for the final class. Every other result exits `2`
after writing a manifest with false production and theorem-closure flags.

## Signed inventory

The `--inventory` JSON must use
`lattice-aggregation:mama-signer-inventory:v1`. It contains exactly 6,667
parties and an exact MP-SPDZ protocol record. Runtime, source, schedule, and
bytecode paths are relative to the inventory directory and are digest-bound.
Runtime arguments must select `mama-party.x`, `-N 6667`, and at least `-S 40`.

Each party record binds:

- `party_index`, derived `signer_id`, identity public key, transport public key,
  canonical non-loopback endpoint, DKG receiver ID, authorization ID, and a
  unique host-attestation ID;
- a signature by the signer identity over the canonical campaign roster; and
- a production custody-attestation document, detached signature, and custody
  root public key.

Custody roots are not trusted merely because the inventory lists them. Their
SHA-256 digests must be supplied independently with repeated
`--trusted-custody-root-sha256` arguments. Each custody document uses
`lattice-aggregation:production-custody-attestation:v1` and binds the campaign,
party, endpoint, identity, DKG transcript, opaque share handle, share
commitment, signer binary, custody policy, and validity interval. It must attest
non-exportability, process isolation, direct signer consumption, and production
custody.

## Runner-bound execution

`--orchestrator-command-json` names a JSON file containing a command as a string
array. The runner invokes it only after the full roster passes. It supplies:

- `MAMA_CAMPAIGN_RUN_NONCE`
- `MAMA_ROSTER_DIGEST`
- `MAMA_COMPLETION_BUNDLE`

The orchestrator must write the completion bundle during that invocation. A
prior or replayed completion cannot pass because all receipts bind the fresh run
nonce.

The completion bundle uses
`lattice-aggregation:mama-completion-bundle:v1`. It contains 6,667 signed
`lattice-aggregation:mama-party-completion-receipt:v1` receipts, a digest-bound
global transcript, per-party logs and output shares, and two independent binary
outputs: the MPC reconstruction and FIPS-204 oracle. Each output is exactly
1,280 little-endian unsigned 32-bit coefficients in `[0, 8380417)`, and the byte
strings must match exactly.

## Bounded probe

The following reruns the full 1,280-coefficient circuit with two local MAMA
parties at security parameter 40 and then deliberately returns `2` because this
is not scale evidence:

```sh
python3 scripts/run_mama_6667_scale.py \
  --run-bounded-probe \
  --mp-spdz-root /path/to/MP-SPDZ
```

The resulting resource section reports measured two-party values, an optimistic
traffic floor, and a peer-sensitive all-to-all extrapolation. It does not infer
production wall time, CPU, or RAM from a two-party benchmark.
