# Blocker Closure Status

Date: 2026-07-10

## Scope

Status of the six historical gaps between seed-reconstruction scaffolding and
a full threshold ML-DSA-65 backend. Engineering paths live in:

- `src/crypto/feldman_vss.rs`
- `src/backend/threshold_core.rs`
- `src/backend/real.rs`

Machine-readable status: `ThresholdMldsaEngine::blocker_status()`.

## Status Table

| Blocker | Engineering | Proof / audit | Notes |
| --- | --- | --- | --- |
| Seed-share reconstruction | **Closed** | partial | Transitional core still valid |
| Distributed nonce DKG (live) | **Closed** | open | Live Shamir nonce VSS + attempt IDs; not TEE-attested entropy |
| Partial `z_i` over sk shares | **Closed (seed layer)** | open | Verified sk/nonce seed-share contributions; CLI: `emit-threshold-core-capture` |
| Algebraic poly partial `z_i` | **Closed (single `R_q` poly)** | open | `src/backend/algebraic_partial.rs` |
| Algebraic module-vector partial | **Closed (composition)** | open | `src/backend/module_partial.rs` — `z=y+c·s1` over `R_q^L` |
| FIPS wire packing + threshold z | **Closed (provider bridge)** | open | `src/backend/fips_wire.rs` — Sign_internal wire sig + unpack/share/reconstruct wire `z`; **not** self-contained pack from s1/y partials alone |
| Aggregate partials + hints | **Closed** | open | Lagrange reconstruct → FIPS `Sign_internal`; hints inside standard sig |
| FIPS rejection over partials | **Partial** | open | Outer attempt retry + provider-internal Fiat-Shamir-with-aborts on reconstructed distributed `rnd`; per-partial predicates remain open |
| Binding DKG/VSS | **Closed (hash VSS)** | open | Coefficient + share commitments; not UC / DL-Feldman / audited CT |
| Malicious-secure DKG/VSS | **Open** | open | Requires external proof/audit and stronger adversarial model |
| Closed proofs + audits | **Open** | **Open** | Cannot be closed by repository code alone |

## What “closed” means here

**Engineering closed** means a live, tested library path exists that:

1. Generates and verifies the relevant objects.
2. Produces standard-verifier-compatible ML-DSA-65 signatures on the happy path.
3. Records honest flags for residual limitations.

**Proof/audit closed** means an independent cryptographic proof package and
external review accept the construction. That work is **out of band**.

## Residual (must stay open until external work)

1. **Self-contained FIPS Sign_internal from s1/y partials** — bit-exact ExpandA /
   HighBits / MakeHint without calling the provider for the final pack.
2. **Formal EUF-CMA / epsilon residual theorems** for the five criteria.
3. **Side-channel / constant-time audit**.
4. **Full KAT / CAVP / FIPS lab validation**.
5. **Independent cryptographic review** of the VSS + nonce-DKG + reconstruction
   composition.
6. **TEE/HSM attestation** for dealer and coordinator randomness.

## API entry point

```rust
use lattice_aggregation::ThresholdMldsaEngine;

let status = ThresholdMldsaEngine::blocker_status();
assert!(status.engineering_blockers_closed());
assert!(!status.fully_closed()); // proofs + audits remain open

let out = ThresholdMldsaEngine::threshold_sign_with_live_nonce_dkg(
    &seed, t, &validators, message, dealer_rand, &attempt_rands,
)?;
```

## CLI capture

```bash
# Large-scale reconstruction evidence (legacy ledger flags still honest for that path)
cargo run --features raw-real-mldsa --bin threshold_backend_p1 -- \
  emit-backend-capture --request artifacts/backend-emission-request/latest/request.json \
  --out-dir /tmp/p1-recon

# Live threshold-core engineering path (small committee, new ledger flags)
cargo run --features raw-real-mldsa --bin threshold_backend_p1 -- \
  emit-threshold-core-capture --request artifacts/backend-emission-request/latest/request.json \
  --out-dir /tmp/p1-core
```

`emit-threshold-core-capture` reports `blocker_status` and flips live-nonce,
seed-layer partial, and module-vector composition engineering flags to true while
keeping `production_approved: false`. It keeps FIPS wire packing from module
partials, no-export security, proofs, and audits open.

## Claim boundary (do not over-claim)

May say:

- Live distributed nonce DKG and binding key VSS exist in-tree.
- Partial contributions over secret-key seed shares are implemented and tested.
- Aggregation produces standard ML-DSA-65 signatures that verify.
- Algebraic module-vector partial composition is implemented and tested.
- FIPS rejection sampling runs via `Sign_internal` with reconstructed distributed `rnd`.

Must not say:

- Production threshold ML-DSA security is proved.
- FIPS wire signatures are produced directly from module-vector partials.
- Coordinator no-export security is proved; the current seed-layer path reconstructs seed material in-process.
- Malicious-secure VSS/DKG is proved.
- Audits or FIPS validation are complete.
- `production_approved` may be flipped to true.
