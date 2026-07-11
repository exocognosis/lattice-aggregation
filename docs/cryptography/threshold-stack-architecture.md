# Threshold ML-DSA-65 — Two-Stack Architecture and Roles

Status: architecture decision record. Date: 2026-07-11.

This document records an intentional decision: the repository contains **two
distinct threshold ML-DSA-65 implementation stacks**, and they are kept
separate **on purpose** because they sit on opposite sides of the fundamental
threshold-ML-DSA trade-off. This record fixes their roles, so the split is
deliberate rather than accidental, and names the duplication debt to track.

## Context

Two threshold implementations coexist in the crate. They share one `Poly`
container (`src/low_level/poly.rs`, `[i32; N]`) but use **separate arithmetic
and separate protocols**.

### Stack B — coordinator-assisted, standard-verifier-valid (the *selected* path)

- Files: `src/backend/{fips_sign, real, threshold_core, module_partial,
  algebraic_partial, fips_wire}.rs`, gated behind the `raw-real-mldsa` feature.
- `fips_sign.rs` reimplements FIPS 204 KeyGen + Sign from scratch with a
  **FIPS-ordered NTT** (`ZETA_POW_BITREV`); its public key is byte-equal to the
  `ml-dsa` crate, and its signatures are accepted by the standard `ml-dsa`
  verifier (tested in CI via `--all-features`).
- `real.rs` / `threshold_core.rs` sign via the `ml-dsa` provider.
- **Security model:** the "threshold" is **coordinator seed-reconstruction** —
  the coordinator reconstructs the full secret-key seed and nonce seed in the
  clear, then signs centrally. The `module_partial` / `algebraic_partial`
  algebraic `z = y + c*s1` partials check the identity only (no wire signature);
  `fips_wire` attaches post-hoc `z`-sharing *evidence* to a centrally-produced
  signature.
- **This is the production candidate** (`src/production/selected_backend.rs`
  selects `RealMldsa65Backend`), matching the Profile P1 "coordinator-assisted
  Shamir nonce DKG, TEE/HSM-backed coordinator" direction in the claims matrix.

### Stack A — distributed, no-single-holder (the *aspirational* research path)

- Files: `src/low_level/{poly, ntt, ring}.rs`, `src/crypto/{module_lattice,
  mldsa_module, mldsa_primitives, distributed_nonce, vss_bdlop, bdlop,
  bdlop_pok, mldsa_dkg}.rs`. Always compiled (default features).
- Real distributed cryptography: hiding BDLOP VSS with opening proofs
  (`vss_bdlop` + `bdlop_pok`), a **multi-dealer DKG** producing `t = A s1 + s2`
  with no single key holder (`mldsa_dkg`), and an **additive, no-dealer
  distributed nonce** (`distributed_nonce`).
- Its NTT (`low_level/ntt.rs`, `zeta = 1753`, runtime table) is a correct ring
  multiplication but is **not** FIPS-byte-ordered, so this stack does not (and
  cannot, as-is) emit a wire-format signature a FIPS verifier reads.
- **Security model:** no single party knows the secret key or the joint mask
  `y`. But the additive nonce leaves `epsilon_mask` open (the aggregate mask is
  a sum of uniforms, not `ExpandMask`-uniform), so the standard verifier would
  reject the aggregate response — pinned by
  `distributed_nonce::aggregate_mask_exceeds_gamma1_epsilon_mask_open`.

## The core trade-off

| | Mask `y` | `epsilon_mask` | Standard-verifier valid? | Who knows key / nonce |
| --- | --- | --- | --- | --- |
| **Stack B** | single `ExpandMask` sample | 0 (none) | **Yes** (checked vs `ml-dsa`) | coordinator reconstructs everything |
| **Stack A** | additive `sum_i y_i` | **open** | **No** (would be rejected) | no single party |

Neither stack closes both goals. **The gap between them — closing
`epsilon_mask` for an additive/no-trust nonce while preserving standard-verifier
validity — is the genuinely hard, open research problem this project studies.**
Closing it requires either distributed *uniform* mask sampling (heavy MPC, exact
`epsilon_mask = 0`) or a distribution change to a non-standard verifier
(Raccoon-style). Both are out of scope of both stacks today.

## Decision

1. **Stack B is canonical for the production/valid-signature track.** It is the
   selected Profile P1 backend, the only path that emits `ml-dsa`-verified
   signatures, and the one the `production/` evidence pipeline and the
   `threshold_backend_p1` binary consume. It buys validity with a trusted
   coordinator (the explicit P1 TEE/HSM assumption).
2. **Stack A is canonical for the distributed/no-trust research track.** It is
   where the "no single party holds the key or nonce" security property lives
   (hiding VSS, multi-dealer DKG, no-dealer nonce). It is honest research
   scaffolding: it surfaces `epsilon_mask` rather than closing it, and is not
   wired into the `production/` pipeline.
3. **The two stacks must not be presented as converged.** Stack A must never be
   read as producing a valid signature; Stack B must never be read as a
   distributed-secret scheme (its coordinator sees everything). The A-vs-B split
   *is* the `epsilon_mask` boundary in the Epsilon Residual Ledger.

## Duplication debt (tracked, not yet consolidated)

The two stacks re-implement several primitives. This is a drift hazard to track;
consolidating onto Stack B's FIPS-exact primitives (over the shared `Poly`) is a
future option, deliberately **not** taken now because it would retire recently
merged Stack A work and is not required for Stack A's ring-product correctness.

| Primitive | Stack A | Stack B | Notes |
| --- | --- | --- | --- |
| NTT / negacyclic mul | `low_level/ntt.rs` (non-FIPS order) | `fips_sign.rs` (FIPS order) | only B is wire-exact |
| Decompose / HighBits / LowBits / Power2Round | `mldsa_primitives.rs` | `fips_sign.rs` | ×2 |
| SampleInBall | `mldsa_primitives.rs` | `module_partial.rs` + `fips_sign.rs` | ×3 |
| gamma1 / ExpandMask sampler | `mldsa_primitives.rs` (20-bit) | `module_partial.rs` (research) + `fips_sign.rs` (FIPS bit-pack) | only `fips_sign` is FIPS-exact |
| Shamir split | `feldman_vss.rs`, `vss_bdlop.rs` | `real.rs`, `module_partial.rs`, `algebraic_partial.rs` | ×5 |
| Partial `z_i` / aggregation / rejection / standard verify | absent | `module_partial` / `threshold_core` / `fips_wire` | Stack B only |

## Consequences for requirement #3 (partial signing)

Partial signing (`z_i = y_i + c*s1_i`) **already exists on Stack B**
(`module_partial` / `algebraic_partial`), so it is not "unbuilt." Building it on
Stack A would be a **research demonstration of the distributed, no-dealer
partial** that composes with the Stack A distributed nonce and VSS shares — but
it stays `epsilon_mask`-open (no valid signature). Whether to build Stack A's #3
(aspirational) or invest further in Stack B's #3 (production) is the next
decision; this record does not pre-empt it, only makes the choice explicit.
