# FST-L12: Committee-MPC Cost Model for Exit-1 Threshold ML-DSA-65

Status: engineering estimate (order-of-magnitude). Converts the FST-T4
existence result into a bandwidth/latency budget and a go/no-go gate. Not a
protocol proof; every constant is a labeled model assumption.

Date: 2026-07-14.

## L12-0. Purpose

FST-T4 (`design-space-boundary-theorems.md`) settles that exact threshold
ML-DSA-65 exists for all `t` via MPC, but is silent on cost. The ratified
`epsilon-mask-fork-decision.md` authorizes exactly one route to close the
`epsilon_mask` crux: a scoped heavy-MPC effort on a small committee
(`n ≈ 5–20`). This document estimates whether that route is practical, at what
committee size `k`, and at what blockchain cadence — the go/no-go gate the fork
memo's step 2 (`distributed-mask-mpc-feasibility.md`) requires.

The headline is a single design instruction: **this belongs at
epoch-certificate cadence, not per-block signing.** At that cadence it is
comfortably practical at any committee size up to `k = 128`.

## L12-1. What must run inside MPC (and what must not)

Only the nonlinear core of FIPS 204 signing needs secure evaluation. The rest
is free:

- **Local on shares (no MPC):** `w = A*y` and `z = y + c*s1` are linear;
  each party computes them on its own shares. (Confirmed by the
  verification-identity linearity in `model_fst_algebra_check.py`.)
- **Public, via commit-reveal (no hash-in-MPC):** the challenge `c` is derived
  from `w1`, which is published in the signature anyway. Commit to `w1`, reveal,
  hash in the clear. ~2 rounds, zero secure hashing. This removes the single
  scariest cost item (SHAKE-256 inside MPC).
- **Nonlinear, requires MPC:** `Decompose(w) → (w1, r0)`, the two rejection
  predicates `‖z‖_∞ < γ₁−β` and `‖r0‖_∞ < γ₂−β`, and `MakeHint` with the
  weight bound `≤ ω`. These are comparisons and bit-decompositions.

## L12-2. Model assumptions

| ID | Assumption | Value |
|---|---|---|
| L12-M1 | nonlinear core as comparison-equivalents (CE) per attempt: `Decompose` (1536) + z-norm (1280) + r0-norm (1536) + hint (1536) | 5888 CE/attempt |
| — | expected repetitions (FIPS 204 ML-DSA-65) | `E_rep = 4.25` |
| L12-M2 | one CE = secure multiplications (bit-decomp over 23-bit prime ~ `log₂ q`) | `M_cmp = 24` |
| L12-M3 | bandwidth per secure multiplication per party, 64-bit working ring (`F = 8 B`): king-based Damgård–Nielsen `= 2F` (O(1) in k); naive all-to-all reshare `= (k−1)F` (O(k)) | see table |
| L12-M4 | circuit depth per attempt: `Decompose` (6) + challenge commit-reveal (2) + batched norm checks (6) + hint (4) | 18 rounds/attempt |
| L12-M5 | WAN round-trip per synchronization round | regional 50 ms / global 200 ms |
| L12-M6 | scheduling: sequential (`E_rep` attempts in series) vs speculative (`S` attempts in parallel, keep first accept; `S` sized so `P[all reject] < 2^-20`) | `S = 52` |

Derived: `25024 CE/sig × 24 = 600,576 secure multiplications per signature`.

Only the `‖z‖_∞` check is charged at full weight; the `γ₂` low-bits and hint
predicates are folded in at 1 CE/coeff, which is a floor — a fuller accounting
raises CE counts but does **not** change the round depth (L12-M4), and latency
is depth-bound, so the go/no-go conclusion is robust to L12-M1/M2 being off by
a small factor.

## L12-3. Bandwidth per party per signature

| `k` | king-DN (O(1) in k) | all-to-all (O(k)) |
|---|---|---|
| 8 | 9.6 MB | 33.6 MB |
| 16 | 9.6 MB | 72.1 MB |
| 32 | 9.6 MB | 148.9 MB |
| 64 | 9.6 MB | 302.7 MB |
| 128 | 9.6 MB | 610.2 MB |

**Key result: with a king-based DN multiplication protocol, per-party bandwidth
is flat in `k`** (≈9.6 MB/sig). Committee size is therefore a *security* dial,
not a *bandwidth* dial — you can afford `k = 64–128` for a comfortable honest-
majority margin at no bandwidth cost. Only the naive all-to-all protocol makes
`k` expensive; don't use it.

## L12-4. Latency per signature (depth-bound, independent of `k`)

| schedule | rounds | regional 50 ms | global 200 ms | BW multiplier |
|---|---|---|---|---|
| sequential | 76 | 3.83 s | 15.30 s | ×1 |
| speculative | 18 | 0.90 s | 3.60 s | ×52 |

Latency depends on circuit depth and WAN latency, **not** on `k` or on the
number of comparisons (comparisons in a layer batch). The
latency/bandwidth trade is explicit: speculation cuts latency ~4× but costs
52× bandwidth (500 MB/party/sig at `k=64`). Speculation is only worth it to
chase fast block times; at epoch cadence, sequential is the right choice.

## L12-5. Go / no-go against real cadences

Best case = speculative + regional (0.90 s). Worst case = sequential + global
(15.30 s).

| Target cadence | budget | verdict |
|---|---|---|
| Solana ~0.4 s block | 0.4 s | **NO-GO** (below even best case) |
| Cosmos/Tendermint ~6 s | 6 s | GO — needs speculative + regional |
| Ethereum 12 s slot | 12 s | GO — needs speculative or regional |
| Epoch certificate ~6.4 min | 384 s | **GO — even worst case, sequential + global** |
| Hourly checkpoint | 3600 s | **GO — even worst case** |

## L12-6. The design instruction that falls out

1. **Cadence: epoch certificate, not per block.** At a ~6.4-minute epoch budget
   the worst-case configuration (sequential scheduling, globally distributed
   committee) finishes in 15 s with a 25× margin, using the cheap ×1-bandwidth
   sequential schedule (9.6 MB/party). This is also the *correct* granularity
   for a validator-set certificate: consensus needs one PQ certificate per
   epoch attesting the validator set, not one per transaction. The cost model
   and the product shape agree.
2. **Committee size: `k = 64` (up to 128 free).** Bandwidth is flat in `k` under
   king-DN, so pick `k` for honest-majority security margin, not cost. `k = 64`
   tolerates 31 malicious committee members; the full `n = 10000` validator set
   still governs the `(t, n)` sharing and the per-epoch resharing/sortition into
   the committee, so corruption tolerance is inherited from `t`, not from `k`.
3. **Protocol: king-based DN multiplication, sequential scheduling.** Avoid
   all-to-all (turns `k` into a bandwidth tax) and avoid speculation (52×
   bandwidth) unless a future target genuinely needs sub-slot latency.
4. **Not viable, honestly stated:** per-block signing at high block frequency
   (Solana-class) is out of reach for this route. If per-block PQ signatures are
   ever required, that is a *different* problem than the epoch certificate this
   project targets, and this model says the committee-MPC route does not solve
   it.

## L12-7. What this does and does not establish

- It establishes that the ratified exit-1 route is **practical at epoch
  cadence** and that committee size is not a bandwidth constraint — the two
  facts the fork memo needed to size its charter.
- It does **not** prove security of any concrete MPC instantiation
  (soundness, abort leakage, side channels remain FST-A10-dependent and
  `open`), does not fix the resharing/sortition protocol, and does not cost the
  per-epoch DKG/resharing itself (a separate, less latency-sensitive step).
- Numbers are order-of-magnitude. The conclusions that survive a factor-of-few
  error in L12-M1/M2/M3 are: flat-in-`k` bandwidth (structural, from king-DN),
  epoch-cadence GO with large margin, and per-block NO-GO. The marginal cases
  (Cosmos/Ethereum slot) are the ones sensitive to the constants.

## L12-8. Next artifact

`distributed-mask-mpc-feasibility.md` (fork memo step 2): pin the concrete MPC
primitive list (distributed `ExpandMask` sampling, committed `w = A*y`,
oblivious `Decompose`, oblivious rejection predicates, resharing) and attach
this cost model as its go/no-go gate. Then FST-L12-M1/M2 can be replaced by an
exact gate count from that primitive list, upgrading this estimate toward a
lemma.

## Cross-references

- `docs/cryptography/design-space-boundary-theorems.md` (FST-T4 existence)
- `docs/cryptography/epsilon-mask-fork-decision.md` (ratified exit-1 route)
- `docs/cryptography/epsilon-mask-fork-reconciliation.md`
- `scripts/model_fst_l12_committee_cost.py` (reproduces every number here)
