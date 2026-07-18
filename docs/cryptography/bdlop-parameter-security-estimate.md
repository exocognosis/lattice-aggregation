# BDLOP Commitment Parameter Security Estimate

Status: analytical core-SVP estimate (lattice-estimator NOT run — unavailable in
this environment). This is reviewer-orientation evidence, **not a closed security claim** and **not** a substitute for the lattice-estimator or external review.

Date: 2026-07-12

Scope: validates the "chosen-not-validated" BDLOP module-lattice commitment
parameters used by `src/crypto/bdlop.rs` (Increment 2 of the real threshold key
material build-out). Addresses the open flag in the module docstring
(`bdlop.rs:38-44`) that `KAPPA`, `K`, and the ternary randomness bound are a
"chosen research parameter set pending concrete lattice-estimator validation,"
with hiding (Module-LWE) called out as the likelier constraint.

---

## 1. Executive verdict

| Property | Reduces to | Est. classical bits | Est. quantum bits | Meets ~192-bit target? |
|---|---|---:|---:|---|
| **Hiding** | Module-LWE / decisional knapsack | **~236** | **~214** | Yes (with margin) |
| **Binding** | Module-SIS | **≫ 2000** (statistically unconditional) | ≫ 2000 | Yes (overwhelmingly) |

- **Both properties meet the NIST Level 3 (~192-bit classical) target** under the
  standard analytical core-SVP model.
- **Hiding is the binding constraint** (the lower of the two), exactly as project
  memory anticipated — but it still clears the target by roughly a 44-bit
  classical / 22-bit quantum margin.
- **Binding is effectively statistical**: by a counting argument no admissible
  ternary opening collision exists at all (see §6), so binding does not rely on
  Module-SIS hardness in this regime.
- **Single most important recommendation**: replace this analytical estimate with
  an actual lattice-estimator run plus external review before any hiding-based
  security claim is closed (e.g. the `partial_contribution_soundness` criterion).
  The core-SVP model omits refinements (dual-hybrid, small/sparse-secret guessing)
  that can erode the hiding margin; 236 bits is comfortable but not a proof.

---

## 2. Extracted parameters (exact, from source)

Ring and modulus (`src/low_level/poly.rs:13-15`, re-exported as
`crate::crypto::poly` via `src/crypto.rs:7-8`):

| Symbol | Value | Source |
|---|---|---|
| Ring | `R_q = Z_q[X] / (X^256 + 1)` (negacyclic) | `poly.rs:4,124` |
| `N` (ring degree) | `256` | `poly.rs:13` |
| `q` (modulus) | `8 380 417` = 2^23 − 2^13 + 1 (the ML-DSA modulus); `log2 q = 22.9986` | `poly.rs:15` |

Commitment structure (`src/crypto/bdlop.rs`):

| Symbol | Value | Meaning | Source |
|---|---|---|---|
| `KAPPA` | `4` | Module-SIS binding height — rows of `A1` | `bdlop.rs:52` |
| `K` | `12` | randomness width — short ring elements per opening | `bdlop.rs:54` |
| `ELL` | `1` | message slots — `a2` is a single row `R_q^{1×K}` | `bdlop.rs:10,89` |
| `RANDOMNESS_INF_NORM` | `1` | infinity-norm bound on honest randomness | `bdlop.rs:56` |

Public key: uniform `A1 ∈ R_q^{KAPPA×K} = R_q^{4×12}` and `a2 ∈ R_q^{1×12}`,
expanded from a public seed via SHAKE256 rejection sampling of 23-bit,
`< q` candidates (`module_lattice.rs:81-101`).

Commitment: `t1 = A1·r` (height `KAPPA`), `t2 = ⟨a2, r⟩ + m` (`bdlop.rs:109-115`).

Randomness distribution `r ∈ R_q^K`: **ternary, uniform over `{-1, 0, 1}`**, one
coefficient at a time by SHAKE256 with rejection (byte `& 0x03`: `0→0`, `1→+1`,
`2→-1`, `3→reject`; `module_lattice.rs:138-170`). Each coefficient is uniform on
`{-1,0,1}`, so per-coordinate variance is `2/3` and `σ = sqrt(2/3) ≈ 0.8165`.
Shortness is enforced only in `verify_opening` (`bdlop.rs:122-138`,
`check_noise_bounds(RANDOMNESS_INF_NORM + 1)` ⇒ `|coeff| ≤ 1`); the raw `commit`
path does not re-check it.

### Flattened (over `Z_q`) dimensions used below

| Quantity | Formula | Value |
|---|---|---:|
| Total randomness coordinates | `K·N` | 3072 |
| Binding constraints (SIS) | `KAPPA·N` | 1024 |
| Rows seen by a hiding distinguisher | `(KAPPA+ELL)·N` | 1280 |
| Hiding secret dim after HNF reduction | `(K − (KAPPA+ELL))·N` | 1792 |

### ML-DSA-65 context / security target

The system targets **NIST security Level 3** (ML-DSA-65, Category 3, ≈ 192-bit
classical), with public-key size 1952 B and signature size 3309 B
(`docs/cryptography/thesis-operating-parameters.md:42-52`). The operating-parameters
doc states a claim boundary rather than a numeric bit target; it flags
`partial_contribution_soundness` as requiring "VSS/DKG binding and hiding proof
artifacts" (`thesis-operating-parameters.md:75-77`). This estimate is one input to
that artifact, not the artifact itself. For calibration, ML-DSA-65's own MLWE/MSIS
core-SVP hardness is roughly 165–185 classical bits in the literature, so the
commitment layer analyzed here is **not** the weakest link relative to the
signature scheme it supports.

---

## 3. Methodology and tooling status

**Lattice-estimator was NOT available in this environment.** `which sage` →
not found; `python3 -c "import estimator"` → `ModuleNotFoundError`. Per the task
fallback, security is therefore estimated with the standard **analytical
core-SVP model** (Alkim–Ducas–Pöppelmann–Schwabe "2016 estimate" for primal
uSVP, and the Dilithium/CRYSTALS-style q-ary SIS estimate). All intermediate
numbers below are fully reproducible from the formulas and inputs given in this
document with only Python's `math` (no external packages).

Core-SVP cost model (single-block BKZ-β, sieving): given the required BKZ block
size β, the cost is taken as

- classical bits ≈ **0.292·β**,
- quantum bits ≈ **0.265·β**.

Root-Hermite factor as a function of β:

```
δ(β) = ( (πβ)^(1/β) · β / (2πe) )^( 1 / (2(β−1)) )
```

**Assumptions stated explicitly:**
1. Geometric-Series-Assumption (GSA) BKZ basis profile; one successful β-block.
2. Secret and error are both ternary with `σ = sqrt(2/3)`; the knapsack (no
   explicit noise) is mapped to LWE in Hermite Normal Form, where the "error"
   is the determined short block `r'` and the "secret" is the free short block
   `r''` — both ternary, so `σ_s = σ_e = sqrt(2/3)`.
3. The distinguisher against hiding sees all `KAPPA+ELL = 5` commitment rows
   `(t1, t2)`; that is the strongest (adversary-optimal) sample count.
4. No exploitation of small/sparse-secret structure beyond using `σ = sqrt(2/3)`.
   This is a known **optimistic-for-the-defender** simplification — see §8.

---

## 4. Hiding — Module-LWE / decisional knapsack

Hiding requires `(A1·r, ⟨a2,r⟩)` to be pseudorandom for short `r`, so that `t2`
masks `m` (`bdlop.rs:34-36`). This is the decisional knapsack / Module-LWE
problem on the full commitment matrix `[A1; a2] ∈ R_q^{5×12}`. Search-recovering
`r` is a unique-SVP (primal) instance.

**HNF mapping.** Flatten `A·r = t` with `A ∈ Z_q^{1280×3072}`. Fix 1280 of the
3072 short coordinates as the "determined" block `r'` and the remaining 1792 as
the free secret `r''`. This yields LWE with:

- secret dimension `n = 1792`,
- available samples `M = (KAPPA+ELL)·N = 1280` (the adversary cannot manufacture
  more — the commitment is fixed),
- modulus `q = 8 380 417`, ternary secret and error.

Being **sample-limited** (`M = 1280 < n = 1792`) makes the attack *harder*, which
is why the margin is comfortable.

**Primal uSVP success condition** (Kannan embedding, lattice dim `d = m + n + 1`,
volume `q^m`), optimized over the number of samples `m ≤ M`:

```
σ·sqrt(β)  ≤  δ(β)^(2β − d)  ·  q^(m/d)
```

**Result (minimal feasible β):**

| Quantity | Value |
|---|---:|
| Optimal samples used `m` | 1272 |
| Embedding dimension `d = m+n+1` | 3065 |
| Required BKZ block size **β** | **808** |
| Root-Hermite factor `δ(β)` | 1.002398 (`log2 δ = 0.003456`) |
| **Core-SVP classical bits = 0.292·808** | **≈ 236** |
| **Core-SVP quantum bits = 0.265·808** | **≈ 214** |

Hiding clears the ~192-bit Level 3 target by ~44 classical / ~22 quantum bits.
Note the code's own caveat (`bdlop.rs:36`) that hiding is *computational, not
information-theoretic* for these dimensions — that is expected and consistent:
the map is compressing, but short preimages are unique, so recovery is an MLWE
problem, precisely what is estimated here.

---

## 5. Binding — Module-SIS on `A1`

Binding is broken by a short nonzero `z = r − r'` with `A1·z = 0 (mod q)`, i.e. a
Module-SIS solution in `Λ_q^⊥(A1)` (`bdlop.rs:28-33`). Because both openings are
ternary and shortness-checked (`|coeff| ≤ 1`), an admissible `z` has
`‖z‖_∞ ≤ 2`, hence worst-case `‖z‖_2 ≤ 2·sqrt(K·N) = 2·sqrt(3072) ≈ 110.85`.

Flattened SIS instance: `d_con = KAPPA·N = 1024` constraints, `D = K·N = 3072`
columns, kernel-lattice determinant `q^{1024}`. BKZ-β returns a shortest vector
of length `δ(β)^(m−1)·q^(d_con/m)` in the optimal subdimension `m`. The attack
succeeds only if that length drops to `≤ 110.85`.

**Result:** infeasible in any relevant regime. The minimum achievable norm over
all subdimensions stays orders of magnitude above the target bound:

| BKZ block size β | min achievable `‖v‖` |
|---:|---:|
| 800 | 282 304 |
| 1000 | 102 971 |
| 1500 | 20 008 |
| 2000 | 7 909 |
| 3000 | 2 869 |

Even β = 3000 (core-SVP classical ≈ 876 bits) yields `‖v‖ ≈ 2869 ≫ 110.85`. No
β < 8000 reaches the admissible norm. **Binding therefore far exceeds any
practical target and is not the constraint.**

---

## 6. Why binding is statistically (not just computationally) sound

The Module-SIS instance is hard because an admissible solution generically does
**not exist**. Counting the short openings vs. the image space:

- admissible short differences `z` (`‖z‖_∞ ≤ 2`): `5^(K·N) = 5^3072 ≈ 2^7133`,
- image space of `A1` on those: `q^(KAPPA·N) = q^1024 ≈ 2^23551`.

Since `2^7133 ≪ 2^23551`, the expected number of nonzero admissible collisions is
`≈ 2^(−16418)` — negligible. The ternary map `r ↦ A1·r` is injective on
shortness-checked openings with overwhelming probability, so **binding holds
statistically for the checked-opening path**, independent of Module-SIS hardness.
`KAPPA = 4` is, if anything, over-provisioned for binding.

**Usage caveat (not a parameter issue).** This binding guarantee applies only to
the shortness-checked `verify_opening` path. As the module notes
(`bdlop.rs:30-33`), the VSS share-consistency path deliberately accepts unbounded
`r` and thus obtains homomorphic consistency, not binding, from these parameters
(see `crate::crypto::vss_bdlop`). Downstream binding claims must route through the
shortness check.

---

## 7. Verdict and recommendations

**Verdict.** Under the analytical core-SVP model, the chosen parameters
(`KAPPA=4`, `K=12`, ternary randomness, `q = 8 380 417`, `N = 256`) **meet the
NIST Level 3 / ~192-bit classical target for both hiding and binding.** Hiding
(~236 classical / ~214 quantum) is the tighter side and the correct thing to
watch; binding is statistically sound with an enormous margin.

**Recommendations, in priority order:**

1. **Validate with the real lattice-estimator + external review before closing
   any hiding claim.** Core-SVP is a heuristic, lower-bound-ish estimate; run
   `estimator.LWE.estimate` on the HNF instance (`n=1792`, `m=1280`, `q=8380417`,
   ternary secret+error) and record the primal, dual, and dual-hybrid numbers.
   This is the gating action for `partial_contribution_soundness`.
2. **If additional hiding margin is desired, increase `K` (randomness width).**
   It is the cheapest lever: it raises the secret dimension and the sample count
   together, pushing β up, at linear cost in commitment randomness size. `KAPPA`
   need not change — it is already far beyond what binding requires.
3. **Do not reduce `q`.** The modulus is fixed by ML-DSA-65 interoperability;
   a smaller `q` would help hiding but break the shared-arithmetic assumption
   with the signature layer. Prefer the `K` lever instead.
4. **Keep the shortness check on the binding-critical path** and document that
   the unbounded-`r` VSS path is consistency-only, so no caller mistakes it for
   a binding commitment.

No parameter is *weak* per this estimate; the required action is validation, not
a parameter change.

---

## 8. Limitations (read before citing any number here)

- **The lattice-estimator was not run.** These are hand-computed core-SVP numbers
  from the GSA/2016 model. They are a heuristic that has historically tracked the
  estimator to within tens of bits but is **not** a substitute for it or for
  external cryptographic review.
- The model **ignores small/sparse-secret refinements** (dual-hybrid, coordinate
  guessing/dropping, the "bai-galbraith" secret rescaling). Given the large
  modulus (`q ≈ 2^23`) against a ternary secret, these are exactly the attacks
  most likely to erode the hiding number. A 20–30% erosion still clears 192 bits,
  but this must be checked, not assumed.
- Core-SVP charges only a single BKZ block and the sieve exponent `0.292/0.265`;
  it omits the polynomial and `o(β)` factors, so it is deliberately conservative
  (favorable to the attacker) as a floor.
- Binding's statistical argument (§6) is a first-moment count; it shows the
  *expected* number of collisions is negligible, consistent with the SIS
  intractability, and matches the module's stated design intent.

---

## 9. KAT / CAVP conformance coverage (Stack B provider path)

Assessment of ML-DSA-65 known-answer / ACVP vector coverage on the standard
provider path, for a FIPS-204 conformance claim.

### What exists

| Fixture / test | Kind | Coverage |
|---|---|---|
| `tests/fixtures/acvp_mldsa65_sigver_fips204_sample.json` | Real ACVP **sigVer** sample vectors (from `usnistgov/ACVP-Server`, commit `15c0f3d…`) | ML-DSA-65, FIPS204, external interface, pure pre-hash. **Exactly 2 test cases** (`tcId 31` accepting, `tcId 32` rejecting). Pins `source_prompt`/`expected_results` SHA-256. |
| `tests/production_provider.rs` (`…verifies …acvp… vectors`) | Test driver | Parses the fixture, checks metadata, and runs each case through `HazmatMldsa65Provider::verify_with_context`, asserting accept/reject matches `testPassed`. **Gated behind the `raw-real-mldsa` feature** (optional `ml-dsa` crate v0.1.1). |
| `tests/production_provider.rs` (hazmat smoke tests) | Self-generated | Sign/verify round-trip and mutation-rejection from a fixed seed via the `ml-dsa` crate. Not KATs (self-consistency only). |
| `tests/fixtures/mldsa65_provider_smoke.json` | Smoke input | Self-labeled "**not an ACVP or FIPS KAT**"; a single message blob. |

### What is missing for a real FIPS-204 conformance claim

- **sigVer breadth: only 2 vectors.** ACVP ML-DSA sigVer prompts contain many
  cases across parameter sets and mutation classes; 1 pass + 1 fail is a smoke
  sample, not conformance coverage.
- **No `keyGen` vectors.** No ACVP ML-DSA-65 keyGen KATs (seed → expanded
  `(pk, sk)`) are present anywhere in `tests/`.
- **No `sigGen` vectors.** No deterministic/hedged signature-generation KATs, so
  the signing path is validated only by self-round-trip, never against NIST
  expected outputs.
- **Interface/pre-hash matrix not covered.** Only `signature_interface=external`
  + `pre_hash=pure`. No `internal` interface (`external_mu`) and no HashML-DSA
  (pre-hashed) vectors.
- **Not a validated module.** Verification rides on the `ml-dsa` crate (v0.1.1),
  which is not a CAVP/ACVTS-validated or FIPS-140-certified implementation. Both
  the fixture `note` and `mldsa65_provider_smoke.json` state this explicitly, and
  the default provider is `UnavailableMldsa65Provider` (fails closed); real
  verification only runs under the optional hazmat feature.

**Bottom line for coverage:** the provider path has a *token* real ACVP sigVer
anchor (2 vectors) wired to an actual verifier, but **keyGen and sigGen KATs are
entirely absent**, sigVer is not exercised across the interface/pre-hash matrix,
and the underlying implementation is unvalidated. This is consistent with the
project's stated boundary (`requires CAVP/ACVTS validation evidence`,
`thesis-operating-parameters.md:136-139`) and is **not** sufficient for a FIPS-204
conformance claim. Closing it requires the full ACVP keyGen + sigGen + sigVer
vector sets across the supported interfaces, run against the provider actually
shipped.
