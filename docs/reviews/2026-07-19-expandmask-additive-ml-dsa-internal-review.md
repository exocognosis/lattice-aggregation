# Internal Review: Exact ExpandMask MPC and Additive-Share ML-DSA Wiring

Review date: 2026-07-19

Reviewer class: internal independent review, not external certification

Verdict: **algebraic wiring resolved; blocked for production and theorem closure**

The exact ExpandMask MPC is a meaningful test-scale primitive candidate. Static
inspection is consistent with FIPS 204 ExpandMask for ML-DSA-65, and an
independent recomputation of the checked fixture produced the same digest as the
two-party MAMA execution. The current signer now contains the correct
mixed-share algebraic integration seam: it leaves additive `y_i` shares
unweighted, applies signing-set Lagrange weights to Shamir `s1_i`, plain-sums
the resulting `z_i`, and plain-sums public `A*y_i` values before deriving the
FIPS challenge. Production custody, authenticated MPC-to-signer transfer,
complete transcript linkage, retry security, scale, and external review remain
open.

This review does not claim external independence, production security, a
6,667-party execution, or theorem closure.

## Update 2026-07-19: custody-consumption seam, linkage digest, and mask ledger

This update records source-level advances reviewed after the algebra
resolution. It does not promote any production, scale, custody-authenticity,
external-independence, or theorem-closure gate. All such gates remain
fail-closed. This remains an internal agent review, not external independence,
production security, a 6,667-party execution, or theorem closure.

Confirmed resolved (algebra, formerly R-01): re-inspection of
`emit_additive_mask_partial` (`src/backend/fips_sign.rs:1889`) confirms it
computes `weighted_s1 = scale_module(s1_share, member.lagrange_weight)` at
`:1900` and then forms `z_i = y_i + c*(lambda_i*s1_i)` through
`compute_z_from_share_ntt` (`:1756`). `aggregate_additive_mask_partials`
(`:1909`) plain-sums each `z_i` with scalar one (`:1924`), and
`aggregate_additive_mask_shares` (`:1949`) plain-sums each `y_i` with scalar one
(`:1956`). No Lagrange weight is ever applied to the additive `y_i` term. The
resolved-in-source disposition stands; it is not production evidence.

Meaningfully advanced code seams (NOT production, custody authenticity, or
closure):

- Custody-consumption seam. A new signing entrypoint
  `strict_distributed_sign_from_custody_and_mask_outputs`
  (`src/backend/fips_sign.rs:977`) consumes a new module `src/backend/custody.rs`.
  `NonExportableModuleShare` / `NonExportablePolyArrayShare` (`custody.rs:81`,
  `:114`) expose each signer's `s1_i` / `s2_i` only through a borrowing callback
  (`with`), never returning, cloning, or serializing the inner value, and
  best-effort zeroize on drop. `SignerCustodyHandle65` (`custody.rs:147`) binds
  the sealed shares to a validator identity and evaluation point. In the signer
  loop each `s1_i` and `s2_i` is touched only inside a per-signer callback
  (`fips_sign.rs:1106`, `:1117`); the coordinator never materializes a plaintext
  `Vec` of all secret shares. Shares are dealt once via genuine Shamir
  (`split_module_vector_shamir` / `split_poly_array_shamir`,
  `fips_sign.rs:915`, `:917`), removing the prior per-attempt re-split
  anti-pattern.
- End-to-end linkage. New `end_to_end_linkage_digest` (`custody.rs:225`) binds
  the DKG transcript digest, public key, message, `mu`, signing-set identity,
  exact-mask attempt binding, `kappa`, MPC transcript digest, aggregate
  commitment, partial bundle, rejection-predicate outcome, and the aggregate
  signature into one digest.
- Single-use mask ledger. New `MaskConsumptionLedger` (`custody.rs:307`)
  enforces single-use consumption per (transcript, `kappa`, attempt-binding)
  (`consume`, `:336`), accounts for retries and selective aborts (`record_retry`,
  `record_abort`), and serializes via `to_state` / `from_state` (`:392`, `:406`)
  for persistence across restarts.
- Standard-wire evidence. Test
  `custody_held_shares_and_exact_masks_emit_standard_wire_signature`
  (`fips_sign.rs:2604`) drives the seam to a standard-verifiable ML-DSA-65 wire
  signature and asserts that replaying the same masks against the same ledger
  fails closed (`:2706`).
- Sibling backend CLI. The sibling repo
  `/Users/rickglenn/Documents/lattice-threshold-backend-p1` adds a deterministic,
  nonproduction CLI `emit-dealerless-dkg-custody-record` that fails closed on
  `--production` and serializes `finalize_dealerless_dkg` signer share bindings.

Blockers retained open after this update (partial advancement noted, none
closed):

- No-single-secret signing: OPEN. The custody path's
  `CustodyDistributedSignPackage.no_single_secret_signing_path` is hard-coded
  `false` (`fips_sign.rs:849`, `:1226`), and the test provisioner
  `provision_signer_custody_handles_from_seed_for_test` (`:894`) still holds the
  whole secret and derives all shares from one seed
  (`ShareProvenance::LocalSeedDerivedForTest`). Custody-consumption seam added;
  production no-single-secret still blocked.
- DKG `K` shares not consumed by the MPC input path: OPEN. In the custody
  harness the coordinator still knows `rhopp`, documented as a harness artifact
  (`fips_sign.rs:790`); production `rhopp` must be a secret jointly derived
  inside the exact-ExpandMask MPC and never learned by any coordinator.
- Custody-held `s1`/`s2` not consumed by a real signer: ADVANCED but OPEN. The
  signer now consumes shares via non-exportable handles, but the shares trace to
  a locally generated secret, not an independently attested vault
  (`ShareProvenance::ExternalAttestedVault` ships with no provider).
- Complete end-to-end cryptographic linkage: ADVANCED but OPEN. The linkage
  digest binds the listed fields; it does not prove the DKG/MPC transcripts came
  from real distributed executions (`custody.rs:29`).
- Retry erasure and selective-abort proofs: ADVANCED but OPEN. The ledger
  accounts for retries/aborts and enforces single use, but formal erasure and
  selective-abort proofs remain incomplete.
- 6,667-party MAMA not executed: OPEN. Only a two-party run exists.
- Real 6,667-of-10,000 campaign not executed: OPEN. The preflight was re-run and
  still reports `blocked_prerequisites_unmet`
  (`artifacts/real-6667-of-10000-mldsa-campaign/latest/manifest.json`).
- No external named reviewers signed the frozen evidence: OPEN.

New blockers added by this update:

- ExpandA reconciliation. The module-form DKG (`src/crypto/mldsa_module.rs`)
  explicitly defers byte-exact FIPS-204 ExpandA, while the wire signing path
  (`fips_sign::expand_a`) is byte-exact. Sourcing wire-verifiable key shares
  directly from the module DKG is blocked until these are reconciled; this is
  why the custody test still provisions from a `fips_sign`-native seed.
- Coordinator `rhopp` knowledge. In the custody signing harness `rhopp` is
  coordinator-known (a test artifact). Production requires `rhopp` to be jointly
  derived inside the exact-ExpandMask MPC and never learned by any coordinator.

The internal gate result stays `blocked`, with production, no-single-secret,
external-independence, and theorem-closure claim flags false.

## Scope and evidence checked

- `mpc/Programs/Source/mldsa65_expandmask.mpc`
- `scripts/build_exact_expandmask_mpc_candidate.py`
- `scripts/run_exact_expandmask_mpc_equivalence.py`
- `artifacts/exact-distributed-expandmask-mpc/{latest,equivalence-latest,malicious-equivalence-latest,mama-equivalence-latest}`
- `src/backend/fips_sign.rs`
- `src/backend/module_partial.rs`
- `src/crypto/interpolation.rs`
- `docs/cryptography/formal-security-theorem.md`
- `docs/cryptography/correctness-lemmas.md`
- `docs/cryptography/proof-implementation-crosswalk.md`
- the current internal campaign and theorem-review manifests
- sibling backend campaign linkage in
  `/Users/rickglenn/Documents/lattice-threshold-backend-p1`
- NIST FIPS 204, especially Algorithms 7 and 34

Integrity checks passed for all four checked `SHA256SUMS` files. The current
circuit digest is
`e1b5365906c0258d1352f56a3074244f0bb8a2762a17573cdc034fe07330e4bb`,
and the checked schedule digest is
`53ecd0c4a81c4a398332fce5a48cbc4587b4320b7acde84ecd0cc09c8f3bdf1e`.

An independently written local oracle recomputed all 1,280 fixture
coefficients. Its digest was
`eb56c7485c1a40984b6c9ce3f4eb555781b36954676d6e6de715e9b070e4ff92`,
which equals both the expected and reconstructed-output digests in the
two-party, 40-bit-statistical-security MAMA manifest.

## Findings

### R-01 Resolved algebraically: additive masks and Shamir secret shares use the correct mixed-share equation

The MPC emits additive shares satisfying:

```text
y = sum_{i in A} y_i mod q.
```

The prior strict path applied signing-set interpolation to the whole partial,
which was incompatible with raw additive `y_i` outputs. The current additive
path no longer does that. It implements:

```text
weighted_s1_i = lambda_i(A) * s1_i
z_i           = y_i + c*weighted_s1_i
z             = sum_i z_i.
```

Therefore:

```text
lambda_i(A) = product_{j in A, j != i} (-x_j)/(x_i-x_j) mod q
z_i          = y_i + lambda_i(A) * (c*s1_i)
z            = sum_{i in A} z_i
             = y + c*s1.
```

`emit_additive_mask_partial` scales only `s1_i` by `lambda_i(A)` and then adds
the unweighted mask share. `aggregate_additive_mask_partials` applies scalar
one to every partial. The signing set rejects zero or duplicate interpolation
points. The path also computes `w_i = A*y_i` and plain-sums those values before
`HighBits` and `c_tilde` derivation. The APIs are exported through
`src/backend/mod.rs` and `src/lib.rs` behind `raw-real-mldsa`.

This resolves the response and public-commitment aggregation equations in
source. It does not prove that a remote signer used the same authenticated MPC
output in `w_i` and `z_i`, and the current orchestration still centralizes all
shares.

References: `src/backend/fips_sign.rs:1318`,
`src/backend/fips_sign.rs:1359`, `src/backend/fips_sign.rs:1396`,
`src/backend/fips_sign.rs:1420`, `src/backend/fips_sign.rs:1444`,
`src/backend/mod.rs:37`, and `src/lib.rs:35`.

### R-02 Critical: the formal transcript challenge is not the FIPS 204 challenge

FIPS 204 requires:

```text
tr       = H(pk, 64)
mu       = H(tr || M', 64)
c_tilde  = H(mu || w1Encode(w1), lambda/4)
c         = SampleInBall(c_tilde).
```

The formal theorem currently defines `c = H_T(sid, t, V, pk, m, Com)`. An
unmodified ML-DSA verifier does not hash `sid`, `t`, `V`, or `Com`. If those
fields are inserted into `c_tilde`, standard verification fails. If they are
not inserted, the theorem's challenge-binding statement does not follow from
the final signature alone.

The protocol needs two explicitly separated bindings:

```text
T_auth  = H(protocol, sid, epoch, t, V, A, pk, M', attempt, kappa,
            MPC source/schedule/runtime digests, input commitments,
            output-share commitments)

c_tilde = H(mu || w1Encode(w1), lambda/4)
```

Every partial and MPC output receipt must bind both `T_auth` and `c_tilde` before
aggregation. The final wire signature remains exactly `(c_tilde, z, h)`. The
active signing set must be enforced by partial proofs or attestations and the
authorization transcript, not by silently changing the FIPS challenge.

References: `docs/cryptography/formal-security-theorem.md:59`,
`docs/cryptography/formal-security-theorem.md:185`,
`src/backend/fips_sign.rs:503`, and FIPS 204 Algorithm 7.

### R-03 Critical: the algebraically correct path still has a single secret holder and centralized mask-share access

The strict path derives the complete ML-DSA secret from one local seed and
computes `rho''` locally. The additive API accepts every signer-private mask
share in one `Vec`, computes each `A*y_i` in the same process, and explicitly
plain-sums the mask shares back into full `y` for its direct-equation check. It
also retains full `t0`, reconstructs `c*s2`, and computes rejection predicates
and hints in one process. This is correct algebraic integration evidence, not a
distributed custody boundary and not proof that no party learns joint `y`.

For the mixed-share path, the same signing-set weights are required for the
Shamir-shared secret terms:

```text
w_i   = A*y_i                       ; w = sum_i w_i
u_i   = lambda_i(A) * (c*s2_i)      ; c*s2 = sum_i u_i
v_i   = lambda_i(A) * (c*t0_i)      ; c*t0 = sum_i v_i
z_i   = y_i + lambda_i(A)*(c*s1_i)  ; z = sum_i z_i
```

Opening `c*s2`, `c*t0`, or similarly secret-dependent intermediate values to an
untrusted coordinator is outside the FIPS signature leakage and the stated
theorem model. Those values and the rejection computation must remain inside a
reviewed MPC/threshold computation, or an explicit leakage theorem must justify
their exposure. The only public outputs should be the accepted standard
signature, required public commitment material, bounded predicates, and
transcript evidence designed not to leak shares.

References: `src/backend/fips_sign.rs:541`, `src/backend/fips_sign.rs:567`,
`src/backend/fips_sign.rs:611`, `src/backend/fips_sign.rs:616`,
`src/backend/fips_sign.rs:662`, and `src/backend/fips_sign.rs:1482`.

### R-04 High: local attempt binding exists, but MPC provenance and exported shares are not end-to-end authenticated

The signer now computes an input-binding digest over `rho''`, `kappa`, and the
ordered signing set, and it rejects supplied attempts whose digest or signer
ordering differs. This is a useful local linkage guard. However,
`AdditiveMaskAttempt65` represents malicious-MPC and exact-equivalence status as
caller-supplied booleans. It carries no signed runtime, circuit, schedule,
input-commitment, output-receipt, or custody evidence for the supplied shares.

The circuit accepts `mu` solely from player 0. It does not establish that
`mu = H(H(pk,64) || M',64)`, bind `pk` to DKG output, or bind the selected
message/context to all parties. The equivalence fixture deliberately supplies
an arbitrary 64-byte `mu`, which is adequate for an ExpandMask unit vector but
not end-to-end signing equivalence.

`K` and `rnd` are XOR-shared inputs, but there is no checked no-dealer DKG
transcript for `K`, no commit-before-input proof for `rnd`, and no reviewed
selective-abort treatment. The circuit's private output files contain plain
additive field shares after private reveal. MAMA authenticates the computation,
but the artifact does not provide a transferable proof that the value later
submitted to the Rust signer is the exact authenticated MPC output.

Required disposition:

- Bind `pk`, `tr`, `M'`, `mu`, epoch, attempt, `kappa`, and active set in
  `T_auth`.
- Define and review the conversion from no-dealer DKG custody to the circuit's
  XOR-shared `K` interface.
- Commit all `rnd` contributions before input finalization and account for
  abort/retry bias.
- Produce an attested or cryptographically committed output receipt inside the
  MPC and verify it in the partial-signing process.

References: `src/backend/fips_sign.rs:203`,
`src/backend/fips_sign.rs:580`, `src/backend/fips_sign.rs:593`,
`src/backend/fips_sign.rs:1338`,
`mpc/Programs/Source/mldsa65_expandmask.mpc:83`, and
`mpc/Programs/Source/mldsa65_expandmask.mpc:220`.

### R-05 High: retry selection is implemented, but retry security, erasure, and partial-validity proofs remain absent

The strict Rust loop advances `kappa`, selects the matching supplied MPC attempt,
and fails closed when a retry output is missing or its local binding differs.
That resolves the basic retry-index handoff. No authenticated evidence connects
the sequence of MPC executions to the accepted FIPS rejection loop, proves that
rejected shares are erased, prevents replay across sessions, or bounds malicious
selective abort.

There is also no proof that an externally submitted `w_i`, `z_i`, `u_i`, or
`v_i` is consistent with the signer's authenticated MPC output and committed
key shares. Standard-verifier acceptance checks the final tuple, but does not
prove individual contribution validity or no-subthreshold signing.

Required disposition:

- Bind every attempt and `kappa` to immutable input/output commitments.
- Prove or attest `w_i = A*y_i` and each weighted secret-share equation.
- Run aggregate norm/hint predicates over the exact values encoded in the final
  signature.
- Record rejected attempts without revealing rejected secret-dependent values,
  and specify erasure and retry policy.
- Complete the selective-abort and accepted-distribution proof.

### R-06 High: a signer integration seam exists, but exact MPC artifacts are not cryptographically linked into it or the theorem

The signer now consumes `AdditiveMaskAttempt65` values and exports the additive
integration APIs from the backend and crate roots. This closes the source-level
integration seam. It does not consume or verify the exact MPC circuit,
schedule, runtime, MAMA-manifest, input-commitment, output-receipt, or custody
digests. Caller-provided status booleans are not cryptographic linkage. The
current campaign and theorem artifacts therefore still do not establish that
the supplied shares came from the reviewed exact MPC run.

The MAMA manifest records two parties. The `10,000` and `6,667` values in the
candidate manifest are target metadata, not executed-party evidence. Therefore
the evidence does not discharge FST-L4, FST-L5, FST-L6, FST-L7, FST-T1, or
FST-T2.

Required disposition:

- Add a versioned successor artifact that binds the exact MPC source, schedule,
  runtime binary, MP-SPDZ commit, public inputs, per-party output receipts,
  signing-set digest, partial bundle, rejection transcript, final public key,
  message, and final signature.
- Make campaign and theorem-linkage generators verify those digests rather than
  copy status booleans.
- Keep all closure flags false until the real 6,667-party path and the proof
  obligations are complete.

### R-07 Medium: equivalence and provenance evidence is narrow

The positive result covers one deterministic input fixture, `kappa = 0`, two
parties, and full 5-by-256 dimensions. It is useful differential evidence, not a
general equivalence proof or distribution proof. The runner deletes raw inputs,
full logs, and private outputs with its temporary directory, retaining only
hashes and log tails. It records the runtime path but not the runtime binary
digest. `SHA256SUMS` authenticates file integrity only against a checksum stored
beside the file; it is not reviewer authentication.

Required additions include multi-vector and nonzero-`kappa` coverage, retry
sequences, different party counts, checked raw-log/output commitments,
reproducible runtime binaries, signed reviewer attestations, and an independent
implementation or formal SHAKE/BitUnpack equivalence argument.

### R-08 Medium: "10,000 signatures into one" is not defensible wording

The target construction does not aggregate 10,000 pre-existing independent
ML-DSA signatures. It aims to have an authorized set of 6,667 custodians jointly
produce one signature under one threshold-controlled ML-DSA public key.

Defensible target wording:

> A 6,667-of-10,000 threshold signing protocol that emits one standard-size
> ML-DSA-65 signature verifiable by an unmodified FIPS 204 verifier.

Current-evidence wording:

> A two-party malicious-MPC test demonstrated exact full-dimension ExpandMask
> fixture equivalence, while production-scale threshold signing and theorem
> closure remain open.

Not defensible:

- "10,000 ML-DSA signatures were condensed into one."
- "6,667 independent ML-DSA signatures were aggregated."
- "The theorem is closed."
- "Production threshold ML-DSA security is proven."

## Mathematical disposition

The ExpandMask circuit itself is consistent with the reviewed FIPS 204 mapping:

- `rho'' = SHAKE256(K || rnd || mu, 64)` uses a 128-byte one-block input.
- Each polynomial absorbs `rho'' || IntegerToBytes(kappa+r, 2)`.
- ML-DSA-65 uses five polynomials, 256 coefficients, and 20 bits per
  coefficient.
- Each decoded coefficient is `gamma1 - encoded`, represented modulo
  `q = 8380417`.
- Private arithmetic outputs reconstruct additively modulo `q` without opening
  the joint `K`, `rnd`, `rho''`, or `y` inside the circuit.

The current signer now correctly implements the next algebraic layer:

- active-set Lagrange coefficients are computed from distinct nonzero points;
- only Shamir `s1_i` is multiplied by `lambda_i(A)`;
- additive `y_i` remains unweighted in each `z_i`;
- `z_i` values are aggregated by plain addition;
- public `w_i = A*y_i` values are aggregated by plain addition;
- the resulting `w` drives the standard FIPS `w1` and challenge calculation;
- the additive integration surface is exported by the backend and crate roots.

The `w_i` object is an algebraic public commitment value, not by itself a proof
that a remote signer used the same authenticated `y_i` in its `w_i` and `z_i`.
The current in-process implementation obtains that consistency by holding the
share itself, which is precisely why custody and remote contribution soundness
remain open.

This establishes a credible exact primitive candidate, fixed-fixture functional
evidence, and correct source-level mixed-share signing equations. It does not
establish input provenance, private distributed custody, authenticated output
transfer, rejection-distribution preservation, remote contribution soundness,
or the security reductions required by the theorem.

## Theorem-linkage disposition

The evidence now advances two implementation sub-obligations: exact computation
of the FIPS mask function at test scale, and the algebraic aggregation part of
FST-L5 for mixed additive-mask and Shamir-secret shares. It also advances the
implementation side of FST-T4. It does not discharge:

- FST-A2 through FST-A4: DKG, share binding, and mask commitment security.
- FST-A5: complete abort and rejection-distribution preservation.
- FST-A6: partial correctness and extractability.
- FST-A7 and FST-L1/L2: transcript/challenge compatibility as currently stated.
- FST-L4: authenticated, attributable partial validity.
- FST-L5: end-to-end aggregation from the exact MPC outputs.
- FST-L6: no subthreshold signing.
- FST-L7: accepted-distribution compatibility.
- FST-T1 and FST-T2: threshold unforgeability and real/ideal realization.

The internal gate result is therefore `blocked`, with theorem and production
claim flags false.

## External review still required

An external cryptographic review must independently validate:

- the SHAKE256 and BitUnpack circuit against FIPS 204 and current NIST errata;
- the MAMA threat model, preprocessing, runtime build, field configuration, and
  malicious-security parameters;
- the mixed additive/Shamir equations and active-set Lagrange handling;
- the DKG-to-XOR-share interface for `K` and no-single-secret custody;
- output-share authentication from MPC into the signer;
- FIPS challenge compatibility and two-layer transcript proof;
- distributed `s1`, `s2`, and `t0` contribution validity;
- rejection sampling, selective abort, retries, erasure, and side channels;
- the 6,667-of-10,000 execution evidence and reproducibility package;
- FST-L1 through FST-L9 and the FST-T1/FST-T2 reductions.

External reviewers must be organizationally independent, identified in the
review package, and sign the exact evidence digests they reviewed. This internal
report cannot satisfy that gate.

## Reference

- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204), Algorithms 7 and 34.
