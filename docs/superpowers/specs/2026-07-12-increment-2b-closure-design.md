# Increment 2b Closure Design: Extractability Reconciliation + Encrypted Share Transport

Date: 2026-07-12

## Status

Design/specification only. This document specifies the two remaining open
checkboxes of Increment 2b in
`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`:

1. Per-share validity proofs / malicious-dealer binding + extractability
   (pivoted to a BDLOP Fiat-Shamir proof of a short opening,
   `src/crypto/bdlop_pok.rs`, wired into VSS/DKG in PR #114) — the slack
   reconciliation, aggregated-share norm gap, and `t^(d)` link remain OPEN.
2. Encrypted per-receiver share transport — shares are currently dealt in the
   clear.

It **does not** claim any new security property. Per the repository honesty
discipline (`docs/cryptography/claims-matrix.md`,
`docs/cryptography/blocker-closure-status.md`), VSS/DKG binding, hiding,
extractability, and malicious-secure DKG remain `open`. This document specifies
what additional proof obligations would close the gaps and, honestly, which ones
the current sigma-protocol can discharge versus which need a different proof
system or a parameter/architecture change.

Only the encrypted-transport **interface** (Section 4, and the accompanying
`src/crypto/share_transport.rs`) is implemented alongside this spec. Everything
in Section 3 (extractability) is specification, not code — the existing VSS/DKG
proof logic is unchanged.

---

## 1. Where the primitive stands today

`bdlop_pok::prove`/`verify` is a Lyubashevsky Fiat-Shamir-with-aborts sigma
protocol over `R_q = Z_q[X]/(X^256+1)`. For a BDLOP commitment
`C_j = (t1_j, t2_j)` with `t1_j = A1 * rho_j` and
`t2_j = <a2, rho_j> + c_j`, it proves knowledge of a **short** `rho_j` with
`A1 * rho_j = t1_j`. Two accepting transcripts sharing a mask extract
`rho_bar_j = z - z'` and `c_bar_j = d - d'` with:

- `A1 * rho_bar_j = c_bar_j * t1_j`,
- `||rho_bar_j||_inf <= 2 (B + 1)` (short, `B = 2^16`),
- `c_bar_j = X^a ± X^b`, an **invertible** slack in the fully-splitting ring
  (`extractor_yields_short_relaxed_opening_with_invertible_slack`).

This is a **relaxed** MSIS witness for the binding part `t1_j` only. It
certifies each commitment is a genuine relaxed MSIS image (not out-of-image /
unopenable). It does **not**:

- bind the message part `t2_j` (the proof never touches `a2` or `c_j`);
- combine the per-commitment slacks into a single sharing polynomial;
- bound the aggregated randomness `rho(i)` a receiver actually holds;
- link the DKG public value `t^(d) = A s1 + s2` to the commitments.

These are exactly the four obligations below.

---

## 2. Target relation (from the security plan)

`docs/cryptography/vss-dkg-security-plan.md` (Extractability) requires: for any
accepted dealer transcript, an efficient extractor recovers a **unique**
degree-`< tau` polynomial `P(x)` such that every accepted receiver share equals
`P(i)`, any `tau` accepted shares reconstruct the same value, and the dealer
public-key contribution corresponds to `P(0)`; or the transcript is rejected
with public evidence.

Extraction of a unique `P` decomposes into:

- **(E1)** share-value binding: each accepted `verify_share` pins a unique
  `P(i)` given the public commitments;
- **(E2)** single-polynomial consistency: the pinned `{P(i)}` lie on one
  degree-`< tau` polynomial whose coefficients are the committed `{c_j}`;
- **(E3)** public-value link: `P^{s1}(0), P^{s2}(0)` (the constant terms) satisfy
  `A * s1_0 + s2_0 = t^(d)`.

---

## 3. Extractability reconciliation (SPECIFICATION — not implemented here)

### 3.1 Gap A — aggregated-share norm bound (closes E1)

**Problem.** `vss_bdlop::verify_share` checks only the homomorphic relation
`commit(P(i); rho(i)) == sum_j i^j C_j` with **no** norm bound on
`rho(i)` (documented by `verify_share_does_not_enforce_randomness_shortness`).
BDLOP binding holds only for **short** openings: `A1` is `KAPPA x K` with
`KAPPA = 4 < K = 12`, so it has a nontrivial kernel and an **unbounded** `rho'`
opens any commitment to any message. Without a norm bound, `verify_share` gives
homomorphic *consistency*, not binding — a malicious dealer is not pinned.

**Fix.** Enforce a centered infinity-norm bound on the aggregated randomness:

```
||rho(i)||_inf <= beta(i),   beta(i) = sum_{j=0}^{tau-1} i^j
```

on the centered representative in `(-q/2, q/2]`. Then two accepted openings
`(v, rho)`, `(v', rho')` of the same combined commitment, both bounded by
`beta(i)`, give `A1 (rho - rho') = 0` with `||rho - rho'||_inf <= 2 beta(i)`. If
`rho != rho'` this is a nonzero `MSIS_{2 beta}` solution on `A1`; if `rho = rho'`
then `<a2, rho> + v = <a2, rho'> + v'` forces `v = v'`. So the norm bound reduces
share-value binding to `MSIS_{2 beta}`.

**Wire-in.**
- `src/crypto/vss_bdlop.rs`: add the centered-norm check to `verify_share`
  (compute `beta(receiver_index)` from `commitments.len()` = `tau`, reject if
  any centered coefficient of `share.randomness` exceeds it). This is the single
  load-bearing change; it is additive to the existing homomorphic check.
- `src/crypto/mldsa_module.rs`: `verify_components` → `SharedSecretKey::verify`
  inherit it automatically (they call `vss_bdlop::verify_share`). Note the DKG
  **aggregates** `D` dealer contributions, so the joint bound is
  `beta_joint(i) = D * beta(i)`; `verify` must know `D` (the accepted-dealer
  count) or check per-dealer before summing.
- `src/crypto/mldsa_dkg.rs`: the complaint rule in `finalize` /
  `finalize_with_evidence` already gates on `shared.verify`, so a norm-bound
  failure surfaces as an existing `DealerFaultClass::InvalidShareRelation`. The
  cleanest placement checks the bound **per dealer before aggregation** (each
  dealer's `rho(i)` is bounded by `beta(i)`), avoiding the `D` factor entirely.

**Honesty — what is actually provable, and the hard constraint.** The reduction
is only meaningful when the check does not wrap mod `q` and the resulting MSIS
instance is not trivially solvable:

- **No wraparound:** need `2 beta(i) < q ~ 2^23`. With integer points `i in
  1..=n` and `beta(n) ~ n^{tau-1}`, this already fails for modest committees:
  `tau = 3` needs `n <~ 2047`; `tau = 4` needs `n <~ 161`; `tau = 5` needs
  `n <~ 50`.
- **Non-trivial MSIS:** a short kernel vector of `A1` exists by pigeonhole once
  the infinity-norm bound exceeds roughly `q^{KAPPA/K} = q^{1/3} ~ 200` (over
  `K*N = 3072` coordinates against `KAPPA*N = 1024` constraints). So for the
  current parameters (`KAPPA=4, K=12`), `MSIS_{2 beta}` is only plausibly hard
  for `2 beta <~ 200`, i.e. `beta(n) <~ 100` — essentially `tau = 2, n <~ 99` or
  `tau = 3, n <~ 9`.

Therefore Gap A is **provable with the current primitive only for tiny
committees**. For a realistic committee (the repo elsewhere references 10,000
validators) the norm bound is vacuous. Closing E1 at scale needs **one of**:

1. **Exceptional-set evaluation** — replace integer evaluation points with a set
   of short/invertible ring elements (e.g. `{X^i}` or a challenge subtractive
   set) so the Vandermonde/Lagrange factors stay short; `rho(i)` then has a small
   norm independent of `n`. This is a redesign of the sharing/interpolation in
   `vss_bdlop.rs` and `interpolation.rs`, not just a check.
2. **Re-parameterization** — choose `(KAPPA, K, q)` (lattice-estimator
   validated) so `MSIS_{2 beta}` is hard at the needed `beta`. This is the
   already-flagged "parameters pending lattice-estimator validation" work.

### 3.2 Gap B — slack reconciliation + message binding (closes E2)

**Problem 1 (slack).** Each `C_j` extracts under its **own** slack `c_bar_j`.
The homomorphic combination `sum_j i^j C_j` is only a valid relaxed opening of
the share commitment if all coefficients share a **common** slack. `deal_secret`
today calls `bdlop_pok::prove` once per commitment with independent Fiat-Shamir
seeds (`fiat_shamir_seed` hashes a single commitment), so the slacks are
independent and do not reconcile into one polynomial.

**Problem 2 (message).** The current proof is over `t1` only. Nothing certifies
the committed coefficient **values** `c_j` (the `t2` part), so even with common
slack the extracted object is a binding-part witness, not the sharing
polynomial's coefficients.

**Fix.** Replace the per-commitment proofs with **one batched opening proof**
over all `tau` coefficient commitments under a **single** Fiat-Shamir challenge,
and extend the proved statement to the **full** commitment:

- joint mask across the `tau` openings; one challenge `d` derived over all `tau`
  commitment `w`-vectors ⇒ extracted slack `c_bar = d - d'` is common;
- prove knowledge of short `rho_j` with `A1 rho_j = t1_j` **and**
  `<a2, rho_j> = t2_j - c_j` for the claimed `c_j` (fold the `a2` row into the
  statement matrix), so the message part is bound.

With a common slack, `A1 (sum_j i^j rho_bar_j) = c_bar (sum_j i^j t1_j)` and the
analogous `a2` relation hold by linearity, so `sum_j i^j C_j` has a valid relaxed
opening under the single `c_bar`. Combined with Gap A's norm bound at `>= tau`
points, Lagrange interpolation yields a unique degree-`< tau` relaxed sharing
polynomial ⇒ E2.

**Wire-in.**
- `src/crypto/bdlop_pok.rs`: add `BatchOpeningProof` + `prove_batch`/
  `verify_batch` (joint mask, joint challenge over the concatenated `t1`/`t2`
  statements). Same ring, challenge set, rejection sampling — a moderate
  extension, not a new proof system.
- `src/crypto/vss_bdlop.rs`: `deal_secret` emits one `BatchOpeningProof` instead
  of `Vec<OpeningProof>`; `verify_commitments` calls `verify_batch`.
- `src/crypto/mldsa_module.rs`: `KeyProofs` holds per-component batch proofs;
  `verify_commitment_proofs` and `KeyProofs::digest` adapt one-for-one.

**Honesty — provable vs different system.** The batched common-challenge proof
still extracts a **relaxed** opening: it pins `c_bar * c_j`, i.e. the coefficient
up to an invertible slack. This is sufficient for **binding-style
extractability** (no two distinct short sharing polynomials open the same
commitments), which is what the security plan's binding clause needs. It is
**not** exact-message extraction (recovering the exact `c_j in R_q`). Exact
extraction needs a **different proof system** — an exact amortized proof
(ENS20/ALS with exact-opening machinery) or a lattice SNARK
(LaBRADOR-style). The relaxed sigma-protocol here fundamentally cannot recover
`c_j` without the slack factor.

### 3.3 Gap C — public-value link (closes E3)

**Problem.** `mldsa_dkg::deal` publishes `t^(d) = A s1^(d) + s2^(d)` and,
separately, commitments to the `s1/s2` coefficients. Nothing forces the
published `t^(d)` to equal `A * (committed s1 constant term) + (committed s2
constant term)`. A malicious dealer can publish an inconsistent `t^(d)`.

**Fix.** A **linear-relation proof over `R_q`** that the message openings of the
constant-term commitments `(C^{s1}_{*,0}, C^{s2}_{*,0})` satisfy
`A * s1_0 + s2_0 = t^(d)`. This is a proof of a public linear relation among
committed messages (ENS20/ALS linear proof, or a Schnorr-style lattice proof
over the same commitment key). It is a **new, additional** proof component but
uses the same lattice toolbox.

**Wire-in.**
- `src/crypto/mldsa_dkg.rs`: `deal` attaches a `PublicValueLinkProof` to
  `DealerContribution`; the accept predicate in `finalize` /
  `finalize_with_evidence` checks it and, on failure, emits a **new**
  `DealerFaultClass::PublicValueMismatch` (publicly re-checkable in
  `verify_fault`, consistent with the existing closed-fault-class discipline and
  its over-claim guard test).

### 3.4 Extractability closure — summary

| Obligation | Mechanism | Proof system | Status |
| --- | --- | --- | --- |
| E1 share-value binding | centered norm bound on `rho(i)`, reduce to `MSIS_{2 beta}` | current primitive | provable **only for tiny committees**; scale needs exceptional-set evaluation or re-parameterization |
| E2 single polynomial | batched common-challenge + `t2` message binding | extended sigma-protocol | provable as **relaxed** (up to slack) binding |
| E2 exact coefficients | exact opening | **different** system (exact amortized / LaBRADOR) | out of scope of current primitive |
| E3 public-value link | `R_q` linear-relation proof | additional lattice proof | new component, same toolbox |
| MSIS/MLWE params, CT, audit | lattice-estimator + review | external | out of band |

**Bottom line.** With the current sigma-protocol, extended per Gaps A–C, the
repository can reach **relaxed, binding-style VSS extractability for small
committees**: a unique relaxed degree-`< tau` sharing polynomial is pinned, its
constant term is linked to `t^(d)`, and malicious dealers are caught with public
evidence. It **cannot** reach exact-message extraction or large-committee
soundness without a different proof system or a sharing-algebra/parameter
change, and no claim beyond `open` may be made until MSIS/MLWE parameters are
lattice-estimator validated and externally reviewed.

---

## 4. Encrypted per-receiver share transport

### 4.1 Problem

`vss_bdlop::deal_secret` returns cleartext `HidingShare`s; `mldsa_dkg` notes any
party assembling all shares (the `finalize` caller / any `DkgOutput` holder) can
reconstruct. Secrecy is scoped to sub-threshold **validator** coalitions only.
To scope secrecy to each receiver, each share must be transported so only
receiver `i` learns `(P(i), rho(i))`.

### 4.2 Real primitive (recommended for production): ML-KEM

A PQ-secure transport needs a **KEM**: **ML-KEM (FIPS 203 / Kyber)**. Each
receiver publishes a static ML-KEM public key during DKG setup; the dealer
encapsulates a shared secret per receiver and wraps the serialized share with an
AEAD under a key derived (SHAKE256/HKDF) from it, binding
`(session_id, dealer_id, receiver_index, threshold, validator-set digest)` as
associated data. This is IND-CCA2 and post-quantum.

**No-new-crates note.** The repository has **no KEM dependency** and a "no new
crates" rule (`sha3`, optional `ml-dsa`, `serde`, `async-trait`, `zeroize`,
`thiserror`, `tokio`). A real transport therefore requires adding **`ml-kem`**
as a new crate — a **justified exception**, exactly analogous to the optional
`ml-dsa` backend dependency (feature-gated, `default-features = false`). It
should be introduced behind a feature flag with its own claim boundary, not
enabled by default.

### 4.3 Interim primitive (implemented): SHAKE256 authenticated encryption

Until ML-KEM lands, `src/crypto/share_transport.rs` provides a SHAKE256-based
authenticated-encryption **interface** over the existing `sha3` dependency:

- `ShareTransport` trait: `seal` / `open`.
- `Shake256Transport` reference impl: encrypt-then-MAC. Two subkeys
  `k_enc, k_mac` are derived from the receiver key by domain-separated SHAKE256;
  the keystream is `SHAKE256(k_enc || nonce)` XORed onto the plaintext; the tag
  is `SHAKE256(k_mac || nonce || associated_data || ciphertext)`, checked with a
  best-effort constant-time comparison.
- `ReceiverKey`: a 32-byte symmetric key, zeroized on drop.
- `SealedShare`: `{ nonce, ciphertext, tag }`, a serde wire object.

**Security boundary (stated in the module and here).** This is **NOT a KEM** and
does **NOT** solve key distribution. It assumes a **pre-shared per-receiver
symmetric key channel** (`ReceiverKey` established out-of-band, or by a future
ML-KEM handshake that this trait abstracts). It provides confidentiality and
integrity under the SHAKE256-as-PRF assumption **given** unique `(key, nonce)`
pairs; reusing a `(key, nonce)` pair breaks confidentiality (stream-cipher
caveat). It offers **no** public-key functionality, **no** PQ key exchange,
**no** forward secrecy, and is **not** constant-time end-to-end. It is **not**
wired into VSS/DKG — no existing VSS/DKG security property changes.

### 4.4 Future integration (specification only)

When adopted, `vss_bdlop::deal_secret` would return a `SealedShare` per receiver
instead of a cleartext `HidingShare`; each receiver `open`s its share, then runs
the unchanged `verify_share`. Associated data binds
`(session_id, dealer_id, receiver_index)` to prevent cross-context replay, and
`SharedSecretKey::reveal_digest` / the DKG commit digest would bind the
**ciphertexts** rather than cleartext shares. The `ShareTransport` trait is the
seam where the ML-KEM-backed hybrid impl (4.2) drops in without touching VSS/DKG
call sites.

---

## 5. Non-claims (unchanged)

- No malicious-secure VSS/DKG, binding, hiding, or extractability is claimed;
  all remain `open` in the claims matrix.
- The interim transport is an interface with a reference symmetric AEAD, not a
  production KEM, and provides no PQ key exchange.
- The extractability mechanisms in Section 3 are specification; the existing
  `bdlop_pok` / `vss_bdlop` / `mldsa_dkg` proof logic is unchanged.
- MSIS/MLWE parameter validation, constant-time audit, and external review
  remain out of band and gate any promotion.
