# Proof Closure Ledger
<a id="proof-closure-ledger"></a>

Date: 2026-05-28

Status: single status index, not a completed proof.

## Scope

This ledger collects the named advantage terms, implementation residuals, and
proof-route documents that currently define the threshold ML-DSA-65 claim
boundary. It is designed as a reviewer-facing index: every term that appears in
the top-level theorem shape should have one visible status, one evidence route,
and one closure requirement.

This ledger does not prove that any term is negligible, zero, or bounded. It
also does not replace the detailed worksheets. Its purpose is to prevent the
repository from accidentally treating scaffold evidence, deterministic tests,
or idealized assumptions as completed cryptographic proof.

The repository remains a research scaffold. It is not production-ready and not
a security proof. In particular, implementation evidence is not cryptographic
proof, and production VSS/DKG remains open.

## Ledger Status Key
<a id="ledger-status-key"></a>

- **Implemented engineering evidence**: code and tests exercise the stated
  boundary, but the result is not by itself a cryptographic proof.
- **Experimentally supported**: deterministic simulations, fixtures, or
  reproducible artifacts support the modeled experiment profile.
- **Proof route documented**: a theorem target, bad-event decomposition, or
  simulator route exists, but the proof is not complete.
- **Idealized route**: a theorem path may assume an ideal functionality; this
  can isolate a proof dependency but does not instantiate a production backend.
- **Open proof obligation**: a reduction, simulator, distributional bound,
  parameter-specific proof, or theorem instantiation remains missing.
- **Production blocker**: production security, production slashing, deployment
  readiness, or publication wording depends on closing this item first.
- **Not claimed**: the repository documents the topic as future work or as an
  explicit non-claim.

## Term Ledger
<a id="ledger-term-table"></a>

| Term | Meaning | Current status | Evidence or route | Closure requirement | Safe wording |
| --- | --- | --- | --- | --- | --- |
| `eps_vss` | Concrete VSS/DKG setup loss for malicious-secure dealer sharing, public-key derivation, complaint handling, and anti-framing. | Open proof obligation; production blocker. | [vss-dkg-security-plan.md](vss-dkg-security-plan.md), [vss-backend-selection.md](vss-backend-selection.md), [production-vss-backend.md](production-vss-backend.md), `src/crypto/vss.rs`, `src/crypto/production_policy.rs`. | Select a production backend and prove binding, hiding, extractability or equivalent soundness, complaint resolution, key-bias resistance, privacy, anti-framing, and deterministic public-key derivation. | The repository contains a VSS/interpolation scaffold and production boundary. It does not implement or prove malicious-secure production DKG/VSS. |
| `eps_vss_ideal` | Loss from replacing concrete DKG/VSS with the ideal functionality `F_VSS_DKG` in the immediate signing theorem path. | Idealized route; not a production realization. | [vss-idealization-and-selection.md](vss-idealization-and-selection.md), [formal-security-theorem.md](formal-security-theorem.md), [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md). | State the exact `F_VSS_DKG` leakage and interfaces, prove the signing-side theorem under those outputs, and separately prove or instantiate a concrete realization before production claims. | The immediate theorem route may assume ideal setup to isolate signing proof work. This does not close concrete VSS/DKG security. |
| `eps_mask` | Distributional distance between aggregate threshold masks and centralized ML-DSA-65 mask sampling before rejection conditioning. | Proof route documented; open proof obligation. | [mask-distribution-equivalence.md](mask-distribution-equivalence.md), [rejection-sampling-bounds.md](rejection-sampling-bounds.md), [rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md), hazmat bridge tests. | Select the production `CombineMask` family and prove exact equality or a quantified `eps_mask_bound` for all ML-DSA-65 mask coefficients, public high bits, active-set binding, retry freshness, and corrupted-party influence. | The repository identifies the mask-distribution theorem route. It does not claim aggregate masks are centralized-ML-DSA distributed. |
| `eps_commit` | Commitment binding, hiding, equivocation, non-adaptivity, and commitment-set binding losses before challenge derivation. | Proof route documented; backend proof open. | [random-oracle-game.md](random-oracle-game.md), [formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md), [rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md). | Instantiate the production commitment scheme, prove binding and hiding under rushing, prove opened commitment sets equal challenged sets, and account for every commitment-related random-oracle prior query. | The transcript and commitment ordering are modeled. Commitment security is not proven by the current scaffold. |
| `eps_ro` | Random-oracle programming, typed-domain separation, prior-query, and byte-encoding injectivity losses. | Proof route documented; byte-level proof open. | [random-oracle-game.md](random-oracle-game.md), [formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md), [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md), transcript determinism tests. | Prove injective encodings and domain separation for `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib`; quantify prior-query losses across sessions, retries, validators, and oracle queries. | The repository fixes random-oracle domains and transcript fields. It does not complete the ROM reduction. |
| `eps_rej` | Mismatch between threshold aggregate rejection and centralized ML-DSA-65 rejection on the same candidate values. | Proof route documented; predicate proof open. | [rejection-predicate-equivalence.md](rejection-predicate-equivalence.md), [rejection-sampling-bounds.md](rejection-sampling-bounds.md), [noise-rejection-proof-plan.md](noise-rejection-proof-plan.md), hazmat rejection tests. | Prove equivalence of `z`, low-bit, `ct0`, hint, challenge, active-set, encoding, strictness, malformed-input, and verifier-side high-bit predicates, or charge every mismatch to an explicit subterm. | Predicate maps and boundary tests exist. They do not prove accepted threshold signatures match centralized ML-DSA rejection. |
| `eps_withhold` | Selective-abort, retry, timeout, post-commitment withholding, post-challenge withholding, and observable abort-label bias. | Proof route documented; open proof obligation and operational blocker. | [withholding-abort-bound.md](withholding-abort-bound.md), [active-adversary-model.md](active-adversary-model.md), [rejection-sampling-bounds.md](rejection-sampling-bounds.md), actor simulation tests. | Fix retry limits, timeout/exclusion policy, acceptance-probability lower bounds, simulator behavior, observable abort transcript `O_abort`, and evidence/release noninterference. | The repository decomposes selective-abort obligations. It does not claim bounded selective-abort advantage or production liveness. |
| `eps_contrib` | Loss from proving that every accepted contribution is context-bound, relation-valid, simulatable or extractable as required, and witness hiding under the selected leakage model. | Proof route documented; production backend not selected. | [contribution-soundness-relation.md](contribution-soundness-relation.md), [contribution-backend-instantiation.md](contribution-backend-instantiation.md), [proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md), `src/crypto/contribution_proof.rs`. | Choose a proof, MPC, interactive, or ideal contribution backend and prove soundness, extraction or replacement, hiding, context binding, leakage bounds, and audit status. | The repository defines the contribution-backend replacement route. Current transcript-hash payloads are not production contribution proofs. |
| `eps_classify` | Residual probability that an unauthorized accepting aggregate output is not mapped to a base ML-DSA forgery or named threshold-side assumption violation. | Proof route documented; must be eliminated for final theorem. | [unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md), [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md), [ideal-functionality.md](ideal-functionality.md). | Define the production verifier grammar, prove classifier totality and disjointness, supply per-case reductions, and prove `eps_cls_unmapped = 0`. | The repository decomposes unauthorized-output classification. It does not prove final unforgeability. |
| `eps_verify` | Residual standard-verifier compatibility loss for proving accepted threshold outputs verify as unmodified ML-DSA-65 signatures. | Implemented engineering evidence plus open proof decision. | [correctness-lemmas.md](correctness-lemmas.md), [rejection-predicate-equivalence.md](rejection-predicate-equivalence.md), hazmat standard-verifying tests. | Decide whether this term is folded into `eps_rej` or remains separate; then prove byte-level signature layout, high-bit reconstruction, hint use, and verification acceptance for all accepted threshold transcripts. | Hazmat paths exercise standard-size verification. This is not a complete compatibility theorem. |
| `implementation_residual` | Residual from code correctness, fail-closed policy, side-channel discipline, randomness quality, compiler behavior, transport identity binding, operational key management, and external review. | Mixed engineering evidence; production blocker. | [proof-implementation-crosswalk.md](proof-implementation-crosswalk.md), [side-channel-boundary.md](side-channel-boundary.md), [claims-matrix.md](claims-matrix.md), [docs/audit/README.md](../audit/README.md), production policy tests. | Complete code review, constant-time and leakage analysis, randomness review, production backend audit, authenticated transport proof assumptions, consensus integration review, and external cryptographic review. | The repository has useful guardrails and reproducible tests. It is not audited or production-ready. |
| `audit_residual` | External assurance gap after internal tests and documentation manifests pass. | Not claimed as closed. | Audit packet and reproducibility artifacts. | Obtain independent cryptographic review, implementation audit, side-channel audit, and operational review for the selected construction. | Internal tests are review inputs, not independent assurance. |

## Dependency Notes

The most important dependency chain is:

```text
FST-T1-IdealVSS
  requires eps_commit, eps_ro, eps_mask, eps_rej,
           eps_withhold, eps_contrib, eps_classify,
           eps_verify or its absorption into eps_rej,
           and implementation_residual controls.

Production FST-T1 threshold unforgeability
  additionally requires replacing eps_vss_ideal with a concrete eps_vss
  theorem for the selected VSS/DKG backend.

FST-T2 real/ideal realization
  additionally requires a complete simulator and transition reductions.

FST-T3 transcript non-malleability
  additionally requires byte-level injectivity and random-oracle separation.

FST-T4 implementation conformance
  remains an implementation guard, not a cryptographic proof.
```

The `eps_reject(A,Z)` term in
[simulator-hybrid-reductions.md](simulator-hybrid-reductions.md) expands across
the rejection-sampling worksheets as:

```text
eps_reject(A,Z)
  <= eps_rs_mask
   + eps_rs_commit
   + eps_rs_rej
   + eps_rs_withhold
   + eps_rs_ro
   + eps_rs_verify
```

This ledger maps those worksheet names to the publication-facing names
`eps_mask`, `eps_commit`, `eps_rej`, `eps_withhold`, `eps_ro`, and
`eps_verify`.

## Closure Sequence

The conservative proof-closure order is:

1. Close the IdealVSS signing theorem first, leaving concrete DKG/VSS out of
   scope through `F_VSS_DKG`.
2. Select the contribution backend and close `eps_contrib`.
3. Close random-oracle and commitment non-adaptivity terms.
4. Close mask distribution and rejection predicate equivalence.
5. Close withholding, retry, release, and evidence noninterference.
6. Prove verifier compatibility and decide the final treatment of
   `eps_verify`.
7. Eliminate `eps_classify` by proving the unauthorized-output classifier is
   total and disjoint.
8. Replace ideal VSS/DKG with a concrete backend theorem and independent audit.

## Non-Claims
<a id="ledger-non-claims"></a>

This ledger does not claim:

- `eps_mask`, `eps_rej`, `eps_withhold`, `eps_contrib`, `eps_classify`,
  `eps_verify`, or `eps_vss` is negligible, zero, or numerically bounded.
- The current VSS scaffold is malicious secure.
- The current contribution payload binding is a zero-knowledge proof, MPC
  proof, extractable proof, or production soundness relation.
- The hazmat ML-DSA-65 implementation is FIPS validated, independently
  audited, side-channel safe, or production ready.
- The repository proves a secure, production-ready threshold ML-DSA-65
  signature scheme.

## Manifest Anchors

The documentation manifest test treats these headings and text anchors as the
stable contract for this file:

- `# Proof Closure Ledger`
- `proof-closure-ledger`
- `Status: single status index, not a completed proof.`
- `ledger-status-key`
- `ledger-term-table`
- `FST-T1-IdealVSS`
- `FST-T1 threshold unforgeability`
- `FST-T2 real/ideal realization`
- `FST-T3 transcript non-malleability`
- `FST-T4 implementation conformance`
- `eps_vss`
- `eps_vss_ideal`
- `eps_mask`
- `eps_commit`
- `eps_ro`
- `eps_rej`
- `eps_withhold`
- `eps_contrib`
- `eps_classify`
- `eps_cls_unmapped = 0`
- `eps_verify`
- `implementation_residual`
- `audit_residual`
- `research scaffold`
- `not production-ready`
- `not a security proof`
- `implementation evidence is not cryptographic proof`
- `ledger-non-claims`

Keep these anchors stable when reorganizing this document, or update
`tests/proof_documentation_manifest.rs` in the same change.
