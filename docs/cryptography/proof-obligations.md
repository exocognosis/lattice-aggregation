# Proof Obligations Matrix

Status: traceability matrix for proof targets, not a completed proof.

Date: 2026-05-27

## Scope

This matrix tracks theorem and lemma areas for the threshold ML-DSA-65
scaffold against the current proof-surface documents. Status values are limited
to:

- `implemented engineering guard`
- `proof sketch only`
- `external theorem dependency`
- `open`

An `implemented engineering guard` means the repository has a code or test
invariant that supports the obligation as a scaffold guard. It is not a
cryptographic proof. Active-adversary security is not complete in this
repository.

## Matrix

| Area | Source surface | Obligation | Current status | Notes |
| --- | --- | --- | --- | --- |
| FST-T1 threshold unforgeability | `formal-security-theorem.md` | Prove threshold EUF-CMA security for static corruption of at most `t - 1` validators from FST-A1 through FST-A8 and FST-L1 through FST-L7. | open | The theorem is explicitly not proved; current backend is deterministic simulation. |
| FST-T2 real/ideal realization | `formal-security-theorem.md`, `ideal-functionality.md` | Construct a simulator and prove UC-style realization of `F_TMLDSA` under the selected network and corruption model. | open | Requires FST-L1 through FST-L9 plus simulator hybrids and concrete bounds. |
| FST-T3 transcript non-malleability | `formal-security-theorem.md`, `formal-threshold-mldsa-transcript.md`, `random-oracle-game.md`, `proof-implementation-crosswalk.md` | Show canonical transcript encodings cannot bind one challenge to two distinct typed sessions. | proof sketch only | Current tests cover deterministic ordering and challenge changes, but no formal encoding injectivity proof is present. |
| FST-T4 implementation conformance gate | `formal-security-theorem.md`, `proof-implementation-crosswalk.md` | Keep conformance evidence separate from cryptographic reductions. | implemented engineering guard | Backend boundaries, type-state flow, and tests support traceability only. |
| FST-T5 thesis and operating-parameter boundary | `thesis-operating-parameters.md`, `thesis-operating-parameters.json`, `claims-matrix.md` | Keep thesis id, Profile P1 assumptions, promotion criteria, failure criteria, and fallback trigger explicit without promoting any criterion. | implemented engineering guard | The manifest pins `research scaffold only`, all five criteria as `partially_met`, and Falcon/LaBRADOR-style proof aggregation as `evaluate_only`; this is not selected-backend proof closure or production threshold ML-DSA security. |
| FST-T6 Criterion 2 proof-substance boundary | `criterion-2-proof-substance.md`, `criterion-2-proof-substance.json`, `rejection-equivalence-evidence.md` | Keep the aggregate rejection-equivalence proof payload explicit without claiming verifier compatibility, rejection-distribution preservation, or criterion closure. | implemented engineering guard | The manifest pins required artifact slots and theorem links for proof review; Criterion 2 remains `partially_met` and open. |
| FST-L1 canonical transcript injectivity | `formal-security-theorem.md`, `formal-threshold-mldsa-transcript.md`, `correctness-lemmas.md` | Prove exact production byte encoding is injective for all challenge-bearing fields. | proof sketch only | `SigningTranscript` binds explicit fields; formal wire-level injectivity remains missing. |
| FST-L2 challenge binding | `formal-security-theorem.md`, `formal-threshold-mldsa-transcript.md`, `random-oracle-game.md`, `correctness-lemmas.md`, `noise-rejection-proof-plan.md` | Prove commitments, session ID, threshold, validator set, key, message, and ordered commitment map are fixed before challenge use. | implemented engineering guard | The scaffold constructs transcripts after canonical commitments; real ML-DSA commitment semantics remain open. |
| FST-L3 validator-set soundness | `formal-security-theorem.md`, `correctness-lemmas.md`, `proof-implementation-crosswalk.md` | Reject duplicate, unknown, insufficient, and mismatched validator collections before transcript or aggregation use. | implemented engineering guard | `CommitmentSet` and `PartialShareSet` enforce scaffold collection validation. |
| FST-L4 partial-share validity | `formal-security-theorem.md`, `proof-implementation-crosswalk.md` | Verify each partial share against signer metadata, transcript, commitment, and public key with attributable failure evidence. | open | Simulation partials are deterministic fixtures and do not prove real partial-share equations. |
| FST-L5 aggregation correctness | `formal-security-theorem.md`, `correctness-lemmas.md` | Show at least `t` valid partial shares for one transcript aggregate to a standard-valid ML-DSA signature. | open | Algebraic response aggregation is stated for a future real backend. |
| FST-L6 no subthreshold signing | `formal-security-theorem.md`, `vss-dkg-security-plan.md` | Show fewer than `t` corrupt shares cannot produce unauthorized aggregate signatures except by breaking listed assumptions. | open | Depends on real VSS/DKG sharing soundness and real partial verification. |
| FST-L7 abort compatibility | `formal-security-theorem.md`, `noise-rejection-proof-plan.md` | Prove threshold abort and rejection behavior preserves the accepted ML-DSA-65 signature distribution. | open | Requires a selected threshold construction and Fiat-Shamir-with-aborts analysis. |
| FST-L8 ideal extraction | `formal-security-theorem.md`, `ideal-functionality.md` | Extract or simulate real invalid-share, abort, and aggregate-output events into ideal functionality calls. | open | No simulator construction or extraction proof is present. |
| FST-L9 evidence noninterference | `formal-security-theorem.md`, `active-adversary-model.md`, `vss-dkg-security-plan.md` | Prove evidence generation reveals no honest secret material and adds no signing capability. | proof sketch only | Evidence categories exist as adapter diagnostics; production anti-framing and leakage proofs remain open. |
| Correctness Lemma 1 field inversion | `correctness-lemmas.md` | Prove `modular_inverse(a)` returns `a^{-1}` for nonzero field elements and callers avoid zero denominators. | proof sketch only | Fermat-based implementation is described; caller preconditions and timing analysis remain. |
| Correctness Lemma 2 Lagrange basis | `correctness-lemmas.md` | Prove computed coefficients reconstruct degree-bounded polynomials at zero for duplicate-free nonzero indices. | proof sketch only | Formula is implemented; boundary validation proof is incomplete. |
| Correctness Lemma 3 Shamir reconstruction over `R_q` | `correctness-lemmas.md`, `vss-dkg-security-plan.md` | Prove coefficient-lane reconstruction of polynomial shares and production-random sharing privacy. | proof sketch only | Algebra is scaffolded; deterministic masks are not privacy evidence. |
| Correctness Lemma 4 canonical collection determinism | `correctness-lemmas.md`, `proof-implementation-crosswalk.md` | Prove valid network multisets produce canonical order independent of arrival order. | implemented engineering guard | BTree-backed validation and tests support the scaffold invariant. |
| Correctness Lemma 5 transcript challenge binding | `correctness-lemmas.md`, `formal-security-theorem.md` | Prove challenge bytes are determined by exactly the listed transcript fields. | implemented engineering guard | Implemented for simulation transcript construction, not a full ML-DSA proof. |
| Correctness Lemma 6 threshold response aggregation | `correctness-lemmas.md`, `noise-rejection-proof-plan.md` | Prove partial responses recombine to `z = y + c * s` in the exact ML-DSA module domain. | open | Real response equations and backend are absent. |
| Correctness Lemma 7 standard verification compatibility | `correctness-lemmas.md`, `noise-rejection-proof-plan.md` | Prove emitted aggregate signatures pass standard ML-DSA-65 verification. | open | `SimulatedBackend::verify_standard` is unavailable. |
| Correctness Lemma 8 infinity-norm preservation | `correctness-lemmas.md`, `noise-rejection-proof-plan.md` | Prove accepted aggregate responses, hints, and challenges satisfy all ML-DSA-65 verifier bounds. | open | Scalar `Poly` bound checks are not full module-vector ML-DSA checks. |
| Noise Lemma A mask commitment before challenge | `noise-rejection-proof-plan.md`, `formal-threshold-mldsa-transcript.md`, `random-oracle-game.md` | Define real mask commitments and prove they are fixed before challenge derivation. | proof sketch only | Ordering exists in the scaffold; real commitment binding/hiding is unspecified. |
| Noise Lemma B aggregate mask distribution | `noise-rejection-proof-plan.md` | Prove aggregate threshold masks match or are acceptably close to the standard ML-DSA mask distribution. | open | Requires selected construction and Renyi divergence bound for `epsilon_mask`; no production bound is complete. |
| Noise Lemma C response algebra and norm bound | `noise-rejection-proof-plan.md`, `correctness-lemmas.md` | Prove response algebra and final `||z||_inf` bound for accepted signatures. | open | Real aggregate response and module-vector bounds are not implemented. |
| Noise Lemma D aggregate rejection bound preservation | `noise-rejection-proof-plan.md` | Prove final encoded aggregate responses, hints, and challenges satisfy verifier-side predicates. | open | Boundary and malformed-hint tests are listed as future artifacts. |
| Noise Lemma E local rejection soundness | `noise-rejection-proof-plan.md` | Define and prove a local accept predicate for partial responses. | open | No production `LocalAccept` predicate is specified. |
| Noise Lemma F aggregate rejection soundness | `noise-rejection-proof-plan.md` | Define and prove aggregate acceptance gates, including standard verification or equivalent checks. | open | Current aggregator delegates to a simulated hash backend. |
| Noise Lemma G abort distribution | `noise-rejection-proof-plan.md`, `active-adversary-model.md` | Bound observable local and aggregate abort leakage under the chosen adversary view. | open | Requires network, retry, slashing, and leakage model choices. |
| Noise Lemma H accepted-signature distribution | `noise-rejection-proof-plan.md` | Prove accepted threshold signatures have the standard ML-DSA-65 distribution or a quantified Renyi divergence bound accepted by the proof. | open | Needs external threshold ML-DSA construction and review. |
| VSS binding | `vss-dkg-security-plan.md` | Prove accepted VSS commitments bind to one degree-`< tau` dealer polynomial and context. | open | Current VSS is deterministic scaffold code. |
| VSS hiding | `vss-dkg-security-plan.md` | Prove fewer than `tau` corrupt validators learn no useful secret information before reconstruction. | open | Requires production commitments, encrypted shares, and proof system. |
| VSS extractability | `vss-dkg-security-plan.md` | Extract a unique accepted dealer polynomial or reject with public evidence. | open | No production extractable proof system is selected. |
| DKG output agreement and robustness | `vss-dkg-security-plan.md`, `active-adversary-model.md` | Prove honest validators finalize one accepted-dealer set, transcript, share relation, and public key. | open | Simulated DKG is not malicious-secure. |
| DKG key-bias resistance | `vss-dkg-security-plan.md`, `active-adversary-model.md` | Prove rushing adversaries cannot bias the joint key beyond the stated bound. | open | Requires commit-before-share or equivalent production protocol proof. |
| Complaint evidence anti-framing | `active-adversary-model.md`, `vss-dkg-security-plan.md` | Define public evidence predicates that identify dealer or receiver faults without framing honest validators. | proof sketch only | Evidence semantics are specified as requirements; adapter evidence is not production slashing authority. |
| Static active adversary model | `active-adversary-model.md`, `formal-security-theorem.md` | Choose and prove static active security for the first production claim. | proof sketch only | The model is described, but no proof is completed. |
| Adaptive active adversary with erasures | `active-adversary-model.md`, `formal-security-theorem.md` | Prove adaptive security with erasure points, channel assumptions, and state-exposure theorem. | open | The docs explicitly prohibit adaptive claims without these additions. |
| Standard ML-DSA-65 unforgeability | `formal-security-theorem.md` | Rely on accepted ML-DSA-65 EUF-CMA security for the selected model. | external theorem dependency | Must cite the external FIPS 204/ML-DSA security analysis used by the final proof. |
| Commitment and proof-system soundness | `formal-security-theorem.md`, `vss-dkg-security-plan.md` | Rely on binding, hiding, extractability, and zero-knowledge properties of selected production primitives. | external theorem dependency | Profile P1 selects the coordinator-assisted Shamir nonce DKG direction, but concrete audited commitment, encryption, and proof-system primitives remain unselected. |
| Constant-time and side-channel discipline | `formal-security-theorem.md`, `vss-dkg-security-plan.md` | Show implementation leakage does not invalidate the proof assumptions. | open | No side-channel audit is complete. |

## Wording Risks

- Rows marked `implemented engineering guard` must not be quoted as proof of
  FST-T1, FST-T2, active-adversary security, or production ML-DSA compatibility.
- Rows marked `proof sketch only` identify proof-plan text or scaffold evidence,
  not theorem completion.
- Active-adversary and adaptive-corruption claims remain incomplete until a
  production VSS/DKG protocol, network model, erasure model, and simulator are
  selected and proved.
