# Cryptographic Claims Matrix

Status: publication-facing claim boundary for the threshold ML-DSA-65 scaffold.

Date: 2026-05-27

## Scope

This matrix separates current repository claims from proof targets introduced
by the current proof-surface and traceability documents:

- `active-adversary-model.md`
- `claims-matrix.md`
- `correctness-lemmas.md`
- `formal-security-theorem.md`
- `formal-threshold-mldsa-transcript.md`
- `ideal-functionality.md`
- `noise-rejection-proof-plan.md`
- `proof-implementation-crosswalk.md`
- `protocol-code-crosswalk.md`
- `proof-obligations.md`
- `random-oracle-game.md`
- `side-channel-boundary.md`
- `vss-dkg-security-plan.md`

Allowed status values are:

- `implemented engineering guard`
- `hazmat conformance only`
- `proof sketch only`
- `external theorem dependency`
- `open`

No row in this document claims completed active-adversary security or
production threshold ML-DSA security.

## Matrix

| Claim area | Current repository claim | Full-proof surface | Status | Publication boundary |
| --- | --- | --- | --- | --- |
| Deterministic transcript binding | The scaffold derives a challenge from protocol label, version, session ID, threshold, validator set, public key, message, and ordered commitments. | FST-L1, FST-L2, Correctness Lemma 5, Noise Lemma A | implemented engineering guard | May claim scaffold transcript binding tests; must not claim formal injectivity or ML-DSA distribution equivalence. |
| Canonical validator and share collections | The scaffold rejects duplicate, unknown, insufficient, and mismatched validator collections before transcript or aggregation use. | FST-L3, Correctness Lemma 4 | implemented engineering guard | May claim API-level collection validation; must not claim malicious-secure share validity. |
| Commitment-before-challenge flow | The type-state and transcript flow exercise commitment collection before challenge-dependent partial signing in simulation. | FST-L2, Noise Lemma A | implemented engineering guard | May claim protocol-order guard in the scaffold; real mask commitment binding/hiding remains unproved. |
| Aggregation boundary validation | Aggregation receives a bound transcript and threshold-valid partial-share set before delegating to the backend. | FST-L5, Correctness Lemma 6, Noise Lemma F | implemented engineering guard | May claim boundary checks; must not claim aggregate signatures are standard ML-DSA signatures. |
| Wire frame and evidence shape | Adapter frames and local evidence containers are versioned scaffold surfaces. | FST-L9, active-adversary evidence semantics | implemented engineering guard | May claim local diagnostics and malformed-frame rejection; must not claim production slashing or anti-framing. |
| Coordinator-assisted ML-DSA-65 profile | The selected production-candidate backend direction is Profile P1: non-default ML-DSA-65 coordinator-assisted Shamir nonce DKG with a TEE/HSM-backed coordinator assumption and a standard-verifier compatibility target. Current code exercises production-candidate skeleton boundaries for profile types, non-public production policy gates, transcript bindings over the original application message plus `mu`, preprocessing attempts, provider boundaries, the final verifier gate, production wire frames, bounded NIST ACVP-Server FIPS204 ML-DSA-65 sigVer sample conformance, and compile-fail simulator rejection. | FST-T4, FST-L1, FST-L5, Noise Lemmas A, E, and F | hazmat conformance only | The safe claim is selection of the Profile P1 coordinator-assisted ML-DSA-65 direction, ordinary provider conformance evidence, and hazmat conformance scaffolding only; aggregate standard-verifier compatibility remains a target until real threshold recomputation, full KAT, bridge-test, proof, and audit gates pass. It must not be described as production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or completed proof. Later Profile P2/MPC and TALUS paths are migration candidates, not current claims. |
| Epsilon pre-filter and hint-routing guardrails | `EpsilonLedger` records deterministic conformance counters for masking, rejection, and withholding residuals; the blinded pre-filter gate returns a pass token or abort record before share release; hint-routing conformance types carry only public digests; and the signing hot path preserves the DKG setup-only boundary. | Noise Lemmas C, D, F, and H; FST-L5; FST-L9 | hazmat conformance only | May claim typed ordering guardrails, Renyi divergence accounting labels, blinded pre-filter pass/abort frames, hint-routing conformance state, and DKG setup-only boundary documentation; must not claim production Gaussian sampling, real ML-DSA hint correctness, or completed rejection-distribution preservation. |
| Typed acceptance predicates | `LocalAccept` and `AggregateAccept` in `src/production/acceptance.rs` are hazmat/conformance-only typed acceptance predicates for coordinator-assisted scaffolding, with conformance tests in `tests/production_acceptance.rs`. | FST-L4, FST-L5, Noise Lemmas E, F, and H | hazmat conformance only | May claim typed acceptance boundary wiring only; must not claim production partial verification, real aggregate recomputation, or distribution proof. |
| Five-criterion evidence gates and closure frameworks | `mask_distribution`, `rejection_equivalence`, `abort_bias`, and `partial_soundness` modules plus `unauthorized-aggregate-reduction.md` provide typed evidence gates, a P1 aggregate recomputation artifact gate, selected profile binding digest, standard-verifier bridge evidence digest, a checked-in standard-verifier bridge fixture package, selected-backend aggregate-output artifact gate, real standard-provider aggregate-output package derivation, selected-backend threshold-output artifact gate, selected-backend proof-closure artifact package gate, closure-package frameworks, stricter release-gate coverage, and a reduction-case manifest for the five hypothesis blockers. The Batch 4 package adds full KAT/validation artifact slots and a theorem-linkage artifact digest for proof review. | Noise Lemmas B, F, G, and H; FST-L4, FST-L6, FST-L7, FST-T1 | hazmat conformance only | May claim partial executable evidence-gate, sample-vector provider conformance, bridge fixture conformance evidence, selected-profile drift rejection, fixture-backed bridge digest drift rejection, selected-backend aggregate-output artifact gate drift rejection, real standard-provider aggregate-output package evidence, selected-backend threshold-output artifact gate drift rejection, selected-backend proof-closure artifact package gate drift rejection, raw fixture-package digest carriage with test-pinned drift detection, and closure-framework coverage for blocker assessment only. The selected-backend aggregate-output artifact gate, real standard-provider aggregate-output package path, selected-backend threshold-output artifact gate, and selected-backend proof-closure artifact package gate are conformance/proof-review gates only; each remains a conformance/proof-review gate only and is not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, not selected-backend proof closure, and not a completed standard-verifier compatibility proof. This coverage is necessary but not sufficient for criterion promotion; it must not claim completed Renyi proof, real threshold aggregate recomputation, abort-bias proof, production partial verification, threshold EUF-CMA reduction, and must not claim completed standard-verifier compatibility proof. |
| Criterion 2 proof substance | `criterion-2-proof-substance.md` and `criterion-2-proof-substance.json` formalize the open proof payload required for `aggregate_rejection_equivalence`, including emitted-output verifier compatibility, aggregate acceptance equivalence, rejection-distribution substance, theorem links, required artifact slots, the checked `tests/fixtures/p1_real_recomputation_artifact_fixture.json` recomputation-slot fixture, and the checked `tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json` standard-verifier compatibility fixture. | Correctness Lemmas 7 and 8; Noise Lemmas D, F, and H; FST-L5; FST-L7 | hazmat conformance only | May claim the Criterion 2 proof-payload checklist is documented and assessor-visible as `criterion2_proof_payload_formalized`, with checked real recomputation and standard-verifier compatibility slot fixture evidence; must not claim Criterion 2 is met, selected-backend proof closure, rejection-distribution preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or completed standard-verifier compatibility. |
| Thesis and operating parameters | `thesis-operating-parameters.md` and `thesis-operating-parameters.json` formalize thesis id `native-threshold-mldsa65-aggregation-p1`, Profile P1 operating assumptions, parameter notation, promotion criteria, failure criteria, and fallback trigger. | FST-0, FST-1, FST-D2, proof-obligations.md | hazmat conformance only | May claim the current thesis and operating-parameter boundary is documented as `research scaffold only`; must not claim selected-backend proof closure, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, rejection-distribution preservation, or completed standard-verifier compatibility. Formalization does not promote any of the five criteria beyond `partially_met`. |
| Field inversion and Lagrange arithmetic | The code implements Fermat inversion and Lagrange coefficient formulas over the scaffold modulus. | Correctness Lemmas 1 and 2 | proof sketch only | May describe algebraic scaffold and tests; caller preconditions and timing analysis remain proof obligations. |
| Shamir-style reconstruction over `R_q` | Coefficient-lane reconstruction is described and scaffolded for deterministic shares. | Correctness Lemma 3 | proof sketch only | Must not claim sharing privacy because deterministic masks are not production randomness. |
| Standard ML-DSA verification compatibility | The real standard-provider aggregate-output package path can bind one provider-verified ML-DSA-65 candidate signature through acceptance, recomputation, and bridge digest evidence; the selected-backend threshold-output artifact gate can bind that evidence to a threshold-output source package for proof review; and the selected-backend proof-closure artifact package gate can bind those outputs to full KAT/validation artifact slots, rejection-distribution review, standard-verifier compatibility artifacts, and a theorem-linkage artifact digest. No threshold aggregate signature is claimed to verify as a standard ML-DSA-65 signature. | Correctness Lemma 7, FST-L5 | open | A selected-backend aggregate-output artifact gate now binds accepted aggregate conformance evidence to recomputation and bridge digests; the real standard-provider package path is stronger than fixture-only bridge confidence; the selected-backend threshold-output artifact gate is stronger than real standard-provider aggregate-output package evidence; and the selected-backend proof-closure artifact package gate is stronger than the selected-backend threshold-output artifact gate. It is still not selected-backend proof closure and not a completed standard-verifier compatibility proof. Keep compatibility language as future work until reviewed proof/audit artifacts, full KAT/validation gates, rejection-distribution preservation, and required standard-verifier compatibility proof artifacts exist. |
| Infinity-norm and hint-bound preservation | Scalar polynomial bound checks exist as low-level scaffolding only. | Correctness Lemma 8, Noise Lemmas C and D | open | Must not imply full ML-DSA-65 module-vector norm, hint, or challenge checks are implemented. |
| Local partial-share validity | Simulated partial shares are deterministic API fixtures. | FST-L4, Noise Lemma E | open | Must not claim production partial verification, extractability, fraud proofs, or slashing soundness. |
| Aggregate rejection soundness | The simulated aggregator does not implement real ML-DSA aggregate recomputation or standard verification. | Noise Lemma F | open | Must present current aggregation as simulation and boundary validation only. |
| Rejection-sampling distribution preservation | No threshold Fiat-Shamir-with-aborts distribution proof is present. | FST-L7, Noise Lemmas G and H | open | Must not claim accepted threshold signatures match standard ML-DSA distribution. |
| Threshold unforgeability | The repository states FST-T1 as a target theorem. | FST-T1 | open | Must not claim EUF-CMA security for the threshold scaffold. |
| Real/ideal realization | The repository states FST-T2 and ideal-functionality targets. | FST-T2, FST-L8, `ideal-functionality.md` | open | Must not claim UC realization or completed simulator. |
| Transcript non-malleability | Deterministic ordering tests support the direction of the claim. | FST-T3, FST-L1, FST-L2 | proof sketch only | May claim partial scaffold support; no formal byte-encoding proof exists. |
| Implementation conformance as evidence | Tests and backend contracts are useful gates for future production backends. | FST-T4, `proof-implementation-crosswalk.md` | implemented engineering guard | Conformance is necessary but not sufficient for cryptographic security. |
| VSS/DKG binding | Production VSS must bind commitments and shares to one dealer polynomial and context. | `vss-dkg-security-plan.md` | open | Current `src/crypto/vss.rs` and `src/dkg.rs` are deterministic/simulated. |
| VSS/DKG hiding | Production VSS/DKG must hide honest dealer contributions against fewer than `tau` corrupt validators. | `vss-dkg-security-plan.md` | open | Must not claim secrecy for current deterministic VSS masks. |
| VSS/DKG extractability | Accepted dealer transcripts must be extractable or rejected with public evidence. | `vss-dkg-security-plan.md` | open | No extractable production proof system is selected. |
| DKG output agreement and robustness | A production protocol must make honest validators finalize the same accepted-dealer set, transcript, share relation, and public key. | `vss-dkg-security-plan.md`, `active-adversary-model.md` | open | Simulated DKG does not provide malicious-secure agreement or robustness. |
| DKG key-bias resistance | A production proof must address rushing and last-mover abort bias. | `vss-dkg-security-plan.md`, `active-adversary-model.md` | open | No bias-resistance claim is available for the scaffold. |
| Static active-adversary model | The model describes static active corruption as the conservative first production target. | `active-adversary-model.md`, FST-D2 | proof sketch only | Do not state that static active security is complete; only the target model is described. |
| Adaptive active-adversary model | Adaptive security requires erasures, channel assumptions, and a state-exposure theorem. | `active-adversary-model.md`, FST-X5 | open | Must not claim adaptive security. |
| Public complaint and anti-framing evidence | Production evidence predicates are specified as requirements. | `active-adversary-model.md`, `vss-dkg-security-plan.md`, FST-L9 | proof sketch only | Current evidence records are adapter diagnostics, not chain-verifiable slashing proofs. |
| ML-DSA-65 base unforgeability | A final proof must rely on the accepted external ML-DSA-65 security theorem. | FST-A1 | external theorem dependency | Cite the selected external theorem in any production proof package. |
| Commitment, encryption, and proof-system assumptions | A final VSS/DKG proof must rely on selected primitive assumptions. | FST-A3, FST-A4, `vss-dkg-security-plan.md` | external theorem dependency | No concrete audited primitive stack is selected in this repository. |
| Constant-time, randomness, and erasure discipline | Production implementations must satisfy leakage, randomness, and erasure assumptions. | FST-A9, `active-adversary-model.md`, `vss-dkg-security-plan.md` | open | No constant-time or state-exposure audit is complete. |

## Related Work Comparator

Falcon/LaBRADOR-style proof-wrapper aggregation is related work and an
external comparator, not an implemented repository path. In that model, the
system proves that many independent Falcon signatures satisfy their verifier
relations and compresses the proof object around those already-formed
signatures. See the Ethereum Research discussion,
[Lattice-based signature aggregation](https://ethresear.ch/t/lattice-based-signature-aggregation/22282),
for one public benchmark and protocol comparison.

This repository targets a different and riskier construction: native threshold
ML-DSA-65 signing that would, if all theorem, backend, bridge-test, and audit
gates close, emit one standard-verifier-compatible ML-DSA-65 signature under an
epoch threshold public key. That path is higher-risk because it must preserve
mask distribution, rejection behavior, partial contribution soundness,
selective-abort bounds, and threshold unforgeability inside the signing
protocol itself. Its upside is also higher: a successful construction would use
the ordinary ML-DSA verifier and a standard-sized aggregate instead of a
separate proof-wrapper verifier and larger proof artifact.

The safe publication boundary is therefore comparative only. The repository may
contrast proof-wrapper aggregation with native threshold signatures, but must
not claim that the native threshold ML-DSA path is proven, implemented for
production, standard-verifier compatible, or superior in deployed performance.

## Non-Claims

The repository must continue to avoid these claims until the corresponding
proof obligations are complete:

- Active-adversary VSS/DKG security.
- Adaptive corruption security.
- Production slashing or anti-framing soundness.
- Standard ML-DSA-65 verifier compatibility for simulated aggregate signatures.
- Production partial verification, real aggregate recomputation, or distribution
  proof from `LocalAccept` or `AggregateAccept` conformance tokens.
- Completed proof of any hypothesis criterion from evidence gates or reduction
  manifests alone.
- Threshold EUF-CMA security or real/ideal realization.
