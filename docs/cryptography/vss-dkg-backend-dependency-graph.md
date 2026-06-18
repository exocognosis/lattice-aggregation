# VSS/DKG Backend Dependency Graph
<a id="vss-dkg-backend-dependency-graph"></a>

Stable anchor: vss-dkg-backend-dependency-graph

Status: Batch E dependency graph and blocker list, not a backend selection or proof.

Theorem target name: Theorem D3-vss-dkg-backend-dependency-closure

This document records the dependency path from the ideal `F_VSS_DKG` boundary
to any future production VSS/DKG backend selection. The current repository has
no selected production VSS/DKG backend. The deterministic Rust path remains a
scaffold and policy-gated proof boundary, not malicious-secure production DKG.

## D3-0. Target Boundary
<a id="d3-target-boundary"></a>

Theorem D3-vss-dkg-backend-dependency-closure. A production backend selection
may replace the ideal `F_VSS_DKG` route only after every dependency below is
specified, proved or bounded, implemented, audited, and composed into the
`FST-T1` theorem route with explicit residual accounting:

```text
eps_vss(A,Z)
  <= eps_vss_backend_selection(A,Z)
   + eps_vss_binding(A,Z)
   + eps_vss_hiding(A,Z)
   + eps_vss_extract(A,Z)
   + eps_vss_complaint(A,Z)
   + eps_vss_key_bias(A,Z)
   + eps_vss_privacy(A,Z)
   + eps_vss_anti_framing(A,Z)
   + eps_vss_pk_derivation(A,Z)
   + eps_vss_impl(A,Z).
```

Until this target is closed, the signing-side theorem may use `eps_vss_ideal`
only as an ideal-functionality decomposition term, not as production backend
evidence.

## D3-1. Dependency Graph
<a id="d3-dependency-graph"></a>

| Node | Depends on | Required closure | Residual terms |
| --- | --- | --- | --- |
| Ideal `F_VSS_DKG` boundary | Declared setup leakage and ideal output semantics | Keep ideal assumptions separate from production obligations and charge unresolved setup realization to `eps_vss_ideal`. | `eps_vss_ideal`, `eps_vss` |
| Backend selection | Candidate families, assumptions, parameters, auditability | Select a concrete backend ID, version, parameter set, security assumptions, proof route, implementation plan, and external-review scope. | `eps_vss_backend_selection`, `eps_vss_impl` |
| Transcript grammar | Backend selection | Define canonical encodings, domain separators, validator/dealer ordering, transcript digests, failure records, and verifier inputs. | `eps_vss_binding`, `eps_vss_complaint`, `eps_vss_impl` |
| Dealerless setup | Transcript grammar | Specify the network model, static active corruption threshold, rushing power, retry policy, exclusion policy, and deterministic abort/finalize semantics. | `eps_vss_extract`, `eps_vss_key_bias`, `eps_vss_impl` |
| Coefficient commitments | Backend selection, transcript grammar | Bind each accepted dealer contribution to one polynomial or module-vector witness in the exact ML-DSA-compatible setup context. | `eps_vss_binding`, `eps_vss_hiding`, `eps_vss_extract` |
| Private share delivery | Transcript grammar, dealerless setup | Provide authenticated confidential receiver delivery with identity binding, replay protection, malformed-frame rules, and delivery transcript binding. | `eps_vss_hiding`, `eps_vss_privacy`, `eps_vss_anti_framing`, `eps_vss_impl` |
| Complaint verification | Coefficient commitments, private share delivery | Provide deterministic public predicates for bad shares, invalid complaints, missing responses, malformed objects, equivocation, and inconclusive cases. | `eps_vss_complaint`, `eps_vss_anti_framing`, `eps_vss_privacy`, `eps_vss_impl` |
| Agreement/extractability | Transcript grammar, coefficient commitments, complaint verification | Prove unique extraction or ideal realization for accepted dealer transcripts and agreement on dealer set, complaint log, share semantics, and setup digest. | `eps_vss_extract`, `eps_vss_binding`, `eps_vss_complaint` |
| Key-bias resistance | Dealerless setup, complaint verification, agreement/extractability | Bound rushing, last-mover abort, complaint timing, dealer exclusion, retry, ordering, and finalization bias on `pk_epoch`. | `eps_vss_key_bias`, `eps_vss_complaint`, `eps_vss_extract` |
| Privacy/hiding | Coefficient commitments, private share delivery, complaint verification | Prove hiding or witness hiding for unopened coefficients, receiver shares, openings, complaint responses, timing, and malformed-object behavior. | `eps_vss_hiding`, `eps_vss_privacy`, `eps_vss_complaint`, `eps_vss_impl` |
| Anti-framing | Private share delivery, complaint verification, epoch binding | Prove corrupted parties cannot create public evidence falsely blaming honest dealers or receivers. | `eps_vss_anti_framing`, `eps_vss_complaint`, `eps_vss_binding`, `eps_vss_impl` |
| Threshold public key derivation | Coefficient commitments, agreement/extractability | Prove accepted dealer constants, public-key contributions, final shares, and `pk_epoch` derive from the same extracted setup transcript. | `eps_vss_pk_derivation`, `eps_vss_extract`, `eps_vss_binding` |
| Epoch binding | Transcript grammar, threshold public key derivation | Bind every commitment, encrypted share, opening, complaint, accepted dealer set, threshold, validator set, parameter set, and public key to one epoch transition and `dkg_digest`. | `eps_vss_binding`, `eps_vss_pk_derivation`, `eps_vss_anti_framing`, `eps_vss_impl` |
| Implementation/audit | All concrete backend objects and predicates | Implement canonical verifiers, fail-closed gates, negative tests, resource limits, side-channel review, interoperability tests, vectors, and external cryptographic audit. | `eps_vss_impl`, `eps_vss_backend_selection` |
| Proof composition into `FST-T1` | All preceding nodes | Replace or relate `eps_vss_ideal` to concrete `eps_vss`, preserve setup leakage, and import the backend theorem into the final threshold ML-DSA proof. | `eps_vss`, `eps_vss_ideal`, all `eps_vss_*` subterms |

## D3-2. Blocking Checklist
<a id="d3-blocking-checklist"></a>

The backend remains blocked until all of the following are complete:

- Backend selection: no concrete production VSS/DKG backend, backend ID,
  parameter set, or proof system has been selected.
- Transcript grammar: canonical setup, commitment, share-delivery, complaint,
  response, finalization, and epoch-binding encodings are not finalized.
- Dealerless setup: the production network, rushing, retry, exclusion, and
  deterministic abort semantics are not proved.
- Coefficient commitments: no selected post-quantum-compatible binding and
  hiding commitment/opening relation is proved for the ML-DSA setup context.
- Private share delivery: no production confidential authenticated delivery
  proof is integrated with complaint and anti-framing evidence.
- Complaint verification: public deterministic complaint predicates and
  malformed-object handling are not complete.
- Agreement/extractability: no malicious-secure extraction or ideal-realization
  theorem exists for accepted dealer transcripts.
- Key-bias resistance: no bound covers rushing, last-mover abort, complaint
  timing, exclusion, retry, ordering, and finalization effects.
- Privacy/hiding: no proof closes coefficient, share, opening, complaint,
  timing, and malformed-object leakage.
- Anti-framing: no proof covers every public evidence path against honest
  dealers and honest receivers.
- Threshold public key derivation: no proof ties accepted dealer constants,
  final shares, and `pk_epoch` to the same extracted transcript.
- Epoch binding: no production proof binds every setup object to the epoch
  transition, validator set, parameter set, accepted dealer set, and
  `dkg_digest`.
- Implementation/audit: verifier code, negative tests, vectors,
  interoperability tests, side-channel review, resource limits, and external
  cryptographic audit are not sufficient to support a production claim.
- Proof composition into `FST-T1`: no final theorem imports a concrete
  malicious-secure VSS/DKG backend and replaces the ideal-only setup boundary.

## D3-3. Closure Order
<a id="d3-closure-order"></a>

Close dependencies in this order:

1. Select the backend family, backend ID, assumptions, parameter set, and
   production eligibility criteria.
2. Freeze the transcript grammar and epoch-binding domains before writing
   backend proofs or verifier tests.
3. Specify dealerless setup, private delivery, complaint, response, finalize,
   retry, exclusion, and abort semantics.
4. Prove coefficient commitment binding, hiding, and extractability in the
   exact setup relation.
5. Prove complaint soundness, privacy, anti-framing, key-bias resistance, and
   threshold public-key derivation against the declared active adversary.
6. Implement canonical verifiers, fail-closed production gates, negative tests,
   resource limits, vectors, and interoperability checks.
7. Complete side-channel review, implementation review, and external
   cryptographic audit.
8. Compose the backend theorem into `FST-T1`, replacing the ideal
   `F_VSS_DKG` dependency with the concrete `eps_vss` residual ledger.

## D3-3A. Rust Boundary Anchors
<a id="d3-rust-boundary-anchors"></a>

The current Rust crate exposes policy and statement names that future
production VSS/DKG work must either satisfy or replace. These names are
traceability anchors, not evidence that a production backend has been selected
or proved.

| Proof dependency | Rust boundary |
| --- | --- |
| Production setup statement | `ProductionVssRelationStatement` |
| Statement byte contract | `PRODUCTION_VSS_RELATION_STATEMENT_BYTES` |
| Current deterministic scaffold profile | `VssCommitmentSecurityProfile::DeterministicTranscriptScaffold` |
| Blocked candidate profile | `VssCommitmentSecurityProfile::ProductionCandidateScaffold` |
| Required production profile | `VssCommitmentSecurityProfile::ProductionBindingHiding` |
| Experimental backend family | `ExperimentalVssCommitmentBackend` |
| VSS-only fail-closed gate | `require_production_vss_backend` |
| Combined threshold fail-closed gate | `require_production_threshold_backends` |

If a future backend cannot satisfy these anchors or a reviewed replacement, the
gap remains charged to `eps_vss_impl` and the repository still has no selected
production VSS/DKG backend.

## D3-3B. Batch G Code-Evidence Anchors
<a id="d3-batch-g-code-evidence-anchors"></a>

Batch G adds code-evidence anchors for production-shaped VSS relation
statements and hazmat+experimental actor complaint traces. The complaint-domain
and complaint-label constants listed here are actor anchors behind the combined
`hazmat-real-mldsa` + `experimental-vss` feature surface, not plain
`experimental-vss` VSS-backend exports. These anchors support dependency review
and `eps_vss_impl` bookkeeping only. They are not a production proof, no
production backend selected, and no selected production VSS/DKG backend is
changed by these names.

| Evidence target | Rust anchor |
| --- | --- |
| Production VSS relation byte length | `PRODUCTION_VSS_RELATION_STATEMENT_BYTES` |
| Production VSS relation schema version | `PRODUCTION_VSS_RELATION_STATEMENT_SCHEMA_VERSION` |
| Production VSS relation digest domain | `PRODUCTION_VSS_RELATION_STATEMENT_DOMAIN` |
| Experimental production-shaped object version | `EXPERIMENTAL_VSS_OBJECT_VERSION` |
| Hazmat+experimental actor complaint trace root domain | `EXPERIMENTAL_VSS_COMPLAINT_DOMAIN` |
| Complaint context label | `EXPERIMENTAL_VSS_CONTEXT_LABEL` |
| Dealer commitment label | `EXPERIMENTAL_VSS_DEALER_COMMITMENT_LABEL` |
| Raw share label | `EXPERIMENTAL_VSS_SHARE_LABEL` |
| Encrypted-share label | `EXPERIMENTAL_VSS_ENCRYPTED_SHARE_LABEL` |
| Opening label | `EXPERIMENTAL_VSS_OPENING_LABEL` |
| Adapter-error label | `EXPERIMENTAL_VSS_ADAPTER_ERROR_LABEL` |
| Backend label | `EXPERIMENTAL_VSS_BACKEND_LABEL` |
| Public-key contribution label | `EXPERIMENTAL_VSS_PUBLIC_KEY_CONTRIBUTION_LABEL` |
| Experimental production relation backend ID | `EXPERIMENTAL_VSS_PRODUCTION_RELATION_BACKEND_ID` |
| Production relation canonical D3 layout regression | `production_vss_relation_statement_canonical_layout_matches_d3_anchor` |
| Production relation digest field-binding regression | `production_vss_relation_statement_digest_binds_every_field` |
| Candidate VSS backend policy rejection regression | `combined_production_policy_rejects_candidate_vss_backend_without_experimental_feature` |

Implementation evidence is not cryptographic proof. These constants and tests
do not prove malicious-secure DKG, malicious-secure VSS, extractability,
hiding, complaint soundness, key-bias resistance, anti-framing, or production
public-key derivation.

## D3-4. Non-Claims
<a id="d3-non-claims"></a>

Non-claims: no production backend selected, no malicious-secure DKG proof, no
malicious-secure VSS proof, no zero/negligible claim, no backend selection
theorem, no binding theorem, no hiding theorem, no extractability theorem, no
complaint soundness theorem, no key-bias theorem, no privacy theorem, no
anti-framing theorem, and no public-key derivation theorem. Implementation
evidence is not cryptographic proof.

## D3-5. Manifest Anchors
<a id="d3-manifest-anchors"></a>

Stable strings:

- `# VSS/DKG Backend Dependency Graph`
- `vss-dkg-backend-dependency-graph`
- `Stable anchor: vss-dkg-backend-dependency-graph`
- `Status: Batch E dependency graph and blocker list, not a backend selection or proof.`
- `Theorem D3-vss-dkg-backend-dependency-closure`
- `F_VSS_DKG`
- `FST-T1`
- `eps_vss_backend_selection`
- `eps_vss_binding`
- `eps_vss_hiding`
- `eps_vss_extract`
- `eps_vss_complaint`
- `eps_vss_key_bias`
- `eps_vss_privacy`
- `eps_vss_anti_framing`
- `eps_vss_pk_derivation`
- `eps_vss_impl`
- `eps_vss_ideal`
- `eps_vss`
- `backend selection`
- `transcript grammar`
- `dealerless setup`
- `coefficient commitments`
- `private share delivery`
- `complaint verification`
- `agreement/extractability`
- `key-bias resistance`
- `privacy/hiding`
- `anti-framing`
- `threshold public key derivation`
- `epoch binding`
- `implementation/audit`
- `proof composition into FST-T1`
- `d3-rust-boundary-anchors`
- `d3-batch-g-code-evidence-anchors`
- `hazmat+experimental actor complaint traces`
- `hazmat-real-mldsa`
- `experimental-vss`
- `ProductionVssRelationStatement`
- `PRODUCTION_VSS_RELATION_STATEMENT_BYTES`
- `PRODUCTION_VSS_RELATION_STATEMENT_SCHEMA_VERSION`
- `PRODUCTION_VSS_RELATION_STATEMENT_DOMAIN`
- `EXPERIMENTAL_VSS_OBJECT_VERSION`
- `EXPERIMENTAL_VSS_COMPLAINT_DOMAIN`
- `EXPERIMENTAL_VSS_CONTEXT_LABEL`
- `EXPERIMENTAL_VSS_DEALER_COMMITMENT_LABEL`
- `EXPERIMENTAL_VSS_SHARE_LABEL`
- `EXPERIMENTAL_VSS_ENCRYPTED_SHARE_LABEL`
- `EXPERIMENTAL_VSS_OPENING_LABEL`
- `EXPERIMENTAL_VSS_ADAPTER_ERROR_LABEL`
- `EXPERIMENTAL_VSS_BACKEND_LABEL`
- `EXPERIMENTAL_VSS_PUBLIC_KEY_CONTRIBUTION_LABEL`
- `EXPERIMENTAL_VSS_PRODUCTION_RELATION_BACKEND_ID`
- `production_vss_relation_statement_canonical_layout_matches_d3_anchor`
- `production_vss_relation_statement_digest_binds_every_field`
- `combined_production_policy_rejects_candidate_vss_backend_without_experimental_feature`
- `VssCommitmentSecurityProfile::DeterministicTranscriptScaffold`
- `VssCommitmentSecurityProfile::ProductionCandidateScaffold`
- `VssCommitmentSecurityProfile::ProductionBindingHiding`
- `ExperimentalVssCommitmentBackend`
- `require_production_vss_backend`
- `require_production_threshold_backends`
- `no selected production VSS/DKG backend`
- `no production backend selected`
- `not a production proof`
- `no malicious-secure DKG proof`
- `no zero/negligible claim`
- `implementation evidence is not cryptographic proof`
