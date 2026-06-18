# F_CONTRIB Real/Ideal Simulator Draft
<a id="f-contrib-realization-simulator"></a>

Stable anchor: `f-contrib-realization-simulator`

Status: Batch E formal-reduction draft, not a completed realization proof.

Theorem target name: `Theorem C4-f-contrib-realization-simulator`

## C4-0. Scope
<a id="c4-scope"></a>

This document sketches the real/ideal simulator route for realizing
`F_CONTRIB`. It is a proof-planning artifact for immediate theorem work, not a
claim that any concrete proof system, MPC, interactive protocol, or production
backend realizes `F_CONTRIB`.

Immediate theorem work may cite this simulator draft only as a route. It does
not prove any concrete backend realizes `F_CONTRIB`.

## C4-1. Real Experiment
<a id="c4-real-experiment"></a>

The real experiment `RealContrib(A,Z)` runs the environment `Z`, adversary `A`,
honest validators, aggregator, contribution backend, transcript machinery, and
abort classifier with the concrete contribution-checking path. For each
attempt, the real experiment records:

- the public contribution statement `S_contrib_i`;
- the public contribution encoding and acceptance or rejection result;
- public leakage emitted by the concrete backend;
- transcript, session, epoch, active-set, validator, challenge, DKG,
  commitment, backend, and relation identifiers;
- rejection labels, abort labels, and scheduling metadata visible to `Z`; and
- the final transcript view returned to `Z`.

The real experiment accepts a corrupted contribution only through the concrete
backend predicate or proof-verification procedure. Honest witness material,
shares, masks, openings, and backend randomness are not exposed except through
declared public output or declared leakage.

## C4-2. Ideal Experiment
<a id="c4-ideal-experiment"></a>

The ideal experiment `IdealContrib(S,Z)` runs `Z` with simulator `S` and ideal
functionality `F_CONTRIB`. Honest contribution attempts are submitted to
`F_CONTRIB` with ideal witness handles. Corrupted accepted attempts are routed
through the simulator's extraction path or ideal replacement path before the
ideal functionality releases a public accepted contribution handle.

The ideal experiment gives `Z` the same public interface shape as the real
experiment: accepted records, rejected records, leakage records, transcript
bindings, session and epoch identifiers, abort labels, and final transcript
views. Any mismatch between this ideal view and the real view is charged to the
residual terms in `C4-10`.

## C4-3. Simulator State
<a id="c4-simulator-state"></a>

The simulator state contains:

- `session_table`, keyed by `(epoch_id, session_id, attempt)`;
- `statement_table`, keyed by canonical statement digest;
- `acceptance_table`, keyed by contribution handle and validator index;
- `extraction_table`, recording extracted witnesses or extraction failures;
- `replacement_table`, recording ideal replacement handles and reasons;
- `leakage_table`, recording declared leakage emitted to `Z`;
- `rejection_table`, recording rejection labels and public reasons;
- `abort_table`, recording abort labels and scheduling-visible abort metadata;
- `binding_table`, recording transcript, session, epoch, active-set,
  validator, challenge, DKG, commitment, backend, and relation bindings; and
- `randomness_table`, recording simulator coins needed to reproduce the ideal
  public view.

State entries are append-only within an epoch and must be domain-separated by
protocol version, parameter set, backend declaration, and relation identifier.

## C4-4. Simulator Inputs
<a id="c4-simulator-inputs"></a>

The simulator receives:

- the public environment inputs and adversarial messages;
- the active corruption set allowed by the theorem statement;
- public contribution statements and encodings submitted by corrupted parties;
- honest public statements and ideal witness handles supplied to `F_CONTRIB`;
- public transcript, session, epoch, active-set, challenge, DKG, commitment,
  backend, and relation context;
- declared leakage shape `L_contrib`; and
- rejection, abort, and scheduling information that is visible in the real
  experiment.

The simulator does not receive honest private witnesses, shares, masks,
commitment openings, or backend randomness except through ideal handles
explicitly supplied to `F_CONTRIB`.

## C4-5. Simulator Outputs
<a id="c4-simulator-outputs"></a>

The simulator outputs the ideal public view:

- `ContribAccepted` records with ideal contribution handles;
- `ContribRejected` records with public rejection reasons;
- declared leakage records aligned with `L_contrib`;
- transcript/session/epoch-bound acceptance and rejection records;
- abort records and public scheduling metadata; and
- the final public transcript view observed by `Z`.

The simulator also outputs proof bookkeeping for the reduction route:
extraction success or failure, ideal replacement success or failure, leakage
alignment status, rejection consistency status, abort consistency status, and
binding consistency status.

## C4-6. Leakage Alignment
<a id="c4-leakage-alignment"></a>

Leakage alignment requires the ideal view to expose exactly the leakage allowed
by `L_contrib`, plus public accept/reject and abort metadata already declared
by `F_CONTRIB`. Any concrete backend metadata not represented in
`L_contrib` must be hidden, simulated, or charged to `eps_contrib_leak`.

The simulator records each leakage item with its source statement digest,
epoch, session, attempt, validator, backend declaration, relation identifier,
and transcript digest. Leakage may not be reused across epochs, sessions,
attempts, validators, relation identifiers, or backend declarations.

## C4-7. Extraction Path
<a id="c4-extraction-path"></a>

For an accepted corrupted contribution, the simulator first attempts to extract
a witness `W_contrib_i` such that
`R_contrib(S_contrib_i, W_contrib_i)` holds under the exact statement grammar
and binding context. If extraction succeeds, the simulator submits the
statement and extracted witness to `F_CONTRIB` and records an accepted ideal
handle.

Extraction failure, ambiguity, context mismatch, non-canonical statement
material, or inability to bind the witness to the accepted real contribution is
charged to `eps_contrib_extract` and, when binding is implicated,
`eps_contrib_bind`.

## C4-8. Ideal Replacement Path
<a id="c4-ideal-replacement-path"></a>

If the theorem route permits ideal replacement instead of extraction, the
simulator programs an ideal replacement record for an accepted corrupted
contribution. The replacement must be indistinguishable at the public interface,
must preserve declared leakage, and must bind to the same transcript, session,
epoch, active set, validator, challenge, DKG, commitment, backend, and relation
context as the real accepted contribution.

Replacement failure, leakage mismatch, or public-view mismatch is charged to
`eps_contrib_replace`, `eps_contrib_leak`, or `eps_contrib_sim` as applicable.
This draft does not prove that replacement is available for any concrete
backend.

## C4-9. Rejection Path and Abort Path
<a id="c4-rejection-abort-paths"></a>

For rejected contributions, the simulator emits the same public rejection shape
as the real experiment: epoch, session, attempt, validator, statement digest,
and public reason. Rejection labels must be deterministic functions of the
declared public context or otherwise accounted for by the reduction.

For aborts, the simulator emits only declared abort labels and public
scheduling-visible metadata. Selective abort, abort timing, and abort-label
mismatches are charged to `eps_contrib_abort`; transcript or session mismatch
in abort records is also charged to `eps_contrib_bind`.

## C4-10. Transcript, Session, and Epoch Binding
<a id="c4-transcript-session-epoch-binding"></a>

Every accepted, rejected, replaced, leaked, or aborted contribution record must
bind to:

```text
(
  protocol_version,
  statement_schema,
  epoch_id,
  session_id,
  block_height,
  attempt,
  validator_index,
  validator_identity,
  threshold,
  total_nodes,
  active_set_digest,
  public_key_digest,
  parameter_set_digest,
  mu,
  challenge,
  dkg_commitment_digest,
  masking_commitment_digest,
  secret_commitment_digest,
  contribution_commitment_digest,
  contribution_encoding,
  backend_family,
  backend_id,
  backend_version,
  relation_id,
  domain_separator
)
```

Cross-epoch replay, cross-session replay, attempt reuse, validator rebinding,
active-set rebinding, challenge rebinding, backend rebinding, relation
rebinding, transcript forking, and non-canonical statement aliases are charged
to `eps_contrib_bind`.

## C4-10A. Rust Boundary Crosswalk
<a id="c4-rust-boundary-crosswalk"></a>

The current Rust boundary gives proof authors stable names for the future
backend replacement route. These names are traceability anchors only; they do
not prove the concrete backend realizes `F_CONTRIB`.

| Proof object | Rust boundary |
| --- | --- |
| Contribution statement grammar | `ProductionContributionStatement` |
| Scaffold-to-production statement construction | `production_contribution_statement_from_scaffold` |
| Statement digest binding | `production_contribution_statement_digest_from_scaffold` |
| Required production profile | `ContributionProofSecurityProfile::ProductionProofRelation` |
| Blocked candidate profile | `ContributionProofSecurityProfile::ProductionCandidateScaffold` |
| Current scaffold backend | `TranscriptHashContributionProofBackend` |
| Combined fail-closed gate | `require_production_threshold_backends` |

These anchors support the `eps_contrib_bind`, `eps_contrib_extract`, and
`eps_contrib_leak` accounting routes, but implementation evidence is not
cryptographic proof.

## C4-10B. Batch G Code-Evidence Anchors
<a id="c4-batch-g-code-evidence-anchors"></a>

Batch G adds code-evidence anchors for the production-target contribution
statement layout and actor-derived context labels. These are implementation
traceability anchors for reviewers; they are not a production proof and do not
establish the simulator theorem.

| Evidence target | Rust anchor |
| --- | --- |
| Canonical C4 binding tuple layout regression | `production_contribution_statement_canonical_layout_matches_c4_binding_tuple` |
| Hazmat scaffold context and payload binding regression | `hazmat_scaffold_to_production_statement_binds_source_context_and_payload` |
| Production statement byte length | `PRODUCTION_CONTRIBUTION_STATEMENT_BYTES` |
| Production statement schema version | `PRODUCTION_CONTRIBUTION_STATEMENT_SCHEMA_VERSION` |
| Production statement digest domain | `PRODUCTION_CONTRIBUTION_STATEMENT_DOMAIN` |
| Scaffold contribution proof digest domain | `CONTRIBUTION_PROOF_DOMAIN` |
| Actor production context root domain | `PRODUCTION_CONTEXT_DOMAIN` |
| Epoch context label | `PRODUCTION_EPOCH_LABEL` |
| Validator-set context label | `PRODUCTION_VALIDATOR_SET_LABEL` |
| Public-key context label | `PRODUCTION_PUBLIC_KEY_LABEL` |
| Parameter-set context label | `PRODUCTION_PARAMETER_SET_LABEL` |
| Raw contribution payload binding label | `PRODUCTION_CONTRIBUTION_PAYLOAD_LABEL` |
| Hazmat ML-DSA-65 parameter-set identifier | `PRODUCTION_CONTRIBUTION_PARAMETER_SET_ID` |

These names show that the current code has stable byte and domain boundaries
for the future `F_CONTRIB` realization route. Implementation evidence is not
cryptographic proof, this is not a production proof, and no concrete backend
selected means `eps_contrib_realize` remains open.

## C4-11. Hybrid Sequence
<a id="c4-hybrid-sequence"></a>

- `C4-H0`: real experiment `RealContrib(A,Z)` with the concrete contribution
  backend and real public transcript view.
- `C4-H1`: replace real transcript bookkeeping with canonical transcript,
  session, and epoch binding checks; differences are charged to
  `eps_contrib_bind`.
- `C4-H2`: align concrete backend leakage with declared `L_contrib`;
  differences are charged to `eps_contrib_leak`.
- `C4-H3`: replace accepted corrupted contributions through extraction when
  available; failures are charged to `eps_contrib_extract`.
- `C4-H4`: replace remaining permitted accepted corrupted contributions through
  ideal replacement; failures are charged to `eps_contrib_replace` and
  `eps_contrib_sim`.
- `C4-H5`: replace real rejection and abort handling with ideal
  `F_CONTRIB` rejection and abort records; differences are charged to
  `eps_contrib_abort`, `eps_contrib_bind`, and `eps_contrib_sim`.

At `C4-H5`, the target public view is the ideal experiment
`IdealContrib(S,Z)` with `F_CONTRIB`, subject to all residual terms remaining
visible.

## C4-12. Theorem Target and Residual Terms
<a id="c4-theorem-target-residual-terms"></a>
<a id="theorem-c4-f-contrib-realization-simulator"></a>

Theorem C4-f-contrib-realization-simulator. For every PPT adversary `A`,
environment `Z`, accepted epoch context, session context, active set, static
corruption set allowed by the surrounding theorem, canonical contribution
statement grammar, and candidate concrete contribution backend, there exists a
simulator `S` such that:

```text
| Pr[RealContrib(A,Z) => 1] - Pr[IdealContrib(S,Z) => 1] |
  <= eps_contrib_realize(A,Z)
   + eps_contrib_extract(A,Z)
   + eps_contrib_replace(A,Z)
   + eps_contrib_leak(A,Z)
   + eps_contrib_abort(A,Z)
   + eps_contrib_bind(A,Z)
   + eps_contrib_sim(A,Z)
   + eps_contrib(A,Z)
```

where:

- `eps_contrib_realize` accounts for the unproved concrete realization
  obligation for the selected backend.
- `eps_contrib_extract` accounts for extraction failure, extractor ambiguity,
  or missing knowledge-soundness support.
- `eps_contrib_replace` accounts for ideal replacement failure or a missing
  replacement theorem.
- `eps_contrib_leak` accounts for leakage outside `L_contrib` or mismatched
  leakage simulation.
- `eps_contrib_abort` accounts for abort-label, timing, scheduling, and
  selective-abort mismatch.
- `eps_contrib_bind` accounts for transcript, session, epoch, active-set,
  validator, challenge, DKG, commitment, backend, relation, and canonical
  encoding binding failures.
- `eps_contrib_sim` accounts for simulator public-view indistinguishability
  gaps not captured by the specialized terms above.
- `eps_contrib` is the aggregate contribution residual retained by downstream
  theorem statements until a concrete realization and composition proof are
  supplied.

This theorem target is not established by this document.

## C4-13. Non-Claims
<a id="c4-non-claims"></a>

This document makes these non-claims:

- no concrete backend selected;
- no simulator indistinguishability proof;
- no production contribution soundness proof;
- no zero/negligible claim;
- implementation evidence is not cryptographic proof.

## C4-14. Manifest Anchors
<a id="c4-manifest-anchors"></a>

- `# F_CONTRIB Real/Ideal Simulator Draft`
- `f-contrib-realization-simulator`
- `Status: Batch E formal-reduction draft, not a completed realization proof.`
- `Theorem C4-f-contrib-realization-simulator`
- `theorem-c4-f-contrib-realization-simulator`
- `real experiment`
- `ideal experiment`
- `simulator state`
- `simulator inputs`
- `simulator outputs`
- `leakage alignment`
- `extraction path`
- `ideal replacement path`
- `rejection path`
- `abort path`
- `transcript/session/epoch binding`
- `c4-rust-boundary-crosswalk`
- `c4-batch-g-code-evidence-anchors`
- `C4-H0`
- `C4-H1`
- `C4-H2`
- `C4-H3`
- `C4-H4`
- `C4-H5`
- `eps_contrib_realize`
- `eps_contrib_extract`
- `eps_contrib_replace`
- `eps_contrib_leak`
- `eps_contrib_abort`
- `eps_contrib_bind`
- `eps_contrib_sim`
- `eps_contrib`
- `ProductionContributionStatement`
- `production_contribution_statement_from_scaffold`
- `production_contribution_statement_digest_from_scaffold`
- `production_contribution_statement_canonical_layout_matches_c4_binding_tuple`
- `hazmat_scaffold_to_production_statement_binds_source_context_and_payload`
- `PRODUCTION_CONTRIBUTION_STATEMENT_BYTES`
- `PRODUCTION_CONTRIBUTION_STATEMENT_SCHEMA_VERSION`
- `PRODUCTION_CONTRIBUTION_STATEMENT_DOMAIN`
- `CONTRIBUTION_PROOF_DOMAIN`
- `PRODUCTION_CONTEXT_DOMAIN`
- `PRODUCTION_EPOCH_LABEL`
- `PRODUCTION_VALIDATOR_SET_LABEL`
- `PRODUCTION_PUBLIC_KEY_LABEL`
- `PRODUCTION_PARAMETER_SET_LABEL`
- `PRODUCTION_CONTRIBUTION_PAYLOAD_LABEL`
- `PRODUCTION_CONTRIBUTION_PARAMETER_SET_ID`
- `ContributionProofSecurityProfile::ProductionProofRelation`
- `ContributionProofSecurityProfile::ProductionCandidateScaffold`
- `TranscriptHashContributionProofBackend`
- `require_production_threshold_backends`
- `not a production proof`
