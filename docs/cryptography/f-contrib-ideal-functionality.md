# F_CONTRIB Ideal Functionality
<a id="f-contrib-ideal-functionality"></a>

Stable anchor: `f-contrib-ideal-functionality`

Status: Batch D ideal-functionality specification, not a production backend proof.

Ideal functionality name: `F_CONTRIB`

Theorem target name: `Theorem C3-ideal-contribution-realization-boundary`

## C3-0. Scope
<a id="c3-scope"></a>

`F_CONTRIB` is the immediate ideal contribution-validity functionality used by
the theorem route to isolate signing-side reasoning from an unselected concrete
contribution backend. It specifies the public interface, simulator hooks,
leakage, rejection, extraction or replacement, transcript binding, session and
epoch binding, and abort behavior needed by downstream theorem text.

Immediate theorem work may rely on `F_CONTRIB` as an ideal boundary. Production
security still requires a concrete proof-system, MPC, interactive, or other
reviewed backend that realizes this functionality for the declared leakage and
residual accounting.

## C3-1. Parties and Roles
<a id="c3-parties-roles"></a>

The functionality interacts with:

- validators `P_i`, identified by canonical `validator_index` and validator
  identity in the active set;
- an aggregator or collector `Agg`, which submits contribution frames for
  acceptance and receives accepted public contribution handles;
- an environment `Z`, which creates epochs, sessions, signing attempts, and
  adversarial scheduling pressure;
- an adversary `A` in the real execution, or simulator `S` in the ideal
  execution;
- downstream signing, aggregation, rejection, evidence, and classifier
  components that consume public accept/reject decisions and failure labels.

The active corruption set is fixed by the surrounding theorem statement.
`F_CONTRIB` does not authorize threshold signing by itself and does not replace
the DKG/VSS, collection, rejection, or unauthorized-output classifier
functionalities.

## C3-2. Inputs
<a id="c3-inputs"></a>

For each contribution attempt, `F_CONTRIB` receives a typed public statement:

```text
S_contrib_i = (
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

For honest validators, `F_CONTRIB` also receives either a private witness
`W_contrib_i` or a trusted ideal witness handle sufficient to decide the
relation `R_contrib(S_contrib_i, W_contrib_i)`.

For adversarial validators, the simulator receives accepted public statements
and either extracts a context-bound witness or programs an ideal replacement
record as specified in `C3-6`.

## C3-3. Outputs
<a id="c3-outputs"></a>

On acceptance, `F_CONTRIB` returns:

```text
(ContribAccepted, epoch_id, session_id, attempt, validator_index,
 contribution_handle, contribution_encoding, public_acceptance_record)
```

The accepted handle is relation-valid by definition inside the ideal model and
is bound to exactly one epoch, session, attempt, validator, active set,
challenge, DKG digest, contribution encoding, backend declaration, and
transcript context.

On rejection, `F_CONTRIB` returns:

```text
(ContribRejected, epoch_id, session_id, attempt, validator_index, reason)
```

Only public contribution encodings, public acceptance records, declared leakage,
and labeled failure reasons may leave the functionality. Honest witnesses,
shares, masks, commitment openings, proof randomness, and rejected-attempt
internals remain hidden except as declared by `L_contrib`.

## C3-4. Leakage Interface
<a id="c3-leakage-interface"></a>

The declared leakage function is:

```text
L_contrib(S_contrib_i) = (
  epoch_id,
  session_id,
  attempt,
  validator_index,
  active_set_digest,
  public_key_digest,
  parameter_set_digest,
  mu,
  challenge,
  backend_family,
  backend_id,
  backend_version,
  relation_id,
  public_accept_or_reject_bit,
  public_failure_label,
  contribution_encoding_length,
  public_timing_bucket
)
```

No theorem may treat undeclared leakage as free. If a future realization leaks
message counts, timing, abort labels, malformed-frame classes, proof sizes, or
other public metadata beyond this list, the theorem must extend
`L_contrib` and charge the mismatch to `eps_contrib_leak`.

`F_CONTRIB` never leaks honest shares, DKG private shares, masking randomness,
commitment openings, witness state, proof randomness, `c*s1`, `c*s2`, `c*t0`,
or secret-dependent partial terms except through an explicitly declared leakage
extension.

## C3-5. Rejection Interface
<a id="c3-rejection-interface"></a>

`F_CONTRIB` rejects malformed, stale, replayed, forked, cross-context, or
unsupported contribution attempts. Rejection reasons are public labels chosen
from:

```text
MalformedStatement
UnsupportedSchema
UnsupportedBackend
WrongEpoch
WrongSession
WrongAttempt
WrongValidator
WrongActiveSet
WrongChallenge
WrongDkgDigest
WrongCommitmentDigest
WrongContributionEncoding
RelationInvalid
LeakageMismatch
ExtractionUnavailable
ReplacementUnavailable
AbortBeforeAcceptance
```

Rejected statements do not produce contribution handles. Rejection labels may
be routed to evidence and classifier logic, but rejected witness internals do
not leave the functionality.

## C3-6. Extraction and Replacement Interface
<a id="c3-extraction-replacement-interface"></a>

For each accepted adversarial contribution, the simulator receives one of:

```text
(ExtractedWitness, S_contrib_i, W_contrib_i, extraction_context)
```

where `R_contrib(S_contrib_i, W_contrib_i) = 1`, or:

```text
(IdealReplacement, S_contrib_i, replacement_handle,
 contribution_encoding, replacement_context)
```

where the replacement handle is relation-valid for the same public statement,
encoding, leakage, epoch, session, attempt, validator, active set, challenge,
and transcript binding.

The simulator may program or replace:

- honest contribution frames, as long as their public distribution is
  indistinguishable under the ideal leakage interface;
- accepted adversarial contribution handles, when extraction is unavailable but
  an ideal replacement record with the same public encoding and leakage is
  provided;
- public rejection labels for malformed or cross-context attempts, limited to
  labels allowed by `C3-5`; and
- abort scheduling labels allowed by `C3-9`.

The simulator may not program honest secrets, alter public transcript fields
after acceptance, replace one validator's accepted contribution with another
validator's context, or introduce leakage outside `L_contrib`.

## C3-7. Transcript Binding
<a id="c3-transcript-binding"></a>

Acceptance is defined only for the canonical transcript-bound statement:

```text
ContribTranscript_i = Enc(
  "F_CONTRIB",
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

`F_CONTRIB` rejects non-canonical encodings, duplicated encodings with
conflicting context, backend-family mismatches, relation mismatches, and any
attempt to reuse an accepted contribution in a different transcript context.
Transcript binding failures are charged to `eps_contrib_bind`.

## C3-8. Session and Epoch Binding
<a id="c3-session-epoch-binding"></a>

Every accepted contribution is bound to one tuple:

```text
(epoch_id, session_id, block_height, attempt, validator_index,
 active_set_digest, public_key_digest, parameter_set_digest, mu, challenge)
```

`F_CONTRIB` rejects statements that cross epochs, reuse session identifiers
with inconsistent context, change active sets after acceptance, mix challenge
records, or rely on stale DKG/VSS commitments. The functionality does not infer
missing context from local state; all accepted context must appear in
`S_contrib_i` and in the transcript binding.

## C3-9. Abort Semantics
<a id="c3-abort-semantics"></a>

Before acceptance, the adversary or scheduler may cause:

```text
(ContribAborted, epoch_id, session_id, attempt, validator_index, abort_label)
```

with no accepted contribution handle. After acceptance, abort does not erase
the public acceptance record or allow the simulator to remap the contribution
to another context. Abort labels are leakage and must be included in
`L_contrib` or charged to `eps_contrib_abort`.

Selective abort effects that influence signing completion, evidence routing,
or unauthorized-output classification remain charged to their surrounding
residuals unless a future concrete realization proves they are covered by the
contribution backend theorem.

## C3-10. Theorem Target and Residual Terms
<a id="c3-theorem-target-residual-terms"></a>
<a id="theorem-c3-ideal-contribution-realization-boundary"></a>

Theorem C3-ideal-contribution-realization-boundary. For every PPT adversary
`A`, environment `Z`, accepted epoch context, session context, active set,
static corruption set allowed by the surrounding signing theorem, and
canonical contribution statement grammar, replacing the concrete contribution
checking step with ideal `F_CONTRIB` changes the theorem experiment by at most:

```text
eps_contrib(A,Z)
  <= eps_contrib_ideal(A,Z)
   + eps_contrib_realize(A,Z)
   + eps_contrib_extract(A,Z)
   + eps_contrib_leak(A,Z)
   + eps_contrib_abort(A,Z)
   + eps_contrib_bind(A,Z)
```

where:

- `eps_contrib_ideal` accounts for relying on the ideal functionality instead
  of a concrete backend theorem in immediate theorem work.
- `eps_contrib_realize` accounts for the future obligation to realize
  `F_CONTRIB` with a concrete backend before production claims.
- `eps_contrib_extract` accounts for extraction failure or ideal-replacement
  failure for accepted adversarial contributions.
- `eps_contrib_leak` accounts for leakage outside the declared
  `L_contrib` interface or mismatched leakage composition.
- `eps_contrib_abort` accounts for abort-label, scheduling, and selective-abort
  behavior not proved by the contribution functionality.
- `eps_contrib_bind` accounts for transcript, session, epoch, active-set,
  validator, challenge, DKG, commitment, backend, and relation-binding
  failures.
- `eps_contrib` is the aggregate contribution residual that remains visible
  until a concrete realization and composition proof are supplied.

This theorem target is a boundary statement for proof organization. It does
not prove that any current implementation realizes `F_CONTRIB`.

## C3-11. Production Realization Obligation
<a id="c3-production-realization-obligation"></a>

Immediate theorem documents may cite `F_CONTRIB` for idealized contribution
validity only if they keep `eps_contrib_ideal`, `eps_contrib_realize`, and
`eps_contrib` visible. Production security still requires a concrete backend
that specifies and proves:

- the exact relation `R_contrib`;
- statement and witness schemas;
- soundness or knowledge soundness for accepted corrupted frames;
- witness hiding, zero knowledge, MPC privacy, or an explicit leakage theorem;
- extraction or ideal replacement with the simulator interface above;
- transcript, session, epoch, active-set, validator, challenge, commitment,
  backend, and relation binding;
- abort and selective-abort composition; and
- independent review and integration with production policy.

## C3-12. Non-Claims
<a id="c3-non-claims"></a>

This document makes these non-claims:

- no concrete backend is selected;
- no production contribution soundness proof is supplied;
- no zero or negligible claim is made for any `eps_contrib` term;
- no zero-knowledge, MPC-privacy, witness-hiding, extraction, realization,
  leakage, abort, or binding theorem is proved for production;
- implementation evidence is not cryptographic proof;
- transcript-hash scaffold behavior is not a contribution proof; and
- `F_CONTRIB` is not a production backend.

## C3-13. Manifest Anchors
<a id="c3-manifest-anchors"></a>

- `# F_CONTRIB Ideal Functionality`
- `f-contrib-ideal-functionality`
- `Status: Batch D ideal-functionality specification, not a production backend proof.`
- `F_CONTRIB`
- `Theorem C3-ideal-contribution-realization-boundary`
- `theorem-c3-ideal-contribution-realization-boundary`
- `parties and roles`
- `inputs`
- `outputs`
- `leakage interface`
- `rejection interface`
- `extraction and replacement interface`
- `transcript binding`
- `session and epoch binding`
- `abort semantics`
- `eps_contrib_ideal`
- `eps_contrib_realize`
- `eps_contrib_extract`
- `eps_contrib_leak`
- `eps_contrib_abort`
- `eps_contrib_bind`
- `eps_contrib`
- `no concrete backend is selected`
- `no production contribution soundness proof`
- `no zero or negligible claim`
- `implementation evidence is not cryptographic proof`
