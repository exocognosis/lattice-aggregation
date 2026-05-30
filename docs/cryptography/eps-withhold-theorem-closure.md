# eps_withhold Theorem Closure Batch
<a id="eps-withhold-theorem-closure"></a>

Status: theorem-closure batch for `eps_withhold`, not a completed
selective-abort proof.

This document refines the `RSTC-5` route from
[rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md).
It fixes the model objects needed before withholding, retry, timeout,
abort-label, evidence, and release behavior can be included in an
accepted-distribution theorem.

It does not prove network liveness, slashing soundness, selective-abort
security, or production readiness. Implementation evidence is not
cryptographic proof.

## EWTC-0. Scope and Non-Claim
<a id="ewtc-scope-non-claim"></a>

The route starts after `eps_mask` and `eps_rej` have been separated. It must
not be used to hide mask-distribution mismatch, rejection-predicate mismatch,
commitment failure, or random-oracle loss.

Denial of service and liveness are operational properties. They must be stated
separately from accepted-signature distribution preservation.

## EWTC-1. Model Selection
<a id="ewtc-model-selection"></a>

The first theorem route uses:

- static active corruption;
- authenticated context-bound messages;
- rushing inside each protocol round;
- bounded retries `R_max`;
- timeout/exclusion policy `P_timeout`;
- abort-observable set `O_abort`.

Adaptive corruption, erasures, side-channel timing models, and production
network liveness remain outside this batch.

## EWTC-2. O_abort Transcript Grammar
<a id="ewtc-o-abort-transcript-grammar"></a>

The theorem-level abort transcript must classify:

- missing commitments;
- missing mask openings or contribution messages;
- malformed contribution evidence;
- duplicate, stale, or wrong-session records;
- local abort labels if exposed;
- aggregate rejection;
- retry count and retry identifiers;
- timeout and signer-exclusion records;
- release records and final success;
- admitted timing and message-size classes.

Any observable outside `O_abort` must be excluded from the theorem or charged
to an explicit residual.

## EWTC-3. R_max and Retry Freshness
<a id="ewtc-rmax-retry-freshness"></a>

The proof must fix:

```text
R_max
rho_attempt = Enc(domain, session_id, block_height, attempt, active_set)
```

Required properties:

- every retry context is injective;
- honest masks and challenge inputs are fresh per attempt;
- bounded retries do not condition future accepted masks except through
  `eps_retry_limit`;
- retry-limit exhaustion is distinguished from accepted-distribution bias.

## EWTC-4. P_timeout and Signer Exclusion
<a id="ewtc-ptimeout-signer-exclusion"></a>

`P_timeout` must define:

- when a commitment or contribution is considered missing;
- whether late messages are ignored or included in a future attempt;
- whether a signer is excluded for one attempt, one block, or one epoch;
- how timeout evidence is encoded;
- whether timeout behavior is synchronous, partially synchronous, or a local
  aggregator policy.

Any timeout-induced distribution bias is charged to:

```text
eps_timeout_policy
```

## EWTC-5. Simulator Construction
<a id="ewtc-simulator-construction"></a>

The simulator `Sim` must produce:

```text
View_with_abort_labels
```

from public inputs, corrupted-party inputs, allowed abort leakage, and final
accept/reject status. It must not use honest secret shares, honest mask seeds,
or rejected honest candidate internals.

The simulator depends on:

- `eps_mask` freshness and high-bit coupling;
- `eps_rej` predicate consistency;
- `eps_commit` fixed prechallenge commitments;
- `eps_ro` typed challenge domains;
- `eps_evid` and `eps_release` noninterference if evidence and release
  records are exposed.

## EWTC-6. Withholding Case Analysis
<a id="ewtc-withholding-case-analysis"></a>

The proof must separate:

```text
eps_withhold_commit
eps_withhold_challenge
eps_abort_labels
eps_retry_limit
eps_timeout_policy
```

Cases:

- prechallenge withholding after observing honest commitments;
- postchallenge withholding after seeing `c`;
- malformed contribution submission;
- local honest rejection exposure;
- timeout-driven signer exclusion;
- retry-limit exhaustion.

Corrupted-party withholding is acceptable for the distribution theorem only if
it is denial of service or is charged to one of the displayed terms.

## EWTC-7. Evidence and Release Noninterference
<a id="ewtc-evidence-release-noninterference"></a>

Evidence and release records must not reveal honest masks, secret shares,
proof witnesses, proof randomness, or rejected honest candidates beyond
`O_abort`.

Residuals that must remain visible unless discharged:

```text
eps_evid
eps_release
eps_abort_labels
```

Slashing soundness is separate from accepted-distribution preservation.

## EWTC-8. Bound Statement
<a id="ewtc-bound-statement"></a>

Simulator obligations for this route are refined in
[eps-withhold-simulator-obligations.md](eps-withhold-simulator-obligations.md).

Target statement:

```text
Theorem W-close-static-active.
For the fixed model, retry limit R_max, timeout/exclusion policy P_timeout,
and abort transcript O_abort, there exists a simulator Sim such that

Delta(View_with_abort_labels, Sim(public inputs, O_abort))
  + Pr[withholding changes the conditioned accepted-signature distribution
       outside O_abort]
  <= eps_withhold_bound(lambda, R_max, O_abort, P_timeout).
```

Expanded form:

```text
eps_withhold
 <= eps_withhold_commit
  + eps_withhold_challenge
  + eps_abort_labels
  + eps_retry_limit
  + eps_timeout_policy
  + eps_evid
  + eps_release.
```

## EWTC-9. Residual Ledger
<a id="ewtc-residual-ledger"></a>

| Term | Meaning | Status |
| --- | --- | --- |
| `eps_withhold_commit` | Prechallenge withholding bias. | Open. |
| `eps_withhold_challenge` | Postchallenge withholding bias. | Open. |
| `eps_abort_labels` | Participant-specific abort/evidence label leakage. | Open. |
| `eps_retry_limit` | Bias from bounded retries and retry exhaustion. | Open. |
| `eps_timeout_policy` | Timeout/exclusion policy distribution loss. | Open. |
| `eps_evid` | Evidence-record noninterference. | Open. |
| `eps_release` | Release-record noninterference. | Open. |

No term is claimed negligible or zero in this document.

## EWTC-10. Acceptance Criteria
<a id="ewtc-acceptance-criteria"></a>

This batch is acceptable only if it:

- fixes `O_abort`, `R_max`, and `P_timeout` as theorem-level objects;
- keeps denial of service separate from distributional bias;
- states simulator inputs and forbidden simulator inputs;
- separates prechallenge and postchallenge withholding;
- preserves evidence/release noninterference terms;
- says implementation evidence is not cryptographic proof.

## EWTC-11. Non-Claims
<a id="ewtc-non-claims"></a>

This document does not claim:

- `eps_withhold` is negligible;
- production network liveness is proved;
- slashing soundness is proved;
- retry telemetry is private;
- participant-specific abort labels are harmless;
- accepted threshold signatures are distributed as centralized ML-DSA-65
  signatures;
- the repository is production-ready.

## EWTC-12. Manifest Anchors
<a id="ewtc-manifest-anchors"></a>

Stable anchors and text markers:

- `# eps_withhold Theorem Closure Batch`
- `eps-withhold-theorem-closure`
- `Status: theorem-closure batch for eps_withhold`
- `EWTC-0. Scope and Non-Claim`
- `EWTC-1. Model Selection`
- `EWTC-2. O_abort Transcript Grammar`
- `EWTC-3. R_max and Retry Freshness`
- `EWTC-4. P_timeout and Signer Exclusion`
- `EWTC-5. Simulator Construction`
- `EWTC-6. Withholding Case Analysis`
- `EWTC-7. Evidence and Release Noninterference`
- `EWTC-8. Bound Statement`
- `EWTC-9. Residual Ledger`
- `EWTC-10. Acceptance Criteria`
- `EWTC-11. Non-Claims`
- `EWTC-12. Manifest Anchors`
- `Theorem W-close-static-active`
- `eps-withhold-simulator-obligations.md`
- `eps-withhold-simulator-obligation-route`
- `eps_withhold_bound`
- `eps_withhold_commit`
- `eps_withhold_challenge`
- `eps_abort_labels`
- `eps_retry_limit`
- `eps_timeout_policy`
- `eps_evid`
- `eps_release`
- `O_abort`
- `R_max`
- `P_timeout`
- `implementation evidence is not cryptographic proof`
- `not a completed selective-abort proof`
- `not production-ready`
