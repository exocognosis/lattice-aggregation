# eps_withhold Simulator Obligation Route
<a id="eps-withhold-simulator-obligation-route"></a>

Status: simulator-obligation roadmap for eps_withhold, not a completed
selective-abort proof.

This document records the Residual Closure Batch A simulator obligations for
withholding, retry, timeout, abort-label, evidence, release, and admitted timing
observables. It is a proof roadmap. It does not prove that the listed residuals
are negligible, zero, or production-ready.

## WSO-0. Scope
<a id="wso-scope"></a>

The route refines the `eps_withhold` closure batch by making the simulator
interface explicit. It assumes the surrounding theorem route has already fixed
the static-active model, commitment domains, rejection predicate, mask
freshness, and typed challenge domains.

The roadmap separates two effects:

- denial-of-service and liveness failure, where the adversary prevents a
  completed accepted signature or exhausts retries; and
- accepted-distribution bias, where the conditional distribution of accepted
  signatures changes after accounting for allowed observables.

Only the second effect belongs in an accepted-distribution theorem. The first
may be modeled, logged, or charged to availability assumptions, but it is not a
selective-abort distribution bound by itself.

## WSO-1. Theorem-Level Objects
<a id="wso-theorem-level-objects"></a>

The theorem target must define these objects before claiming any simulator
bound.

`O_abort` is the abort-observable grammar exposed to the environment and the
adversary. It includes only theorem-admitted labels, retry identifiers,
timeout/exclusion records, malformed-evidence classes, release records, final
accept/reject status, and admitted timing or size buckets. Any observable not
listed in `O_abort` remains outside the simulator contract or must be charged
to a visible residual.

`R_max` is the maximum number of attempts in one signing context. It fixes the
retry horizon, the retry-limit exhaustion event, and the set of attempt indices
the simulator must be able to sample.

`P_timeout` is the timeout and signer-exclusion policy. It defines when a
commitment or contribution is missing, how late messages are handled, how long
excluded signers remain excluded, and how timeout evidence is encoded.

Signer exclusion is the rule by which `P_timeout` removes or suppresses a
participant for an attempt, block, epoch, or other fixed scope. The theorem must
state whether signer exclusion affects only liveness or can condition the set
of accepted transcripts.

A retry transcript is the sequence of attempt-indexed public records:

```text
(session_id, attempt, active_set, O_abort_attempt, challenge_domain_attempt,
 final_status_attempt)
```

It must bind retry freshness, active signer set, timeout/exclusion decisions,
and final success or retry-limit exhaustion without exposing rejected honest
candidate internals.

Release/evidence observables are the theorem-admitted records for published
aggregate releases, partial releases, blame evidence, malformed contribution
evidence, timeout evidence, and slashability metadata. They must be classified
inside `O_abort` or charged to `eps_evid` and `eps_release`.

## WSO-2. Simulator Target
<a id="wso-simulator-target"></a>

The theorem target is:

```text
Theorem W1-withholding-simulator-obligation.
For the fixed static-active model, retry bound R_max, timeout/exclusion policy
P_timeout, abort-observable grammar O_abort, signer-exclusion rule, retry
transcript grammar, and release/evidence observable grammar, there exists a
simulator Sim_W1 that samples the admitted abort-visible transcript from public
inputs, corrupted-party inputs, allowed O_abort leakage, and final accept/reject
status, without using honest secret shares, honest mask seeds, or rejected
honest candidate internals.
```

The theorem is an obligation target only. It is not proved by this document.

## WSO-3. Residual Decomposition
<a id="wso-residual-decomposition"></a>

The simulator proof route must keep the residual terms visible:

```text
eps_withhold
 <= eps_withhold_commit
  + eps_withhold_challenge
  + eps_abort_labels
  + eps_retry_limit
  + eps_timeout_policy
  + eps_evid
  + eps_release
  + eps_timing_boundary.
```

Meanings:

- `eps_withhold_commit`: bias from prechallenge withholding after seeing honest
  commitments or commitment metadata.
- `eps_withhold_challenge`: bias from postchallenge withholding after seeing
  the challenge or challenge-dependent contribution requirements.
- `eps_abort_labels`: leakage through participant-specific abort labels,
  local rejection labels, malformed-message classes, or blame labels.
- `eps_retry_limit`: bias from bounded retries, retry freshness failures, or
  retry-limit exhaustion conditioning.
- `eps_timeout_policy`: bias induced by timeout thresholds, late-message
  handling, or signer exclusion.
- `eps_evid`: noninterference gap for evidence records.
- `eps_release`: noninterference gap for release records.
- `eps_timing_boundary`: gap for timing, scheduling, message-size, or boundary
  observables admitted by the model but not discharged elsewhere.

No subterm is claimed negligible or zero here.

## WSO-4. Simulator Obligations
<a id="wso-simulator-obligations"></a>

The simulator route must establish:

- prechallenge commitments are sampled before challenge-dependent choices and
  do not encode honest mask seeds;
- postchallenge withholding is represented only through `O_abort` or charged to
  `eps_withhold_challenge`;
- retry attempts use injective domains and fresh honest randomness per attempt;
- retry-limit exhaustion is modeled as a liveness/availability event unless it
  conditions accepted transcripts;
- timeout and signer-exclusion records follow `P_timeout` and do not leak
  rejected honest candidate internals;
- evidence and release records reveal no honest masks, secret shares, proof
  witnesses, proof randomness, or rejected honest candidates beyond admitted
  release/evidence observables;
- timing and scheduling observables are either bucketed in `O_abort` or charged
  to `eps_timing_boundary`.

## WSO-5. Acceptance Criteria
<a id="wso-acceptance-criteria"></a>

This roadmap is acceptable only if later proof work:

- fixes `O_abort`, `R_max`, `P_timeout`, signer exclusion, retry transcript,
  and release/evidence observables as theorem-level objects;
- states the exact inputs and forbidden inputs for `Sim_W1`;
- preserves the decomposition into all visible residual subterms;
- separates DoS/liveness failure from accepted-distribution bias;
- records which observables are simulated, which are excluded from the theorem,
  and which are charged to residual terms;
- gives an explicit acceptance-probability or conditioning argument before any
  selective-abort advantage bound is claimed.

## WSO-6. Non-Claims
<a id="wso-non-claims"></a>

This document does not claim:

- a selective-abort bound is proved;
- any residual is negligible;
- any residual is zero;
- production liveness is proved;
- the route is production-ready;
- implementation evidence is cryptographic proof;
- actor simulation, fuzzing, or telemetry evidence discharges the simulator
  obligations.

Implementation evidence is not cryptographic proof.
No selective-abort bound is proved, no negligible/zero claim is made, and this
route is not production-ready.

## Manifest Anchors
<a id="wso-manifest-anchors"></a>

Stable anchors and text markers:

- `# eps_withhold Simulator Obligation Route`
- `eps-withhold-simulator-obligation-route`
- `Status: simulator-obligation roadmap for eps_withhold`
- `WSO-0. Scope`
- `WSO-1. Theorem-Level Objects`
- `WSO-2. Simulator Target`
- `WSO-3. Residual Decomposition`
- `WSO-4. Simulator Obligations`
- `WSO-5. Acceptance Criteria`
- `WSO-6. Non-Claims`
- `Manifest Anchors`
- `Theorem W1-withholding-simulator-obligation`
- `O_abort`
- `R_max`
- `P_timeout`
- `signer exclusion`
- `retry transcript`
- `release/evidence observables`
- `eps_withhold_commit`
- `eps_withhold_challenge`
- `eps_abort_labels`
- `eps_retry_limit`
- `eps_timeout_policy`
- `eps_evid`
- `eps_release`
- `eps_timing_boundary`
- `no selective-abort bound is proved`
- `not production-ready`
- `implementation evidence is not cryptographic proof`
