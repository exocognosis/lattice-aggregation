# Random-Oracle and Commitment Closure Plan
<a id="random-oracle-commitment-closure"></a>

Date: 2026-05-28

Status: closure plan for `eps_ro` and `eps_commit`, not a completed ROM proof.

## Scope and Non-Claim
<a id="rocc-scope-non-claim"></a>

This plan defines the proof work needed to close the random-oracle and
commitment terms used by the signing theorem, rejection-sampling route, and
classifier route. It does not prove domain separation, commitment binding,
commitment hiding, or random-oracle programming soundness.

## Random-Oracle Closure
<a id="rocc-random-oracle-closure"></a>

The production proof must account for:

- `H_mu`: message and key-context binding.
- `H_w`: commitment and public masking statement binding.
- `H_c`: signing challenge after the commitment set is fixed.
- `H_vss`: VSS/DKG proof or setup-statement challenge.
- `H_contrib`: contribution-proof challenge.

Required theorem:

```text
eps_ro
  <= eps_ro_injective_encoding
   + eps_ro_domain_separation
   + eps_ro_prior_query
   + eps_ro_replay
   + eps_ro_programming
```

## Commitment Closure
<a id="rocc-commitment-closure"></a>

The commitment proof must establish:

```text
eps_commit
  <= eps_commit_bind
   + eps_commit_hide
   + eps_commit_equivocate
   + eps_commit_open_set
   + eps_commit_context
```

The committed set used by `H_c` must equal the opened and verified set used by
contribution validation and aggregation. Any mismatch must be rejected or
charged to a visible term.

## Cross-Term Dependencies
<a id="rocc-cross-term-dependencies"></a>

`eps_ro` and `eps_commit` feed into:

- `eps_mask`, because corrupt masking contributions must be fixed before the
  challenge.
- `eps_rej`, because same-candidate comparison assumes one challenge and one
  ordered commitment set.
- `eps_contrib`, because contribution proofs bind to the same challenge and
  transcript.
- `eps_classify`, because unauthorized outputs must be classified against
  injective transcript fields.

## Acceptance Criteria
<a id="rocc-acceptance-criteria"></a>

Before these terms can be treated as closed:

- Every random-oracle input has a byte-level injective encoding proof.
- Domain labels are prefix-free and versioned.
- Prior-query losses are parameterized by sessions, attempts, validators,
  evidence records, and oracle queries.
- The commitment backend is selected or idealized.
- Binding, hiding, opening-set equality, and context-binding theorems are
  stated with concrete assumptions.
- Tests remain framed as encoding and regression evidence only.

## Non-Claims
<a id="rocc-non-claims"></a>

This plan does not claim `eps_ro` or `eps_commit` is negligible, zero, or
bounded. It does not claim SHAKE256 domain labels alone justify independent
random oracles, and it does not claim the current scaffold commitments are a
production binding/hiding scheme.

## Manifest Anchors

- `# Random-Oracle and Commitment Closure Plan`
- `random-oracle-commitment-closure`
- `rocc-random-oracle-closure`
- `eps_ro_injective_encoding`
- `eps_ro_domain_separation`
- `eps_ro_prior_query`
- `eps_ro_programming`
- `rocc-commitment-closure`
- `eps_commit_bind`
- `eps_commit_hide`
- `eps_commit_open_set`
- `rocc-cross-term-dependencies`
- `rocc-acceptance-criteria`
- `rocc-non-claims`

