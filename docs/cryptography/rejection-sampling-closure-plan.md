# Rejection-Sampling Closure Plan
<a id="rejection-sampling-closure-plan"></a>

Date: 2026-05-28

Status: closure plan for rejection-sampling terms, not a completed
distribution proof.

## Scope and Non-Claim
<a id="rscp-scope-non-claim"></a>

This plan coordinates the proof routes for `eps_mask`, `eps_rej`,
`eps_withhold`, and `eps_verify`. It does not prove that accepted threshold
signatures are distributed as centralized ML-DSA-65 signatures, and it does not
prove production liveness or selective-abort resistance.

The current hazmat tests are implementation evidence for selected arithmetic
and verification paths. They are not a distributional theorem.

The theorem-closure batch that assembles these routes into a single
accepted-distribution target is
[rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md).

## Dependency DAG
<a id="rscp-dependency-dag"></a>

```text
CombineMask selection
  -> eps_mask closure
  -> H2 shared-mask hybrid
  -> eps_rej same-candidate predicate closure
  -> eps_verify standard-verifier compatibility decision
  -> eps_withhold accepted-distribution conditioning
  -> Delta_accept theorem
```

Commitment and random-oracle terms are prerequisites for this DAG because the
challenge must be bound to a fixed commitment set before rejection conditioning
is analyzed.

## Term Closure Requirements
<a id="rscp-term-closure-requirements"></a>

| Term | Closure requirement | Source route |
| --- | --- | --- |
| `eps_mask` | Select `CombineMask` and prove exact centralized mask distribution or a quantified `eps_mask_bound`. | [mask-distribution-equivalence.md](mask-distribution-equivalence.md) |
| `eps_rej` | Prove aggregate and centralized rejection predicates match on the same candidate values, including strictness, encodings, hints, challenge, active set, and malformed inputs. | [rejection-predicate-equivalence.md](rejection-predicate-equivalence.md) |
| `eps_withhold` | Prove retry, timeout, exclusion, abort-label, release, and evidence behavior are simulatable or explicitly bounded. | [withholding-abort-bound.md](withholding-abort-bound.md) |
| `eps_verify` | Decide whether verifier compatibility is folded into `eps_rej` or remains a separate theorem term; prove final bytes verify under unmodified ML-DSA-65. | [correctness-lemmas.md](correctness-lemmas.md) |

## Acceptance Criteria
<a id="rscp-acceptance-criteria"></a>

Before the rejection-sampling proof can be described as closed:

- `CombineMask` is fixed and parameter-specific for ML-DSA-65.
- The active signer set is identical across commitments, challenge,
  contribution validation, reconstruction, rejection checks, and final output.
- Retry contexts are injective and never reuse mask or challenge material.
- The aggregate rejection predicate is byte-level aligned with FIPS 204
  ML-DSA-65 verification behavior.
- Selective aborts are either denial-of-service only or charged to a proved
  bound with a fixed retry and timeout policy.
- `Delta_accept` is stated with all residual terms visible.

## Non-Claims
<a id="rscp-non-claims"></a>

This plan does not claim:

- `eps_mask = 0`.
- `eps_rej = 0`.
- `eps_withhold` is negligible.
- `eps_verify` has been absorbed into `eps_rej`.
- Current simulations prove production liveness or accepted-signature
  distribution preservation.

## Manifest Anchors

- `# Rejection-Sampling Closure Plan`
- `rejection-sampling-closure-plan`
- `rejection-sampling-theorem-closure.md`
- `rscp-dependency-dag`
- `rscp-term-closure-requirements`
- `eps_mask`
- `eps_rej`
- `eps_withhold`
- `eps_verify`
- `Delta_accept`
- `rscp-acceptance-criteria`
- `rscp-non-claims`
