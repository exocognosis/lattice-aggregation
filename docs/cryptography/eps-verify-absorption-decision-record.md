# eps_verify Absorption Decision Record
<a id="eps-verify-absorption-decision-record"></a>

Status: decision record and roadmap for verifier absorption accounting. This is
not a completed verifier compatibility proof, and it is not a final theorem
decision on whether `eps_verify` is absorbed into `eps_rej`.

## Scope
<a id="eps-verify-absorption-record-scope"></a>

This record fixes the Batch C decision target for whether the verifier residual
`eps_verify` can later fold into `eps_rej`, or whether it must remain a
separate residual term. The immediate route is conservative: carry
`eps_verify` separately until verifier compatibility and rejection-predicate
equivalence are both closed over the same byte-level candidate tuple.

## Candidate Paths
<a id="eps-verify-absorption-record-candidate-paths"></a>

Path A: absorb into `eps_rej`.

This path is available only if verifier compatibility is proved over the same
byte-level candidate tuple as rejection-predicate equivalence. The proof must
show that standard verifier acceptance, aggregate acceptance, and rejection
predicate evaluation all refer to the same `pk`, `M`, `mu`, `sigma`, challenge
bytes, high-bit reconstruction inputs, hint bytes, and malformed-encoding
boundary. Under this path, `eps_verify_reject_absorption` is discharged into
`eps_rej`, and no separate verifier term is charged for the same event.

Path B: carry separate `eps_verify`.

This path remains required while any verifier-specific obligation sits outside
the rejection theorem, including message `M` to `mu` binding, byte-level
`sigma` equality, standard challenge equality, highbits/hint equality,
malformed encoding agreement, or residual mismatch cases that cannot be mapped
to an `eps_rej` subterm without double-counting.

## Recommendation
<a id="eps-verify-absorption-record-recommendation"></a>

The conservative immediate route is Path B: keep `eps_verify` separate until
both theorem targets are closed over the same byte-level candidate tuple:

- `Theorem V1-standard-verifier-compatibility`
- `Theorem R1-reject-predicate-equivalence`

This recommendation does not claim final absorption. It prevents verifier
compatibility obligations from being hidden inside `eps_rej` before the byte
boundary, message boundary, and malformed-input boundary are proved identical.

Decision target:

```text
Decision V2-carry-eps-verify-until-byte-proof
```

The target decision is to carry `eps_verify` until a later proof demonstrates
that Path A accounts for the exact same verifier mismatch events without
omission or double-counting.

## Closure Criteria
<a id="eps-verify-absorption-record-closure-criteria"></a>

Absorption into `eps_rej` may be considered only after a closure document proves
all of the following over the same byte-level candidate tuple:

- byte-level `sigma` equality between aggregate emission and standard verifier
  input;
- challenge equality, including challenge bytes, hash inputs, domain
  separation, and deterministic expansion;
- highbits/hint equality, including reconstruction, hint count, hint ordering,
  and malformed-hint rejection;
- message `M` to `mu` binding under the same public key, context, pre-hash, and
  domain-separation rules consumed by the standard verifier;
- malformed encoding agreement, so aggregate acceptance and standard
  verification reject the same malformed byte strings at the same boundary;
- no double-counting, so every verifier mismatch event is assigned exactly once
  to either `eps_rej` or a visible `eps_verify` subterm.

## Residual Accounting Impact
<a id="eps-verify-absorption-record-residual-accounting-impact"></a>

Until `Decision V2-carry-eps-verify-until-byte-proof` is superseded by a later
closure decision, residual accounting should treat:

- `eps_verify_mismatch` as the catch-all verifier disagreement term for
  aggregate-accepts/verifier-rejects or verifier-accepts/aggregate-rejects
  cases not assigned to a narrower verifier subterm;
- `eps_verify_reject_absorption` as the candidate portion that may later fold
  into `eps_rej`, but only after `Theorem V1-standard-verifier-compatibility`
  and `Theorem R1-reject-predicate-equivalence` close over the same byte-level
  tuple;
- `eps_rej` as the rejection-predicate residual, not a substitute for verifier
  compatibility until byte equality, message binding, hint/highbit agreement,
  malformed encoding agreement, and no-double-counting are all proved.

If Path A is later proved, the closure must show which verifier events move from
`eps_verify_reject_absorption` into `eps_rej` and why `eps_verify_mismatch`
does not retain any unaccounted event. If Path B remains, the final bound must
carry `eps_verify` visibly with its surviving subterms.

## Acceptance Criteria
<a id="eps-verify-absorption-record-acceptance-criteria"></a>

This decision record is acceptable when it:

- states that verifier absorption is a roadmap decision, not a completed proof;
- compares Path A, absorb into `eps_rej`, against Path B, carry separate
  `eps_verify`;
- recommends carrying `eps_verify` until `Theorem V1-standard-verifier-compatibility`
  and `Theorem R1-reject-predicate-equivalence` close over the same byte-level
  candidate tuple;
- names `Decision V2-carry-eps-verify-until-byte-proof`;
- records the required criteria for byte-level `sigma` equality, challenge
  equality, highbits/hint equality, message `M` to `mu` binding, malformed
  encoding agreement, and no double-counting;
- describes residual impact on `eps_verify_mismatch`,
  `eps_verify_reject_absorption`, and `eps_rej`;
- preserves the non-claims listed below.

## Non-Claims
<a id="eps-verify-absorption-record-non-claims"></a>

This decision record does not prove verifier compatibility. It does not decide
final absorption into `eps_rej`. It makes no zero claim and no negligible claim
for `eps_verify`, `eps_verify_mismatch`, `eps_verify_reject_absorption`, or
`eps_rej`. It is not a production-readiness statement. Implementation evidence,
test results, successful verifier experiments, and code crosswalks are review
inputs only; implementation evidence is not cryptographic proof.

## Manifest Anchors
<a id="eps-verify-absorption-record-manifest-anchors"></a>

Stable strings for manifests, cross-references, and residual tracking:

- `eps-verify-absorption-decision-record`
- `eps-verify-absorption-record-scope`
- `eps-verify-absorption-record-candidate-paths`
- `eps-verify-absorption-record-recommendation`
- `eps-verify-absorption-record-closure-criteria`
- `eps-verify-absorption-record-residual-accounting-impact`
- `eps-verify-absorption-record-acceptance-criteria`
- `eps-verify-absorption-record-non-claims`
- `eps-verify-absorption-record-manifest-anchors`
- `Decision V2-carry-eps-verify-until-byte-proof`
- `Theorem V1-standard-verifier-compatibility`
- `Theorem R1-reject-predicate-equivalence`
- `eps_verify_mismatch`
- `eps_verify_reject_absorption`
- `eps_rej`
