# IdealVSS Signing Theorem Closure
<a id="idealvss-signing-theorem-closure"></a>

Date: 2026-05-28

Status: closure plan for `FST-T1-IdealVSS`, not a completed proof.

## IVSTC-0. Scope and Non-Claim
<a id="idealvss-scope-non-claim"></a>

This plan isolates the first theorem target that can plausibly be closed
without selecting a concrete malicious-secure VSS/DKG backend:
`FST-T1-IdealVSS` from
[formal-security-theorem.md](formal-security-theorem.md). In this route, setup
is provided by the ideal functionality `F_VSS_DKG`, and the proof focuses only
on the signing-side threshold ML-DSA-65 obligations.

The lemma-by-lemma proof skeleton is tracked in
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md).

This document does not prove `FST-T1-IdealVSS`. It also does not prove concrete
production VSS/DKG security, production deployment readiness, side-channel
resistance, or final threshold unforgeability without the ideal setup
assumption.

## IVSTC-1. Theorem Under Closure: FST-T1-IdealVSS
<a id="idealvss-theorem-target"></a>

Target theorem:

```text
FST-T1-IdealVSS:
  For every PPT adversary A statically corrupting at most t - 1 validators,
  threshold signing under ideal F_VSS_DKG setup is EUF-CMA secure if the
  signing-side lemmas below hold and the final output classifier has no
  unmapped accepting unauthorized output.
```

The theorem keeps concrete VSS/DKG out of scope by exposing only:

```text
(pk_epoch, dkg_digest, AcceptedDealers, share_i, allowed_setup_leakage)
```

from `F_VSS_DKG` to honest participants and to the simulator.

## IVSTC-2. Ideal Setup Boundary
<a id="idealvss-setup-boundary"></a>

For this theorem path, `F_VSS_DKG` may discharge setup consistency, VSS
binding, VSS hiding, extractability or equivalent share soundness, complaint
soundness, anti-framing, output agreement, and key-bias resistance only for
claims explicitly labeled `IdealVSS`.

The signing proof must not rely on any concrete VSS/DKG implementation detail.
Any production theorem must later replace this ideal setup assumption with a
concrete `eps_vss` theorem and audit record.

## IVSTC-3. Dependency Map
<a id="idealvss-dependency-ledger"></a>

| Dependency | Closure requirement | Current source |
| --- | --- | --- |
| `F_VSS_DKG` interface | Fix exact setup leakage, corruption leakage, complaint leakage, and public digest semantics. | [vss-idealization-and-selection.md](vss-idealization-and-selection.md), [ideal-functionality.md](ideal-functionality.md) |
| Transcript injectivity | Prove typed encodings are injective for session, validator set, key, message, commitments, shares, and evidence references. | [production-transcript-grammar.md](production-transcript-grammar.md), [formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md), [random-oracle-game.md](random-oracle-game.md) |
| Commitment non-adaptivity | Prove commitments are fixed before `H_c` and that opened sets equal challenged sets. | [random-oracle-game.md](random-oracle-game.md), [rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md) |
| Contribution validity | Select or idealize the contribution relation used by accepted partial shares. | [contribution-backend-selection.md](contribution-backend-selection.md), [contribution-backend-instantiation.md](contribution-backend-instantiation.md) |
| Rejection preservation | Close or keep visible `eps_mask`, `eps_rej`, `eps_withhold`, and `eps_verify`. | [rejection-sampling-closure-plan.md](rejection-sampling-closure-plan.md) |
| Unauthorized-output classification | Prove `eps_cls_unmapped = 0` under the production grammar. | [unauthorized-output-classifier-elimination.md](unauthorized-output-classifier-elimination.md) |

## IVSTC-4. Signing-Side Lemma Closure Plan
<a id="idealvss-signing-lemma-plan"></a>

The signing-side work is the closure of `FST-L1` through `FST-L7`, with
`FST-L10` used to eliminate unauthorized accepting outputs:

- `FST-L1` transcript injectivity.
- `FST-L2` challenge binding.
- `FST-L3` validator-set soundness.
- `FST-L4` partial-share validity.
- `FST-L5` aggregation correctness.
- `FST-L6` no subthreshold signing.
- `FST-L7` abort compatibility.
- `FST-L10` unauthorized-output classifier closure.

## IVSTC-5. Real/Ideal and Hybrid Dependencies
<a id="idealvss-hybrid-route"></a>

The closure path should use the existing S0 through S8 simulator worksheet:

1. Replace real setup with `F_VSS_DKG` outputs.
2. Program honest commitments and contribution statements consistently with
   the ideal setup digest.
3. Bind the challenge to one canonical ordered commitment set.
4. Replace honest signing attempts with ideal authorized releases only after
   contribution validity, rejection preservation, and abort simulation are
   accounted for.
5. Map every accepting unauthorized aggregate output through the classifier.

The route may close an idealized theorem only if every signing-side loss is
either proved negligible, explicitly bounded, or left visible in a theorem
statement that does not claim full security.

## IVSTC-6. What Can Be Claimed Now
<a id="idealvss-current-claims"></a>

Safe current claim: the repository defines an immediate proof route for
threshold signing under ideal setup. `F_VSS_DKG` isolates concrete DKG/VSS from
the signing theorem so that the signing-side proof can be reviewed separately.

Unsafe current claim: the repository proves `FST-T1-IdealVSS`, proves concrete
production VSS/DKG, or proves full threshold ML-DSA-65 unforgeability.

## IVSTC-7. What Remains Open
<a id="idealvss-open-items"></a>

- `eps_commit`.
- `eps_ro`.
- `eps_mask`.
- `eps_rej`.
- `eps_withhold`.
- `eps_contrib`.
- `eps_classify`, including `eps_cls_unmapped = 0`.
- `eps_verify`, unless it is absorbed into `eps_rej` with proof.
- Signing-side reductions for `FST-L1` through `FST-L7`.
- Concrete bounds parameterized by sessions, oracle queries, validators,
  corruptions, retries, evidence records, and aggregate verification attempts.

## IVSTC-8. Links to Source Obligations
<a id="idealvss-source-obligations"></a>

- [formal-security-theorem.md](formal-security-theorem.md)
- [idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md)
- [production-transcript-grammar.md](production-transcript-grammar.md)
- [vss-idealization-and-selection.md](vss-idealization-and-selection.md)
- [ideal-functionality.md](ideal-functionality.md)
- [real-ideal-simulator.md](real-ideal-simulator.md)
- [simulator-hybrid-reductions.md](simulator-hybrid-reductions.md)
- [proof-closure-ledger.md](proof-closure-ledger.md)
- [proof-obligations.md](proof-obligations.md)

## IVSTC-9. Reviewer Checklist
<a id="idealvss-acceptance-criteria"></a>

Before `FST-T1-IdealVSS` may move from target to proved theorem:

- `F_VSS_DKG` inputs, outputs, leakage, corruption behavior, and digest
  semantics are fixed.
- The signing proof never uses concrete VSS/DKG properties outside the ideal
  interface.
- `eps_contrib` is closed by a selected backend or explicitly idealized as a
  separate theorem assumption.
- `eps_commit`, `eps_ro`, `eps_mask`, `eps_rej`, `eps_withhold`, and
  `eps_verify` are closed or visible in the theorem statement.
- The unauthorized-output classifier proves `eps_cls_unmapped = 0`.
- All implementation evidence remains described as review evidence, not proof.

## Manifest Anchors

- `# IdealVSS Signing Theorem Closure`
- `idealvss-signing-theorem-closure`
- `IVSTC-0. Scope and Non-Claim`
- `IVSTC-1. Theorem Under Closure: FST-T1-IdealVSS`
- `IVSTC-2. Ideal Setup Boundary`
- `IVSTC-3. Dependency Map`
- `IVSTC-4. Signing-Side Lemma Closure Plan`
- `IVSTC-5. Real/Ideal and Hybrid Dependencies`
- `IVSTC-6. What Can Be Claimed Now`
- `IVSTC-7. What Remains Open`
- `IVSTC-8. Links to Source Obligations`
- `IVSTC-9. Reviewer Checklist`
- `idealvss-theorem-target`
- `FST-T1-IdealVSS`
- `F_VSS_DKG`
- `FST-L1`
- `FST-L7`
- `FST-L10`
- `idealvss-dependency-ledger`
- `idealvss-hybrid-route`
- `idealvss-acceptance-criteria`
- `idealvss-open-items`
