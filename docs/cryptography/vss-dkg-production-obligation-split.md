# VSS/DKG Production Obligation Split
<a id="vss-dkg-production-obligation-split"></a>

Stable anchor: vss-dkg-production-obligation-split

Status: Batch D production-obligation split, not a completed DKG proof.

Theorem target name: Theorem D2-production-vss-dkg-obligation-split

This document separates the assumptions supplied by the ideal `F_VSS_DKG`
route from the obligations that a real malicious-secure production VSS/DKG
backend must discharge. The current repository has a scaffold/ideal route, not
production malicious-secure VSS/DKG.

## D2-0. Split Boundary
<a id="d2-split-boundary"></a>

The ideal route may assume that `F_VSS_DKG` returns a well-formed validator
share vector, one agreed threshold public key, privacy below threshold, and
deterministic failure outcomes according to the ideal leakage interface. This
use is charged to `eps_vss_ideal` and is a proof-decomposition boundary.

A production route may not inherit those guarantees for free. It must replace
the ideal assumption with a concrete protocol, transcript grammar,
implementation, and proof package whose residual is:

```text
eps_vss(A,Z)
  <= eps_vss_binding(A,Z)
   + eps_vss_hiding(A,Z)
   + eps_vss_extract(A,Z)
   + eps_vss_complaint(A,Z)
   + eps_vss_key_bias(A,Z)
   + eps_vss_privacy(A,Z)
   + eps_vss_anti_framing(A,Z)
   + eps_vss_pk_derivation(A,Z)
   + eps_vss_impl(A,Z).
```

No term in this split is zero, negligible, or bounded by repository scaffolding
alone.

## D2-1. Dealerless Setup
<a id="d2-dealerless-setup"></a>

Ideal `F_VSS_DKG` assumption: the functionality creates setup outputs without a
trusted dealer and exposes only declared leakage, accepted parties, rejected
parties, and final outputs.

Production obligation: specify the dealerless DKG network model, static active
corruption threshold, rushing power, retry and exclusion policy, transcript
domains, validator ordering, dealer contribution ordering, and abort semantics.
The proof must show that setup either finalizes one agreed epoch transcript or
fails in a deterministic public state.

Residual terms: `eps_vss_extract`, `eps_vss_key_bias`, `eps_vss_impl`.

## D2-2. Public Coefficient Commitments
<a id="d2-public-coefficient-commitments"></a>

Ideal `F_VSS_DKG` assumption: accepted dealer shares are consistent with one
well-defined dealer contribution.

Production obligation: define public coefficient commitments, vector
commitments, or an equivalent post-quantum relation that binds every accepted
dealer contribution to one degree-`< tau` polynomial or ML-DSA-compatible
module-vector witness in the exact setup context.

Residual terms: `eps_vss_binding`, `eps_vss_hiding`, `eps_vss_extract`.

## D2-3. Private Share Delivery
<a id="d2-private-share-delivery"></a>

Ideal `F_VSS_DKG` assumption: honest receiver shares are delivered privately and
authentically according to the ideal leakage interface.

Production obligation: specify authenticated confidential per-receiver share
transport, receiver identity binding, ciphertext or delivery transcript
binding, replay protection, malformed-frame handling, and side-channel scope.

Residual terms: `eps_vss_hiding`, `eps_vss_privacy`, `eps_vss_anti_framing`,
`eps_vss_impl`.

## D2-4. Complaint Verification
<a id="d2-complaint-verification"></a>

Ideal `F_VSS_DKG` assumption: invalid shares, invalid complaints, and setup
failures are adjudicated by the functionality.

Production obligation: provide public deterministic complaint predicates for
bad shares, invalid receiver complaints, missing dealer responses, malformed
objects, equivocation, and inconclusive cases. Complaint evidence must be
verifiable by third parties without relying on local arrival order.

Residual terms: `eps_vss_complaint`, `eps_vss_anti_framing`,
`eps_vss_privacy`, `eps_vss_impl`.

## D2-5. Agreement and Extractability
<a id="d2-agreement-extractability"></a>

Ideal `F_VSS_DKG` assumption: the simulator can treat accepted setup outputs as
one agreed object with well-defined shares and public key.

Production obligation: prove that every accepted dealer transcript has a unique
extractable witness or an equivalent ideal-realization theorem, and that honest
validators agree on the accepted dealer set, complaint log, final share vector
semantics, and setup digest.

Residual terms: `eps_vss_extract`, `eps_vss_binding`, `eps_vss_complaint`.

## D2-6. Key-Bias Resistance
<a id="d2-key-bias-resistance"></a>

Ideal `F_VSS_DKG` assumption: the final key distribution is produced by the
functionality subject only to declared leakage and corruption.

Production obligation: prove that rushing, last-mover aborts, complaint timing,
dealer exclusion, retry policy, ordering, and finalization rules cannot bias
`pk_epoch` beyond the stated residual.

Residual terms: `eps_vss_key_bias`, `eps_vss_complaint`, `eps_vss_extract`.

## D2-7. Privacy and Hiding
<a id="d2-privacy-hiding"></a>

Ideal `F_VSS_DKG` assumption: unopened honest dealer coefficients and honest
receiver shares remain hidden from adversaries corrupting fewer than the
threshold, except for declared leakage.

Production obligation: prove hiding of commitments, zero-knowledge or
witness-hiding properties of openings, confidentiality of private share
delivery, and non-leakage through complaint responses, timing, rejection codes,
and malformed-object behavior.

Residual terms: `eps_vss_hiding`, `eps_vss_privacy`, `eps_vss_complaint`,
`eps_vss_impl`.

## D2-8. Anti-Framing
<a id="d2-anti-framing"></a>

Ideal `F_VSS_DKG` assumption: the functionality does not let corrupted parties
fabricate cryptographic fault evidence against honest dealers or honest
receivers.

Production obligation: prove that corrupted receivers, dealers, relays, and
network schedulers cannot transform valid honest traffic into public evidence
that falsely attributes a VSS/DKG fault. All evidence must bind dealer,
receiver, epoch, backend ID, transcript domain, and opened objects.

Residual terms: `eps_vss_anti_framing`, `eps_vss_complaint`,
`eps_vss_binding`, `eps_vss_impl`.

## D2-9. Threshold Public Key Derivation
<a id="d2-threshold-public-key-derivation"></a>

Ideal `F_VSS_DKG` assumption: the agreed public key and validator shares match
the functionality outputs.

Production obligation: prove that accepted dealer constants, public-key
contributions, final shares, and `pk_epoch` are deterministically derived from
the same extracted setup transcript and cannot be equivocated across honest
validators.

Residual terms: `eps_vss_pk_derivation`, `eps_vss_extract`,
`eps_vss_binding`.

## D2-10. Epoch Binding
<a id="d2-epoch-binding"></a>

Ideal `F_VSS_DKG` assumption: setup outputs belong to one ideal session and are
not replayed across epochs or validator sets.

Production obligation: bind every commitment, encrypted share, opening,
complaint, finalization record, accepted dealer set, threshold, parameter set,
validator set, and public key to the epoch-transition transcript and `dkg_digest`.

Residual terms: `eps_vss_binding`, `eps_vss_pk_derivation`,
`eps_vss_anti_framing`, `eps_vss_impl`.

## D2-11. Implementation and Audit Obligations
<a id="d2-implementation-audit-obligations"></a>

Ideal `F_VSS_DKG` assumption: implementation risk is outside the ideal
functionality except where the proof explicitly models leakage.

Production obligation: select a concrete backend, implement canonical
encodings, fail-closed production gates, constant-time secret handling where
needed, verifier resource limits, negative tests, transcript test vectors,
interoperability tests, side-channel review, and external cryptographic audit.
Implementation evidence can support assurance, but it is not a cryptographic
proof.

Residual terms: `eps_vss_impl`, plus any cryptographic subterm affected by an
implementation bug or audit gap.

## D2-12. Non-Claims
<a id="d2-non-claims"></a>

This document selects no production DKG. It proves no malicious-secure VSS
theorem, no zero/negligible claim, no binding theorem, no hiding theorem, no
extractability theorem, no complaint soundness theorem, no key-bias theorem, no
privacy theorem, no anti-framing theorem, and no public-key derivation theorem.
Implementation evidence is not cryptographic proof.

## D2-13. Manifest Anchors
<a id="d2-manifest-anchors"></a>

Stable anchors and text markers:

- `# VSS/DKG Production Obligation Split`
- `Stable anchor: vss-dkg-production-obligation-split`
- `vss-dkg-production-obligation-split`
- `Status: Batch D production-obligation split, not a completed DKG proof.`
- `Theorem D2-production-vss-dkg-obligation-split`
- `eps_vss_ideal`
- `eps_vss_binding`
- `eps_vss_hiding`
- `eps_vss_extract`
- `eps_vss_complaint`
- `eps_vss_key_bias`
- `eps_vss_privacy`
- `eps_vss_anti_framing`
- `eps_vss_pk_derivation`
- `eps_vss_impl`
- `eps_vss`
- `dealerless setup`
- `public coefficient commitments`
- `private share delivery`
- `complaint verification`
- `agreement and extractability`
- `key-bias resistance`
- `privacy and hiding`
- `anti-framing`
- `threshold public key derivation`
- `epoch binding`
- `implementation and audit obligations`
- `scaffold/ideal route, not production malicious-secure VSS/DKG`
- `no production DKG`
- `no malicious-secure VSS proof`
- `no zero/negligible claim`
- `implementation evidence is not cryptographic proof`
