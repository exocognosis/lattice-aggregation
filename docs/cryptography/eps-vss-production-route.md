# eps_vss Production Route
<a id="eps-vss-production-route"></a>

Status: production-route roadmap for eps_vss, not a selected malicious-secure
VSS/DKG backend and not a completed VSS proof.

This document narrows the production VSS/DKG proof surface for the threshold
ML-DSA-65 scaffold. It complements the ideal `F_VSS_DKG` route by spelling out
what a concrete setup backend must eventually prove before production security,
slashing, or deployment-readiness claims are available.

Batch D further separates ideal `F_VSS_DKG` assumptions from concrete
production obligations in
[VSS/DKG Production Obligation Split](vss-dkg-production-obligation-split.md).

## D1-0. Scope
<a id="d1-scope"></a>

`eps_vss` covers the loss from replacing an ideal setup functionality with a
real malicious-secure VSS/DKG protocol. The current Rust VSS and DKG code is a
deterministic scaffold and proof boundary. It does not implement the production
relation described here.

The production route must cover both dealer contribution security and global
DKG finalization:

```text
Dealer VSS transcripts -> accepted dealer set -> joint pk_epoch -> share_i.
```

Every step must be bound to epoch transition semantics, validator set,
threshold, parameter set, public transcript, complaint outcomes, and final
public key derivation.

## D1-1. Required Production Objects
<a id="d1-required-production-objects"></a>

A production backend must define:

- VSS/DKG setup context: protocol version, epoch, session, validator set,
  threshold, ML-DSA-65 parameter set, dealer ordering, receiver ordering, and
  transcript domains.
- Public commitments: dealer coefficient commitments, vector commitments, or
  equivalent objects binding one degree-`< tau` dealer polynomial.
- Private share delivery: authenticated and confidential per-receiver share
  transport, with ciphertext or delivery transcript binding to the same dealer
  context.
- Opening/proof objects: receiver-specific proof material, range or norm
  predicates if needed, public-key contribution consistency, and complaint
  response openings.
- Complaint records: public, deterministic evidence for invalid dealer shares,
  invalid receiver complaints, missing responses, malformed frames, and
  inconclusive cases.
- Finalization record: accepted dealer set, rejected dealer set, complaint
  log, transcript digest, joint public key, and per-validator final share.

None of these objects may depend on implicit network arrival order or local
aggregator state.

## D1-2. Theorem Target
<a id="d1-theorem-target"></a>
<a id="theorem-d1-production-vss-dkg-realization"></a>

Theorem D1-production-vss-dkg-realization. For every PPT adversary `A`,
environment `Z`, static active corruption set of size less than the threshold,
and production VSS/DKG backend satisfying the declared transcript grammar, the
real setup protocol realizes the ideal setup boundary needed by the signing
proof with loss:

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
   + eps_vss_backend_selection(A,Z).
```

This theorem is a target statement. This document does not prove it and does
not claim any subterm is negligible or zero.

## D1-3. Residual Subterms
<a id="d1-residual-subterms"></a>

- `eps_vss_binding`: accepted commitments, shares, openings, public-key
  contributions, and complaint responses are not all bound to one unique
  dealer polynomial and context.
- `eps_vss_hiding`: unopened honest dealer coefficients or receiver shares
  leak beyond public outputs and declared complaint leakage.
- `eps_vss_extract`: an accepted dealer transcript lacks a unique extractor or
  ideal replacement object.
- `eps_vss_complaint`: complaint adjudication is unsound, ambiguous,
  non-deterministic, or not publicly verifiable.
- `eps_vss_key_bias`: rushing, last-mover abort, complaint scheduling, dealer
  exclusion, or transcript ordering biases the final key distribution.
- `eps_vss_privacy`: private share delivery, proof material, timing, or
  malformed-frame behavior leaks receiver shares or dealer secrets.
- `eps_vss_anti_framing`: corrupted receivers or network adversaries can
  fabricate public evidence against honest dealers or honest receivers.
- `eps_vss_pk_derivation`: accepted dealer public-key contributions and final
  `pk_epoch` do not deterministically match extracted dealer constants and
  final shares.
- `eps_vss_backend_selection`: an unselected, scaffold, unaudited, or
  assumption-mismatched backend is treated as production eligible.

## D1-4. Production Requirements
<a id="d1-production-requirements"></a>

Before `eps_vss` can be bounded, the backend must provide:

- dealerless DKG or VSS setup with an exact network and rushing model;
- public commitments that bind one polynomial or module-vector witness;
- private share delivery with authenticated receiver identity and context;
- complaint resolution that is deterministic, public, and anti-framing;
- key-bias resistance under dealer exclusion and retry policy;
- extractability, agreement, or an ideal-realization theorem for accepted
  dealer transcripts;
- privacy for unopened honest shares and dealer secrets below threshold;
- deterministic threshold public key derivation from accepted dealer
  contributions;
- transcript binding across epoch transition, validator set, accepted dealer
  set, complaints, public key, and final shares; and
- failure-mode rules that compose with evidence, release, classifier, and
  consensus epoch-transition logic.

## D1-5. Candidate Families
<a id="d1-candidate-families"></a>

### Pedersen/Feldman-Style VSS Adapted to Lattice Statements

This family is useful as a protocol template for commit, share, complaint,
response, and finalization phases. It remains blocked unless the commitment
assumption, share domain, public-key contribution relation, and hiding theorem
are post-quantum compatible and aligned with ML-DSA statements.

Conventional discrete-log Feldman/Pedersen commitments are not selected for
production in this repository.

### MPC/DKG Protocol

An MPC/DKG backend may realize setup through an interactive protocol with
publicly verifiable finalization. It must define privacy leakage, extractor or
ideal-realization hooks, complaint evidence, key-bias resistance, network
scheduling assumptions, and transcript binding. It may be a production path
only after implementation, proof, and audit are available.

### Ideal `F_VSS_DKG` Continuation

The ideal functionality remains the immediate proof-isolation route. It is
acceptable for an IdealVSS theorem but not for production. It assumes binding,
hiding, extractability, complaint soundness, anti-framing, key-bias resistance,
and public-key agreement rather than implementing them.

## D1-6. Acceptance Criteria
<a id="d1-acceptance-criteria"></a>

This route may be considered closed only after a future change provides:

- a selected backend family, backend ID, parameter set, and transcript grammar;
- a complete public relation and witness or ideal-realization statement;
- proofs for binding, hiding, extraction or agreement, complaint soundness,
  privacy, anti-framing, key-bias resistance, and public-key derivation;
- explicit residual accounting for every `eps_vss_*` subterm;
- production policy gates that reject scaffold and unselected backends;
- negative tests for malformed, equivocated, replayed, mismatched, duplicate,
  and out-of-context VSS/DKG records; and
- external cryptographic and implementation review.

## D1-7. Non-Claims
<a id="d1-non-claims"></a>

This document selects no production DKG. It proves no malicious-secure VSS
theorem, no key-bias bound, no complaint soundness, no anti-framing theorem, no
privacy theorem, and no public-key derivation theorem. It makes no zero or
negligible claim for `eps_vss` or any `eps_vss_*` subterm. It is not
production-ready, and implementation evidence is not cryptographic proof.

## D1-8. Manifest Anchors
<a id="d1-manifest-anchors"></a>

Stable strings:

- `# eps_vss Production Route`
- `vss-dkg-production-obligation-split`
- `eps-vss-production-route`
- `Status: production-route roadmap for eps_vss`
- `D1-0. Scope`
- `D1-1. Required Production Objects`
- `D1-2. Theorem Target`
- `D1-3. Residual Subterms`
- `D1-4. Production Requirements`
- `D1-5. Candidate Families`
- `D1-6. Acceptance Criteria`
- `D1-7. Non-Claims`
- `D1-8. Manifest Anchors`
- `Theorem D1-production-vss-dkg-realization`
- `eps_vss_binding`
- `eps_vss_hiding`
- `eps_vss_extract`
- `eps_vss_complaint`
- `eps_vss_key_bias`
- `eps_vss_privacy`
- `eps_vss_anti_framing`
- `eps_vss_pk_derivation`
- `eps_vss_backend_selection`
- `dealerless DKG or VSS setup`
- `public commitments`
- `private share delivery`
- `complaint resolution`
- `key-bias resistance`
- `anti-framing`
- `deterministic threshold public key derivation`
- `epoch transition`
- `no production DKG`
- `no malicious-secure VSS proof`
- `implementation evidence is not cryptographic proof`
