# Proof Dependency Bibliography and Citation Map
<a id="proof-bibliography"></a>

Date: 2026-05-27

Status: citation dependency map, not a completed bibliography.

This document records the external theorem families needed to close the
cryptographic proof package. It deliberately separates known local proof hooks
from external citations still needed. Where the local proof documents do not
identify an exact paper, theorem, parameter statement, or standard section, this
file uses conservative citation placeholders instead of inventing references.

Read with:

- [formal-security-theorem.md](formal-security-theorem.md)
- [random-oracle-game.md](random-oracle-game.md)
- [rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md)
- [vss-backend-selection.md](vss-backend-selection.md)
- [side-channel-boundary.md](side-channel-boundary.md)
- [claims-matrix.md](claims-matrix.md)

## FIPS 204 / ML-DSA

External result needed:

- Normative algorithm and parameter reference for ML-DSA-65 key generation,
  signing, verification, encodings, constants, challenge format, rejection
  predicates, and verification behavior.
- Official interpretation of the message-binding value, verifier input, and
  signature wire format used by ML-DSA-65.
- Scope statement separating FIPS conformance or validation from use of the
  FIPS 204 algorithms in a research threshold construction.

Citation targets:

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, for the
  normative ML-DSA algorithm family and ML-DSA-65 parameter set.
- [Citation needed: exact FIPS 204 section numbers for ML-DSA-65 parameter
  values, signing, verification, signature encoding, and rejection conditions.]
- [Citation needed: official ACVP or validation-program reference if the
  manuscript discusses test vectors, KATs, or non-validation boundaries.]

Where it plugs in:

- `formal-security-theorem.md` FST-1 defines `MLDSA65.KeyGen`,
  `MLDSA65.Sign`, and `MLDSA65.Verify` as FIPS 204 algorithms.
- `formal-security-theorem.md` FST-A1 needs the exact ML-DSA-65 security
  theorem or accepted security interpretation used as the base assumption.
- `formal-security-theorem.md` FST-D6, FST-G1, FST-L5, FST-T1, and FST-T2 use
  standard `MLDSA65.Verify(pk, m, sigma) = accept` as the final acceptance
  predicate.
- `random-oracle-game.md` ROG-D1 and ROG-D3 must align the threshold transcript
  with the ML-DSA message-binding and challenge derivation interface.
- `rejection-sampling-hybrid-proof.md` H0 and H5 need the centralized ML-DSA-65
  signing distribution and exact aggregate rejection predicate.
- `claims-matrix.md` rows for standard byte layout, KAT coverage, standard
  verifier compatibility, FIPS validation, and production readiness depend on
  this citation boundary.

## Dilithium Security Analysis

External result needed:

- Security analysis for the Dilithium or ML-DSA construction at the ML-DSA-65
  parameter level, including the assumption set, random-oracle or QROM model,
  Fiat-Shamir transform treatment, rejection sampling, and concrete security
  loss.
- Parameter-specific justification for using the centralized signing
  distribution as the reference distribution in the threshold hybrid chain.
- A statement of what the base unforgeability assumption covers and what it
  does not cover, especially for modified threshold signing, altered
  transcripts, and side-channel leakage.

Citation targets:

- [Citation needed: Dilithium design/security analysis paper and theorem
  covering EUF-CMA or SUF-CMA security for the relevant parameter family.]
- [Citation needed: ML-DSA/FIPS 204 security rationale or transition note
  connecting Dilithium analysis to ML-DSA-65.]
- [Citation needed: QROM or random-oracle proof reference accepted for ML-DSA
  challenge derivation and tightness/security-loss accounting.]

Where it plugs in:

- `formal-security-theorem.md` FST-A1 is the direct base assumption for
  ML-DSA-65 unforgeability.
- `formal-security-theorem.md` FST-G1 and FST-T1 reduce unauthorized threshold
  forgery to the base ML-DSA-65 assumption plus threshold-specific assumption
  violations.
- `formal-security-theorem.md` FST-H4 and FST-H5 replace aggregate threshold
  signatures with signatures returned by `F_TMLDSA.Sign`; the replacement is
  only meaningful if the returned distribution is tied back to the cited
  centralized theorem.
- `rejection-sampling-hybrid-proof.md` H0 explicitly calls centralized ML-DSA
  the reference distribution and marks the exact FIPS theorem, parameter set,
  and random-oracle interpretation as open.
- `claims-matrix.md` rows for static active security, rejection-sampling
  preservation, and production deployment readiness rely on this citation set
  before any publication-facing security claim can be strengthened.

## Fiat-Shamir With Aborts

External result needed:

- Fiat-Shamir-with-aborts theorem and distribution-preservation analysis
  applicable to lattice signatures with rejection sampling.
- A proof principle for commit-before-challenge threshold signing: public
  commitments must be fixed before challenge derivation, and accepted outputs
  must remain distributed like centralized ML-DSA signatures.
- Selective-abort analysis for active or rushing adversaries that may withhold
  commitments, withhold partial shares, force aggregate rejection, or condition
  later attempts on public abort information.
- Random-oracle programming rules and bad-event bounds for simulators that
  program message-binding, commitment, challenge, VSS, or contribution-proof
  domains.

Citation targets:

- [Citation needed: Fiat-Shamir with aborts foundational theorem used by
  lattice signature proofs.]
- [Citation needed: Dilithium-specific rejection-sampling and abort analysis,
  including accepted-signature distribution bounds.]
- [Citation needed: selective-abort or rushing-adversary analysis for threshold
  Fiat-Shamir signing, or a proof that the project-specific abort channel is
  simulatable.]
- [Citation needed: random-oracle programming lemma for multi-domain
  Fiat-Shamir transcripts with prior adversarial queries.]

Where it plugs in:

- `formal-security-theorem.md` FST-A4 and FST-A5 require commitment binding,
  hiding, abort preservation, and noise-bound preservation.
- `formal-security-theorem.md` FST-G5 and FST-L7 are the abort-bias game and
  abort-compatibility lemma.
- `formal-security-theorem.md` FST-X3 states that no ML-DSA-65
  Fiat-Shamir-with-aborts preservation proof is currently present for the
  threshold setting.
- `random-oracle-game.md` ROG-D2 and ROG-D3 define commitment and challenge
  oracle ordering; ROG-5 defines simulator programming obligations.
- `rejection-sampling-hybrid-proof.md` H2 through H6 and RSH-3 are the main
  insertion points for mask distribution, commit-before-challenge,
  challenge-bound reconstruction, aggregate rejection, accepted-signature
  distribution, and selective-abort simulation.
- `claims-matrix.md` rows for rejection sampling, noise-bound proof, static
  active security, and side-channel/timing boundaries must remain conservative
  until these citations are closed.

## Threshold Signatures / MPC Signing

External result needed:

- Threshold signature or MPC signing security theorem for static Byzantine
  corruption with fewer than `t` corrupted validators, including correctness,
  unforgeability, simulator extraction, partial-share validity, and aggregation.
- Protocol-level theorem for commit-before-challenge signing in which partial
  contributions are attributable, non-portable across transcripts, and
  simulatable against an ideal signing functionality.
- MPC or proof-system reference for contribution proofs if production signing
  uses zero-knowledge, witness-hiding, extractable, publicly verifiable, or
  audited MPC verification relations.
- Reduction pattern from an accepting unauthorized aggregate signature to
  either an ML-DSA forgery, a threshold-share violation, a commitment/proof
  soundness violation, or a transcript-binding violation.

Citation targets:

- [Citation needed: threshold lattice signature or threshold Dilithium/ML-DSA
  signing theorem matching static active corruption.]
- [Citation needed: MPC-in-the-head, proof-carrying contribution, or audited
  MPC signing theorem selected for production partial verification.]
- [Citation needed: ideal-functionality or UC realization reference for
  threshold signing with abort and evidence events, if FST-T2 is claimed in a
  UC-style model.]
- [Citation needed: partial-signature extractability or knowledge-soundness
  theorem for the selected contribution-proof relation.]

Where it plugs in:

- `formal-security-theorem.md` FST-D1 through FST-D6 define the adversary,
  corruption, aggregator, signing oracle, and forgery model.
- `formal-security-theorem.md` FST-A6, FST-L4, FST-L5, FST-L6, FST-L8, FST-T1,
  and FST-T2 need threshold signing correctness, no-subthreshold signing, and
  simulator extraction.
- `formal-security-theorem.md` FST-H0 through FST-H5 need distinguishing
  bounds for replacing real partial-share generation and aggregate outputs with
  ideal signing calls.
- `random-oracle-game.md` ROG-D5 and ROG-G1 require contribution proofs that
  bind to `sid`, `t`, `V`, `pk`, `m` or `mu`, `Com`, `c`, validator identity,
  commitment, share metadata, partial statement, and proof statement.
- `rejection-sampling-hybrid-proof.md` H4 needs a production partial
  verification relation and proof that accepted partials bind to one validator,
  share, active set, challenge, and commitment.
- `claims-matrix.md` rows for proof-bearing contribution boundaries, static
  active theorem, adaptive security, and production readiness depend on this
  citation set.

## VSS/DKG

External result needed:

- Malicious-secure VSS or DKG theorem for static active corruption below the
  threshold, including binding, hiding, extractability, complaint soundness,
  anti-framing, and key-bias resistance.
- Exact relation between accepted dealer transcripts, receiver shares,
  verification metadata, and the resulting threshold ML-DSA public key.
- Complaint and evidence theorem distinguishing dealer faults, receiver faults,
  malformed frames, equivocation, and inconclusive failures without leaking
  honest secret share material.
- If a dealer-based alternative is used, a theorem showing share secrecy and
  binding for the dealer transcript under the same threshold assumptions.

Citation targets:

- [Citation needed: VSS theorem with binding, hiding, complaint soundness, and
  public verifiability under active corruption.]
- [Citation needed: DKG theorem with key-bias resistance against rushing and
  last-mover behavior.]
- [Citation needed: anti-framing theorem for complaint evidence and private
  share delivery.]
- [Citation needed: threshold share secrecy theorem over the exact algebra or
  ring/module domain used by the selected ML-DSA sharing construction.]

Where it plugs in:

- `formal-security-theorem.md` FST-A2 and FST-A3 are the direct threshold
  sharing soundness and verifiable share binding assumptions.
- `formal-security-theorem.md` FST-G4, FST-L3, FST-L4, FST-L6, FST-T1, and
  FST-T2 rely on unique, verified, non-rogue shares and subthreshold secrecy.
- `random-oracle-game.md` ROG-D4 is the random-oracle domain for VSS, DKG,
  complaint, and dealer-contribution proofs.
- `rejection-sampling-hybrid-proof.md` H1 needs all production secret
  components shared with matching degree, identifier domain, commitment
  verification, and active-security properties.
- `vss-backend-selection.md` Required Selection Properties and Selection
  Checklist define the exact backend properties that need citation closure.
- `claims-matrix.md` rows for VSS/DKG scaffold, artifact-to-frame evidence,
  production policy gates, static active security, and production readiness
  all remain blocked by this citation set.

## Lattice / Vector Commitments

External result needed:

- Concrete post-quantum commitment or vector-commitment construction over a
  domain compatible with ML-DSA secret polynomials or module vectors.
- Binding, hiding, extractability, opening-proof soundness, zero-knowledge or
  witness-hiding, receiver-index binding, encrypted-share binding, and
  public-key contribution consistency for the selected relation.
- Parameter-specific security analysis covering modulus, dimension, norm/range
  predicates, proof sizes, rejection behavior, and concrete security loss.
- Serialization and domain-separation theorem tying commitment statements,
  openings, proof statements, complaints, and public-key contribution digests
  to canonical verifier inputs.

Citation targets:

- [Citation needed: named lattice/vector commitment construction selected for
  production VSS/DKG or signing commitments.]
- [Citation needed: opening proof system theorem for binding, hiding,
  extractability, and witness hiding over ML-DSA-compatible vectors.]
- [Citation needed: parameter-selection analysis for ML-DSA-65 dimensions,
  modulus `q = 8380417`, norm/range bounds, proof sizes, and concrete security.]
- [Citation needed: canonical serialization or domain-separation result if the
  proof relies on composed hash/XOF domains as independent random oracles.]

Where it plugs in:

- `formal-security-theorem.md` FST-A3 and FST-A4 need verifiable share binding
  and signing commitment binding/hiding.
- `random-oracle-game.md` ROG-D2, ROG-D4, and ROG-D5 need commitment,
  VSS-proof, and contribution-proof domains that are not portable across
  contexts.
- `rejection-sampling-hybrid-proof.md` H2 and H3 need the production
  distribution for `y_i`, binding/hiding commitments to masking material, and
  equivocation resistance before `H_c`.
- `vss-backend-selection.md` Candidate Family B is the preferred investigation
  path but explicitly unselected; its blockers define the citation and review
  requirements for a production choice.
- `claims-matrix.md` rows for VSS/DKG, proof-bearing contribution boundaries,
  static active theorem, and production deployment readiness all depend on
  selecting and citing this construction.

## Side-Channel Methodology

External result needed:

- Methodology references for constant-time coding, leakage models, dudect or
  equivalent Welch t-test timing analysis, ctgrind or equivalent dynamic
  secret-dependence checks, compiler-output review, zeroization review, and
  platform-specific audit limitations.
- A leakage-model statement explaining what the mathematical theorem assumes
  and what empirical tests can and cannot prove.
- Operational methodology for treating retry counts, abort timing, error paths,
  logging, diagnostics, memory lifetime, and evidence generation as public
  leakage or production blockers.

Citation targets:

- [Citation needed: dudect methodology reference for Welch t-test timing
  leakage detection.]
- [Citation needed: ctgrind or equivalent dynamic analysis reference for
  secret-dependent branch and memory-access checks.]
- [Citation needed: constant-time cryptographic implementation guidance
  accepted for Rust or comparable systems code.]
- [Citation needed: zeroization and compiler-output review guidance for
  production cryptographic implementations.]
- [Citation needed: leakage-resilient or side-channel-aware proof reference if
  any future theorem claims more than a constant-time implementation
  assumption.]

Where it plugs in:

- `formal-security-theorem.md` FST-A9 assumes implementation constant-time
  discipline for production realization, and FST-X6 states that no
  side-channel model or audit is complete.
- `formal-security-theorem.md` FST-L9 needs evidence generation to avoid
  exposing honest secret share material or creating signing capability.
- `rejection-sampling-hybrid-proof.md` RSH-3 includes timing, evidence, retry
  counts, and participant-specific abort labels in the observable abort
  transcript that must be modeled or hidden.
- `side-channel-boundary.md` defines the current boundary: mathematical
  protocol claims do not imply timing, cache, memory-access, logging, panic,
  compiler, allocator, or zeroization guarantees.
- `claims-matrix.md` rows for side-channel resistance, adaptive security,
  FIPS/certification boundaries, and production readiness must remain
  non-claims until this methodology package and audit evidence exist.

## Citation Closure Checklist

- Identify exact FIPS 204 section and table citations for ML-DSA-65 algorithms,
  constants, encodings, rejection predicates, and verifier behavior.
- Identify the base Dilithium/ML-DSA security theorem used for FST-A1,
  including model, parameter set, tightness, and security level.
- Close the Fiat-Shamir-with-aborts citation chain for ML-DSA rejection
  sampling, challenge derivation, accepted-signature distribution, and
  random-oracle programmability.
- Select or cite a threshold ML-DSA, threshold Dilithium, or MPC signing theorem
  that supports static active corruption, partial contribution verification,
  aggregation, and real/ideal simulation.
- Select the production VSS/DKG backend and cite binding, hiding,
  extractability, complaint soundness, anti-framing, and key-bias resistance
  theorems for that exact backend.
- Select the lattice/vector commitment and opening-proof construction, then
  cite its parameter-specific security analysis for the ML-DSA-65 algebra and
  serialization.
- Define the project leakage model and cite the side-channel methodology used
  for constant-time review, empirical timing tests, dynamic analysis,
  zeroization review, and compiler-output inspection.
- For every `[Citation needed: ...]` placeholder above, either replace it with
  a precise citation and theorem/section pointer or leave the corresponding
  theorem document phrased as an open assumption, target, or non-claim.
- Re-run the proof-package claim review after citation closure and update
  `claims-matrix.md` only if the external result, local proof mapping, and
  implementation/audit evidence all support stronger wording.
