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

Resolved citation targets:

- National Institute of Standards and Technology, [FIPS 204,
  Module-Lattice-Based Digital Signature Standard][fips204], August 13, 2024,
  DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204).
  Use Table 1 for ML-DSA-65 parameters (`q = 8380417`, `tau = 49`,
  `lambda = 192`, `gamma1 = 2^19`, `gamma2 = (q - 1)/32`, `(k,l) = (6,5)`,
  `eta = 4`, `beta = 196`, `omega = 55`, claimed NIST security category 3),
  Table 2 for key and signature sizes, Section 5 and Algorithms 1-3 for
  external key generation, signing, and verification, Section 6 and Algorithms
  6-8 for internal key generation, signing, verification, message
  representative `mu`, challenge derivation, and rejection predicates, Section
  7.2 and Algorithms 22-29 for key, signature, `w1`, and challenge encodings,
  and Appendix C for optional loop/output limits and their error-handling
  boundary.
- National Institute of Standards and Technology, [ACVP ML-DSA JSON
  Specification][acvp-mldsa]. Use Section 5 for the advertised ACVP algorithm
  triples `ML-DSA / keyGen / FIPS204`, `ML-DSA / sigGen / FIPS204`, and
  `ML-DSA / sigVer / FIPS204`; Sections 6.1.1-6.1.3 for key-generation,
  signature-generation, and signature-verification test types; Section 6.2 for
  requirements covered and not covered; Sections 7.3-7.5 for registration
  properties; and Sections 9.1-9.3 for response objects. This is a test-vector
  and validation-protocol citation, not evidence of FIPS validation for this
  repository.

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

Resolved citation targets:

- Shi Bai, Leo Ducas, Eike Kiltz, Tancrede Lepoint, Vadim Lyubashevsky, Peter
  Schwabe, Gregor Seiler, and Damien Stehle, [CRYSTALS-Dilithium: Algorithm
  Specifications and Supporting Documentation, Version 3.1][dilithium-v31],
  February 8, 2021. Use Section 6 for the security discussion, including
  UF-CMA/SUF-CMA definitions and the MLWE, SelfTargetMSIS, and MSIS assumption
  split; Section 6.2.1 for the UF-CMA proof sketch; Section 6.2.2 for the
  strong-unforgeability addition; Section 6.3 and Appendix C for concrete
  security analysis; and Table 1 for the Dilithium level-3 parameter/security
  background. This supports the Dilithium design/security rationale, not the
  FIPS 204 wire-format details after standardization changes.
- Leo Ducas, Eike Kiltz, Tancrede Lepoint, Vadim Lyubashevsky, Peter Schwabe,
  Gregor Seiler, and Damien Stehle, [CRYSTALS-Dilithium: A Lattice-Based
  Digital Signature Scheme][dilithium-tches], IACR Transactions on
  Cryptographic Hardware and Embedded Systems, 2018(1):238-268, DOI:
  [10.13154/tches.v2018.i1.238-268](https://doi.org/10.13154/tches.v2018.i1.238-268).
  Use as the original peer-reviewed Dilithium design paper.
- FIPS 204, Section 3 and Appendix D. Section 3 states that ML-DSA is based on
  CRYSTALS-Dilithium and uses the Fiat-Shamir-with-aborts construction; Appendix
  D records differences from the CRYSTALS-Dilithium submission and notes that
  ML-DSA is derived from CRYSTALS-Dilithium Version 3.1.
- Eike Kiltz, Vadim Lyubashevsky, and Christian Schaffner, [A Concrete
  Treatment of Fiat-Shamir Signatures in the Quantum Random-Oracle
  Model][kls-qrom], EUROCRYPT 2018, pp. 552-586, DOI:
  [10.1007/978-3-319-78372-7_18](https://doi.org/10.1007/978-3-319-78372-7_18).
  Use for the QROM Fiat-Shamir/Dilithium security-analysis background cited by
  FIPS 204 and the Dilithium v3.1 specification. It does not by itself prove
  this repository's threshold transcript or selective-abort games.

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

Resolved citation targets:

- Vadim Lyubashevsky, [Fiat-Shamir With Aborts: Applications to Lattice and
  Factoring-Based Signatures][lyu-fs-aborts], ASIACRYPT 2009, pp. 598-616,
  DOI: [10.1007/978-3-642-10366-7_35](https://doi.org/10.1007/978-3-642-10366-7_35).
  Use as the foundational Fiat-Shamir-with-aborts citation for lattice
  identification/signature proofs and abort-based distribution hiding.
- Vadim Lyubashevsky, [Lattice Signatures Without Trapdoors][lyu-trapdoors],
  EUROCRYPT 2012, pp. 738-755, DOI:
  [10.1007/978-3-642-29011-4_43](https://doi.org/10.1007/978-3-642-29011-4_43).
  Use for the later lattice-signature-with-aborts framework cited by FIPS 204.
- Dilithium Version 3.1, Section 3 and Section 6. Use Section 3 for the
  signing algorithms and rejection conditions, and Section 6 for the proof
  sketch tying rejection sampling, Fiat-Shamir, UF-CMA/SUF-CMA, and concrete
  security analysis together for centralized Dilithium. This does not close the
  threshold selective-abort channel.

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

Unresolved citation targets:

- See [Unresolved Citation Targets](#unresolved-citation-targets).

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

Unresolved citation targets:

- See [Unresolved Citation Targets](#unresolved-citation-targets).

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

Unresolved citation targets:

- See [Unresolved Citation Targets](#unresolved-citation-targets).

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

Resolved citation targets:

- Oscar Reparaz, Josep Balasch, and Ingrid Verbauwhede, [dude, is my code
  constant time?][dudect-paper], DATE 2017 / IACR ePrint 2016/1123, together
  with the [dudect project documentation][dudect-repo]. Use for the empirical
  timing-leakage methodology based on repeated measurements of two input
  classes and statistical testing of timing distributions. Treat a dudect pass
  as leakage-detection evidence only, not a proof of constant-time behavior.
- Adam Langley's [ctgrind][ctgrind-repo], "Checking that functions are constant
  time with Valgrind." Use for the dynamic-analysis technique that marks secret
  data and checks whether branches or memory addresses depend on tainted secret
  values. Treat ctgrind or Valgrind-style checks as implementation evidence
  with platform/tool limitations, not as a formal side-channel proof.

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

## Unresolved Citation Targets

The following placeholders remain open because the requested documents do not
identify a concrete construction, theorem, parameter statement, or proof-system
instantiation that can be cited without inventing unsupported claims.

Threshold signing and selective aborts:

- [Citation needed: selective-abort or rushing-adversary analysis for threshold
  Fiat-Shamir signing, or a proof that the project-specific abort channel is
  simulatable.]
- [Citation needed: random-oracle programming lemma for multi-domain
  Fiat-Shamir transcripts with prior adversarial queries.]
- [Citation needed: threshold lattice signature or threshold Dilithium/ML-DSA
  signing theorem matching static active corruption.]
- [Citation needed: MPC-in-the-head, proof-carrying contribution, or audited
  MPC signing theorem selected for production partial verification.]
- [Citation needed: ideal-functionality or UC realization reference for
  threshold signing with abort and evidence events, if FST-T2 is claimed in a
  UC-style model.]
- [Citation needed: partial-signature extractability or knowledge-soundness
  theorem for the selected contribution-proof relation.]

VSS/DKG and share secrecy:

- [Citation needed: VSS theorem with binding, hiding, complaint soundness, and
  public verifiability under active corruption.]
- [Citation needed: DKG theorem with key-bias resistance against rushing and
  last-mover behavior.]
- [Citation needed: anti-framing theorem for complaint evidence and private
  share delivery.]
- [Citation needed: threshold share secrecy theorem over the exact algebra or
  ring/module domain used by the selected ML-DSA sharing construction.]

Lattice/vector commitments and proof systems:

- [Citation needed: named lattice/vector commitment construction selected for
  production VSS/DKG or signing commitments.]
- [Citation needed: opening proof system theorem for binding, hiding,
  extractability, and witness hiding over ML-DSA-compatible vectors.]
- [Citation needed: parameter-selection analysis for ML-DSA-65 dimensions,
  modulus `q = 8380417`, norm/range bounds, proof sizes, and concrete security.]
- [Citation needed: canonical serialization or domain-separation result if the
  proof relies on composed hash/XOF domains as independent random oracles.]

Side-channel proof scope beyond dudect and ctgrind:

- [Citation needed: constant-time cryptographic implementation guidance
  accepted for Rust or comparable systems code.]
- [Citation needed: zeroization and compiler-output review guidance for
  production cryptographic implementations.]
- [Citation needed: leakage-resilient or side-channel-aware proof reference if
  any future theorem claims more than a constant-time implementation
  assumption.]

## Citation Closure Checklist

- FIPS 204 section, table, algorithm, encoding, rejection-predicate, verifier,
  and ACVP references are identified above.
- Dilithium design/security references and the FIPS 204 transition from
  CRYSTALS-Dilithium to ML-DSA are identified above. FST-A1 still needs a final
  manuscript decision on exactly how to phrase the base ML-DSA-65
  unforgeability assumption and whether the claim is ROM, QROM, or a
  FIPS-accepted security-interpretation statement.
- The centralized Fiat-Shamir-with-aborts citation chain is identified above.
  Threshold selective-abort simulation and multi-domain random-oracle
  programming remain unresolved.
- Select or cite a threshold ML-DSA, threshold Dilithium, or MPC signing theorem
  that supports static active corruption, partial contribution verification,
  aggregation, and real/ideal simulation.
- Select the production VSS/DKG backend and cite binding, hiding,
  extractability, complaint soundness, anti-framing, and key-bias resistance
  theorems for that exact backend.
- Select the lattice/vector commitment and opening-proof construction, then
  cite its parameter-specific security analysis for the ML-DSA-65 algebra and
  serialization.
- dudect and ctgrind methodology citations are identified above. The broader
  leakage model, zeroization, compiler-output inspection, and any
  leakage-resilient proof citation remain unresolved.
- For every `[Citation needed: ...]` placeholder in the unresolved list, either
  replace it with a precise citation and theorem/section pointer or leave the
  corresponding theorem document phrased as an open assumption, target, or
  non-claim.
- Re-run the proof-package claim review after citation closure and update
  `claims-matrix.md` only if the external result, local proof mapping, and
  implementation/audit evidence all support stronger wording.

[acvp-mldsa]: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
[ctgrind-repo]: https://github.com/agl/ctgrind
[dilithium-tches]: https://doi.org/10.13154/tches.v2018.i1.238-268
[dilithium-v31]: https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
[dudect-paper]: https://eprint.iacr.org/2016/1123
[dudect-repo]: https://github.com/oreparaz/dudect
[fips204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
[kls-qrom]: https://www.iacr.org/archive/eurocrypt2018/10822196/10822196.pdf
[lyu-fs-aborts]: https://www.iacr.org/archive/asiacrypt2009/59120596/59120596.pdf
[lyu-trapdoors]: https://doi.org/10.1007/978-3-642-29011-4_43
