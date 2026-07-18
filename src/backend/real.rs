//! Real ML-DSA-65 backend (hazmat / research).
//!
//! # Construction
//!
//! `RealMldsa65Backend` provides standard ML-DSA-65 expand/sign/verify helpers
//! used by the P1 [`super::threshold_core::ThresholdMldsaEngine`]:
//!
//! 1. Seed-share reconstruction and full-seed signing.
//! 2. Optional FIPS `Sign_internal` with distributed-nonce `rnd`.
//! 3. Unmodified standard verification (`verify_with_context`).
//!
//! For live nonce DKG, binding VSS, partial share contributions, aggregation,
//! and rejection loops, use [`super::threshold_core`].
//!
//! # Claim boundary
//!
//! - Produces standard-size ML-DSA-65 signatures (3,309 bytes) accepted by
//!   `ml-dsa` verification when inputs are well-formed.
//! - Seed-layer partials are in `threshold_core`; module-vector
//!   `z = y + c*s1` over `R_q^L` is in `module_partial`, and the strict
//!   `fips_sign` path can assemble `s1/y` partials into an accepted FIPS wire
//!   signature for the research execution committee.
//! - Formal proofs and external audits remain open
//!   (`docs/cryptography/blocker-closure-status.md`).
//! - Feature-gated (`raw-real-mldsa`); not production-approved.

use core::fmt;

use ml_dsa::{
    EncodedVerifyingKey, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, VerifyingKey,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

use crate::{
    collections::PartialShareSet,
    errors::ThresholdError,
    transcript::SigningTranscript,
    types::{
        Commitment, PartialSignatureShare, PrivateKeyShare, ThresholdPublicKey, ThresholdSignature,
        ValidatorId, MLDSA65_PUBLICKEY_BYTES, MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES,
    },
    SignatureAggregator,
};

/// Default domain separator for deterministic seed-share derivation.
pub const SEED_SHARE_DOMAIN_DEFAULT: &[u8] = b"lattice-aggregation/real-mldsa65/seed-share/v1";

const COMMITMENT_LABEL: &[u8] = b"lattice-aggregation/real-mldsa65/commitment/v1";
const SHARE_PARTIAL_MAGIC: &[u8; 4] = b"LRSS"; // Lattice Real Seed Share
const SHARE_PARTIAL_VERSION: u16 = 1;
const TAG_FULL_SEED: u8 = 0x01;
const TAG_SEED_SHARE: u8 = 0x02;
/// ML-DSA prime modulus `q` as `u64` for share arithmetic.
const Q: u64 = 8_380_417;

/// Construction label bound into artifacts and docs for this backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RealMldsaConstruction {
    /// Shamir seed reconstruction then standard ML-DSA-65 sign/verify.
    ThresholdSeedReconstruction,
}

impl RealMldsaConstruction {
    /// Stable reader-facing construction name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ThresholdSeedReconstruction => {
                "threshold seed reconstruction → standard ML-DSA-65"
            }
        }
    }

    /// Machine-readable core-mode string (aligned with P1 capture vocabulary).
    pub const fn core_mode(self) -> &'static str {
        match self {
            Self::ThresholdSeedReconstruction => "threshold_seed_reconstruction_mldsa65_provider",
        }
    }
}

/// Secret retained between commitment derivation and partial emission.
pub struct RealCommitmentSecret {
    material: Vec<u8>,
}

impl RealCommitmentSecret {
    fn from_material(material: Vec<u8>) -> Self {
        Self { material }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.material
    }
}

impl fmt::Debug for RealCommitmentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealCommitmentSecret")
            .field("redacted", &true)
            .field("len", &self.material.len())
            .finish()
    }
}

impl Zeroize for RealCommitmentSecret {
    fn zeroize(&mut self) {
        self.material.zeroize();
    }
}

impl Drop for RealCommitmentSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Real ML-DSA-65 backend using seed-share reconstruction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealMldsa65Backend;

impl RealMldsa65Backend {
    /// Construction implemented by this backend.
    pub const fn construction() -> RealMldsaConstruction {
        RealMldsaConstruction::ThresholdSeedReconstruction
    }

    /// Expand a 32-byte seed into an ML-DSA-65 threshold public key.
    pub fn public_key_from_seed(
        seed: &[u8; POLY_SEED_BYTES],
    ) -> Result<ThresholdPublicKey, ThresholdError> {
        let signing_key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
        encoded_verifying_key_to_threshold(&signing_key.verifying_key().encode())
    }

    /// Encode a full 32-byte seed as a coordinator/local key share secret.
    pub fn encode_full_seed_share(
        share_id: ValidatorId,
        seed: &[u8; POLY_SEED_BYTES],
    ) -> PrivateKeyShare {
        let mut secret = Vec::with_capacity(1 + POLY_SEED_BYTES);
        secret.push(TAG_FULL_SEED);
        secret.extend_from_slice(seed);
        PrivateKeyShare::new(share_id, secret)
    }

    /// Split a seed into Shamir seed-shares for a validator set.
    ///
    /// Each validator receives a share with x-coordinate equal to
    /// `validator_id + 1` (so `ValidatorId(0)` is valid). Higher-degree
    /// coefficients are derived from domain-separated SHAKE256 of the seed.
    pub fn split_seed_shares(
        seed: &[u8; POLY_SEED_BYTES],
        threshold: u16,
        validators: &[ValidatorId],
        domain: &[u8],
    ) -> Result<(ThresholdPublicKey, Vec<PrivateKeyShare>), ThresholdError> {
        let total = validators.len() as u16;
        if threshold == 0 || threshold > total || validators.is_empty() {
            return Err(ThresholdError::InvalidThresholdParameters {
                threshold,
                total_nodes: total,
            });
        }

        let mut seen = std::collections::BTreeSet::new();
        for validator in validators {
            if !seen.insert(*validator) {
                return Err(ThresholdError::DuplicateValidator {
                    validator: *validator,
                });
            }
        }

        let public_key = Self::public_key_from_seed(seed)?;
        let mut shares = Vec::with_capacity(validators.len());

        for validator in validators {
            let x = x_coordinate_for(*validator);
            let mut elements = [0u64; POLY_SEED_BYTES];
            for (byte_index, element) in elements.iter_mut().enumerate() {
                *element = evaluate_seed_share_poly(seed, domain, byte_index, threshold, x);
            }
            shares.push(PrivateKeyShare::new(
                *validator,
                encode_seed_share_secret(x, &elements),
            ));
        }

        Ok((public_key, shares))
    }

    /// Sign a message with a full-seed key share (centralized / coordinator path).
    pub fn sign_with_full_seed(
        key_share: &PrivateKeyShare,
        message: &[u8],
    ) -> Result<(ThresholdPublicKey, ThresholdSignature), ThresholdError> {
        let seed = decode_full_seed(key_share.secret())?;
        Self::sign_from_seed(&seed, message, None)
    }

    /// Sign with an optional 32-byte FIPS `rnd` (nonce) for Sign_internal.
    ///
    /// When `rnd` is `Some`, uses ML-DSA `Sign_internal` so distributed nonce
    /// material binds into the FIPS rejection loop. When `None`, uses the
    /// ordinary `Signer::sign` path.
    pub fn sign_from_seed(
        seed: &[u8; POLY_SEED_BYTES],
        message: &[u8],
        rnd: Option<&[u8; POLY_SEED_BYTES]>,
    ) -> Result<(ThresholdPublicKey, ThresholdSignature), ThresholdError> {
        let signing_key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
        let public_key = encoded_verifying_key_to_threshold(&signing_key.verifying_key().encode())?;
        let signature = if let Some(rnd_bytes) = rnd {
            // Match FIPS external empty-context encoding so verify_with_context
            // accepts the signature: mu = H(tr || 0x00 || |ctx|=0 || M).
            let domain = [0u8];
            let ctx_len = [0u8];
            let sig = signing_key
                .expanded_key()
                .sign_internal(&[&domain, &ctx_len, message], &(*rnd_bytes).into());
            signature_to_threshold(&sig.to_bytes())?
        } else {
            signature_to_threshold(&signing_key.sign(message).to_bytes())?
        };
        Ok((public_key, signature))
    }
}

impl crate::backend::Mldsa65Backend for RealMldsa65Backend {
    type Error = ThresholdError;
    type KeyShare = PrivateKeyShare;
    type CommitmentSecret = RealCommitmentSecret;

    fn derive_commitment(
        key_share: &Self::KeyShare,
        transcript: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error> {
        let material = key_share.secret().to_vec();
        validate_key_material(&material)?;

        let mut hasher = Shake256::default();
        hasher.update(COMMITMENT_LABEL);
        update_bytes(&mut hasher, &material);
        hasher.update(&key_share.share_id.0.to_be_bytes());
        hasher.update(&transcript.challenge().0);
        update_bytes(&mut hasher, transcript.message());

        let mut commitment = [0u8; 32];
        hasher.finalize_xof().read(&mut commitment);

        Ok((
            Commitment(commitment),
            RealCommitmentSecret::from_material(material),
        ))
    }

    fn partial_sign(
        share: &Self::KeyShare,
        mut secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error> {
        if secret.as_bytes() != share.secret() {
            secret.zeroize();
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: share.share_id,
            });
        }

        let bytes = encode_partial_payload(share.share_id, secret.as_bytes(), transcript)?;
        secret.zeroize();

        Ok(PartialSignatureShare {
            signer: share.share_id,
            bytes,
        })
    }

    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        if public_key != transcript.public_key() {
            return Err(ThresholdError::TranscriptMismatch);
        }
        if shares.threshold() != transcript.threshold() {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let mut decoded = Vec::with_capacity(shares.len());
        for (validator, share) in shares.iter() {
            let payload = decode_partial_payload(&share.bytes, transcript)?;
            if payload.signer != *validator {
                return Err(ThresholdError::PartialShareVerificationFailed {
                    validator: *validator,
                });
            }
            decoded.push(payload);
        }

        let seed = reconstruct_seed_from_partials(&decoded, transcript.threshold())?;
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let derived_pk = encoded_verifying_key_to_threshold(&signing_key.verifying_key().encode())?;
        if &derived_pk != public_key {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let signature = signature_to_threshold(&signing_key.sign(transcript.message()).to_bytes())?;
        if !Self::verify_standard(public_key, transcript.message(), &signature)? {
            return Err(ThresholdError::StandardVerificationFailed);
        }

        Ok(signature)
    }

    fn verify_standard(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error> {
        let Some((verifying_key, sig)) = decode_verifier_inputs(public_key, signature) else {
            return Ok(false);
        };
        Ok(verifying_key.verify_with_context(message, &[], &sig))
    }
}

/// Aggregator that uses [`RealMldsa65Backend`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealAggregator;

impl SignatureAggregator for RealAggregator {
    type Error = ThresholdError;

    fn aggregate_shares(
        transcript: crate::transcript::ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        crate::aggregation::aggregate_with_backend::<RealMldsa65Backend>(transcript, partial_shares)
    }
}

#[derive(Clone)]
struct DecodedPartial {
    signer: ValidatorId,
    material: Vec<u8>,
}

impl Drop for DecodedPartial {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

fn x_coordinate_for(validator: ValidatorId) -> u16 {
    // Map ValidatorId(u16) → nonzero field evaluation point.
    validator.0.wrapping_add(1)
}

fn encode_seed_share_secret(x: u16, elements: &[u64; POLY_SEED_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + POLY_SEED_BYTES * 8);
    out.push(TAG_SEED_SHARE);
    out.extend_from_slice(&x.to_be_bytes());
    for element in elements {
        out.extend_from_slice(&element.to_be_bytes());
    }
    out
}

fn validate_key_material(material: &[u8]) -> Result<(), ThresholdError> {
    match material.first().copied() {
        Some(TAG_FULL_SEED) if material.len() == 1 + POLY_SEED_BYTES => Ok(()),
        Some(TAG_SEED_SHARE) if material.len() == 1 + 2 + POLY_SEED_BYTES * 8 => Ok(()),
        _ => Err(ThresholdError::BackendUnavailable {
            reason: "real ML-DSA backend key material is malformed",
        }),
    }
}

fn decode_full_seed(material: &[u8]) -> Result<[u8; POLY_SEED_BYTES], ThresholdError> {
    validate_key_material(material)?;
    if material[0] != TAG_FULL_SEED {
        return Err(ThresholdError::BackendUnavailable {
            reason: "expected full-seed key material for centralized sign",
        });
    }
    let mut seed = [0u8; POLY_SEED_BYTES];
    seed.copy_from_slice(&material[1..]);
    Ok(seed)
}

fn decode_seed_share(material: &[u8]) -> Result<(u16, [u64; POLY_SEED_BYTES]), ThresholdError> {
    validate_key_material(material)?;
    if material[0] != TAG_SEED_SHARE {
        return Err(ThresholdError::BackendUnavailable {
            reason: "expected Shamir seed-share key material",
        });
    }
    let x = u16::from_be_bytes([material[1], material[2]]);
    if x == 0 {
        return Err(ThresholdError::BackendUnavailable {
            reason: "seed-share x-coordinate must be nonzero",
        });
    }
    let mut elements = [0u64; POLY_SEED_BYTES];
    for (index, element) in elements.iter_mut().enumerate() {
        let start = 3 + index * 8;
        let mut word = [0u8; 8];
        word.copy_from_slice(&material[start..start + 8]);
        *element = u64::from_be_bytes(word);
        if *element >= Q {
            return Err(ThresholdError::BackendUnavailable {
                reason: "seed-share field element is out of range",
            });
        }
    }
    Ok((x, elements))
}

fn encode_partial_payload(
    signer: ValidatorId,
    material: &[u8],
    transcript: &SigningTranscript,
) -> Result<Vec<u8>, ThresholdError> {
    validate_key_material(material)?;
    let mut out = Vec::with_capacity(4 + 2 + 2 + 32 + material.len());
    out.extend_from_slice(SHARE_PARTIAL_MAGIC);
    out.extend_from_slice(&SHARE_PARTIAL_VERSION.to_be_bytes());
    out.extend_from_slice(&signer.0.to_be_bytes());
    out.extend_from_slice(&transcript.challenge().0);
    out.extend_from_slice(material);
    Ok(out)
}

fn decode_partial_payload(
    bytes: &[u8],
    transcript: &SigningTranscript,
) -> Result<DecodedPartial, ThresholdError> {
    if bytes.len() < 4 + 2 + 2 + 32 + 1 {
        return Err(ThresholdError::MalformedSerialization {
            reason: "real partial share is truncated",
        });
    }
    if &bytes[0..4] != SHARE_PARTIAL_MAGIC {
        return Err(ThresholdError::MalformedSerialization {
            reason: "real partial share magic mismatch",
        });
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != SHARE_PARTIAL_VERSION {
        return Err(ThresholdError::MalformedSerialization {
            reason: "real partial share version unsupported",
        });
    }
    let signer = ValidatorId(u16::from_be_bytes([bytes[6], bytes[7]]));
    let challenge = &bytes[8..40];
    if challenge != transcript.challenge().0 {
        return Err(ThresholdError::TranscriptMismatch);
    }
    let material = bytes[40..].to_vec();
    validate_key_material(&material)?;
    Ok(DecodedPartial { signer, material })
}

fn reconstruct_seed_from_partials(
    partials: &[DecodedPartial],
    threshold: u16,
) -> Result<[u8; POLY_SEED_BYTES], ThresholdError> {
    if partials.len() < threshold as usize {
        return Err(ThresholdError::InsufficientPartialShares {
            required: threshold,
            received: partials.len(),
        });
    }

    // Prefer full-seed material if present (coordinator short-circuit).
    for partial in partials {
        if partial.material.first() == Some(&TAG_FULL_SEED) {
            return decode_full_seed(&partial.material);
        }
    }

    let mut points: Vec<(u16, [u64; POLY_SEED_BYTES])> = Vec::with_capacity(partials.len());
    let mut xs = std::collections::BTreeSet::new();
    for partial in partials.iter().take(threshold as usize) {
        let (x, elements) = decode_seed_share(&partial.material)?;
        if !xs.insert(x) {
            return Err(ThresholdError::DuplicateValidator {
                validator: partial.signer,
            });
        }
        points.push((x, elements));
    }

    let active_xs: Vec<u16> = points.iter().map(|(x, _)| *x).collect();
    let mut seed = [0u8; POLY_SEED_BYTES];
    for byte_index in 0..POLY_SEED_BYTES {
        let mut acc = 0u64;
        for (x, elements) in &points {
            let lambda = lagrange_at_zero(&active_xs, *x)?;
            acc = mod_add(acc, mod_mul(lambda, elements[byte_index]));
        }
        if acc > 255 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "reconstructed seed byte is not a canonical u8 field element",
            });
        }
        seed[byte_index] = acc as u8;
    }
    Ok(seed)
}

fn evaluate_seed_share_poly(
    seed: &[u8; POLY_SEED_BYTES],
    domain: &[u8],
    byte_index: usize,
    threshold: u16,
    x: u16,
) -> u64 {
    // P(x) = s + a_1 x + a_2 x^2 + ... + a_{t-1} x^{t-1}  (mod q)
    let mut acc = u64::from(seed[byte_index]) % Q;
    let mut x_pow = 1u64;
    for degree in 1..threshold {
        x_pow = mod_mul(x_pow, u64::from(x));
        let coeff = derive_share_coefficient(seed, domain, byte_index, degree);
        acc = mod_add(acc, mod_mul(coeff, x_pow));
    }
    acc
}

fn derive_share_coefficient(
    seed: &[u8; POLY_SEED_BYTES],
    domain: &[u8],
    byte_index: usize,
    degree: u16,
) -> u64 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(b"coeff");
    hasher.update(&(byte_index as u64).to_be_bytes());
    hasher.update(&degree.to_be_bytes());
    hasher.update(seed);
    let mut wide = [0u8; 16];
    hasher.finalize_xof().read(&mut wide);
    let value = u128::from_be_bytes(wide);
    (value % u128::from(Q)) as u64
}

fn lagrange_at_zero(active_xs: &[u16], current_x: u16) -> Result<u64, ThresholdError> {
    let mut numerator = 1u64;
    let mut denominator = 1u64;
    for &peer in active_xs {
        if peer == current_x {
            continue;
        }
        numerator = mod_mul(numerator, u64::from(peer));
        let diff = mod_sub(u64::from(peer), u64::from(current_x));
        denominator = mod_mul(denominator, diff);
    }
    let inv = mod_inv(denominator)?;
    Ok(mod_mul(numerator, inv))
}

fn mod_add(a: u64, b: u64) -> u64 {
    (a + b) % Q
}

fn mod_sub(a: u64, b: u64) -> u64 {
    (a + Q - (b % Q)) % Q
}

fn mod_mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(Q)) as u64
}

fn mod_inv(value: u64) -> Result<u64, ThresholdError> {
    if value.is_multiple_of(Q) {
        return Err(ThresholdError::BackendUnavailable {
            reason: "modular inverse of zero in seed reconstruction",
        });
    }
    // Fermat: a^(q-2) mod q
    Ok(mod_pow(value % Q, Q - 2))
}

fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    result
}

fn encoded_verifying_key_to_threshold(
    encoded: &impl AsRef<[u8]>,
) -> Result<ThresholdPublicKey, ThresholdError> {
    let slice = encoded.as_ref();
    if slice.len() != MLDSA65_PUBLICKEY_BYTES {
        return Err(ThresholdError::BackendUnavailable {
            reason: "unexpected ML-DSA-65 public key length",
        });
    }
    let mut bytes = [0u8; MLDSA65_PUBLICKEY_BYTES];
    bytes.copy_from_slice(slice);
    Ok(ThresholdPublicKey(bytes))
}

fn signature_to_threshold(
    encoded: &impl AsRef<[u8]>,
) -> Result<ThresholdSignature, ThresholdError> {
    let slice = encoded.as_ref();
    if slice.len() != MLDSA65_SIGNATURE_BYTES {
        return Err(ThresholdError::BackendUnavailable {
            reason: "unexpected ML-DSA-65 signature length",
        });
    }
    let mut bytes = [0u8; MLDSA65_SIGNATURE_BYTES];
    bytes.copy_from_slice(slice);
    Ok(ThresholdSignature(bytes))
}

fn decode_verifier_inputs(
    public_key: &ThresholdPublicKey,
    signature: &ThresholdSignature,
) -> Option<(VerifyingKey<MlDsa65>, Signature<MlDsa65>)> {
    let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.0.as_slice()).ok()?;
    let signature = Signature::<MlDsa65>::try_from(signature.0.as_slice()).ok()?;
    Some((VerifyingKey::<MlDsa65>::new(&encoded_key), signature))
}

fn update_bytes(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::Mldsa65Backend, collections::CommitmentSet, transcript::SigningTranscript,
    };

    #[test]
    fn construction_labels_are_stable() {
        assert_eq!(
            RealMldsa65Backend::construction().core_mode(),
            "threshold_seed_reconstruction_mldsa65_provider"
        );
    }

    #[test]
    fn full_seed_sign_and_verify_round_trip() {
        let seed = [0x11; 32];
        let share = RealMldsa65Backend::encode_full_seed_share(ValidatorId(1), &seed);
        let message = b"real-backend centralized smoke";
        let (public_key, signature) =
            RealMldsa65Backend::sign_with_full_seed(&share, message).unwrap();
        assert!(RealMldsa65Backend::verify_standard(&public_key, message, &signature).unwrap());
        assert!(!RealMldsa65Backend::verify_standard(&public_key, b"mutated", &signature).unwrap());
    }

    #[test]
    fn threshold_seed_reconstruction_produces_verifying_signature() {
        let seed = [0xA5; 32];
        let validators = vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)];
        let threshold = 2;
        let (public_key, key_shares) = RealMldsa65Backend::split_seed_shares(
            &seed,
            threshold,
            &validators,
            SEED_SHARE_DOMAIN_DEFAULT,
        )
        .unwrap();

        let session_id = [0x5Au8; 32];
        let message = b"threshold seed reconstruction aggregate";

        // Commitments for transcript (use a single-share precommit style).
        let mut commitments = Vec::new();
        let mut secrets = Vec::new();
        for share in &key_shares[..threshold as usize] {
            let precommit = CommitmentSet::new(
                validators.clone(),
                1,
                vec![(share.share_id, Commitment([0; 32]))],
            )
            .unwrap();
            let pre_tx = SigningTranscript::new(
                session_id,
                1,
                validators.clone(),
                public_key.clone(),
                b"precommit",
                precommit,
            )
            .unwrap();
            let (commitment, secret) =
                RealMldsa65Backend::derive_commitment(share, &pre_tx).unwrap();
            commitments.push((share.share_id, commitment));
            secrets.push((share, secret));
        }

        let commitment_set =
            CommitmentSet::new(validators.clone(), threshold, commitments).unwrap();
        let transcript = SigningTranscript::new(
            session_id,
            threshold,
            validators.clone(),
            public_key.clone(),
            message,
            commitment_set,
        )
        .unwrap();

        let mut partials = Vec::new();
        for (share, secret) in secrets {
            // Re-derive on the real transcript challenge binding via partial_sign path:
            // Commitment secrets were derived on precommit transcript; re-bind by
            // deriving again on the real transcript for production-faithful flow.
            let (_c, rebound) = RealMldsa65Backend::derive_commitment(share, &transcript).unwrap();
            let partial = RealMldsa65Backend::partial_sign(share, rebound, &transcript).unwrap();
            // silence unused secret from precommit
            drop(secret);
            partials.push(partial);
        }

        let share_set = PartialShareSet::new(validators, threshold, partials).unwrap();
        let signature = RealMldsa65Backend::aggregate(&public_key, &transcript, share_set).unwrap();

        assert_eq!(signature.0.len(), MLDSA65_SIGNATURE_BYTES);
        assert!(RealMldsa65Backend::verify_standard(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn share_reconstruction_matches_seed_public_key() {
        let seed = [0x42; 32];
        let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
        let (public_key, shares) =
            RealMldsa65Backend::split_seed_shares(&seed, 2, &validators, SEED_SHARE_DOMAIN_DEFAULT)
                .unwrap();
        let expected = RealMldsa65Backend::public_key_from_seed(&seed).unwrap();
        assert_eq!(public_key, expected);
        assert_eq!(shares.len(), 3);
    }
}
