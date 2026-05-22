//! Validated canonical collections for protocol inputs.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    errors::ThresholdError,
    types::{Commitment, PartialSignatureShare, ValidatorId},
};

/// Canonical set of commitments keyed by validator ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentSet {
    validator_set: BTreeSet<ValidatorId>,
    threshold: u16,
    commitments: BTreeMap<ValidatorId, Commitment>,
}

impl CommitmentSet {
    /// Validate and canonicalize network-provided commitments.
    pub fn new(
        validators: Vec<ValidatorId>,
        threshold: u16,
        commitments: Vec<(ValidatorId, Commitment)>,
    ) -> Result<Self, ThresholdError> {
        validate_threshold(threshold, validators.len() as u16)?;
        let validator_set = set_from_validators(validators)?;

        let mut ordered = BTreeMap::new();
        for (validator, commitment) in commitments {
            if !validator_set.contains(&validator) {
                return Err(ThresholdError::UnknownValidator { validator });
            }

            if ordered.insert(validator, commitment).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator });
            }
        }

        if ordered.len() < threshold as usize {
            return Err(ThresholdError::InsufficientCommitments {
                required: threshold,
                received: ordered.len(),
            });
        }

        Ok(Self {
            validator_set,
            threshold,
            commitments: ordered,
        })
    }

    /// Iterate commitments in canonical validator order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &Commitment)> {
        self.commitments.iter()
    }

    /// Return the commitment for a validator if one was supplied.
    pub fn get(&self, validator: ValidatorId) -> Option<&Commitment> {
        self.commitments.get(&validator)
    }

    /// Return the configured threshold.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the number of commitments in the set.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Return `true` when no commitments exist.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    /// Return `true` when the validator is in the configured validator set.
    pub fn contains_validator(&self, validator: ValidatorId) -> bool {
        self.validator_set.contains(&validator)
    }

    pub(crate) fn validators(&self) -> &BTreeSet<ValidatorId> {
        &self.validator_set
    }
}

/// Canonical set of partial signature shares keyed by validator ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialShareSet {
    shares: BTreeMap<ValidatorId, PartialSignatureShare>,
}

impl PartialShareSet {
    /// Validate and canonicalize partial signature shares.
    pub fn new(
        validators: Vec<ValidatorId>,
        threshold: u16,
        shares: Vec<PartialSignatureShare>,
    ) -> Result<Self, ThresholdError> {
        validate_threshold(threshold, validators.len() as u16)?;
        let validator_set = set_from_validators(validators)?;

        let mut ordered = BTreeMap::new();
        for share in shares {
            let signer = share.signer;
            if !validator_set.contains(&signer) {
                return Err(ThresholdError::UnknownValidator { validator: signer });
            }

            if ordered.insert(signer, share).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator: signer });
            }
        }

        if ordered.len() < threshold as usize {
            return Err(ThresholdError::InsufficientPartialShares {
                required: threshold,
                received: ordered.len(),
            });
        }

        Ok(Self { shares: ordered })
    }

    /// Iterate shares in canonical validator order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &PartialSignatureShare)> {
        self.shares.iter()
    }

    /// Return the number of partial shares in the set.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Return `true` when no partial shares exist.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }
}

/// Validated DKG share commitments.
pub type ValidatedDkgShares = CommitmentSet;

/// Validate threshold parameters against the configured validator count.
pub(crate) fn validate_threshold(threshold: u16, total_nodes: u16) -> Result<(), ThresholdError> {
    if threshold == 0 || threshold > total_nodes {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes,
        });
    }

    Ok(())
}

/// Canonicalize validators into a set and reject duplicate IDs.
pub(crate) fn set_from_validators(
    validators: Vec<ValidatorId>,
) -> Result<BTreeSet<ValidatorId>, ThresholdError> {
    let mut set = BTreeSet::new();
    for validator in validators {
        if !set.insert(validator) {
            return Err(ThresholdError::DuplicateValidator { validator });
        }
    }

    Ok(set)
}
