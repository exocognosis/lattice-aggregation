//! One-time preprocessing attempt state.

use std::collections::{hash_map::Entry, HashMap};

use zeroize::Zeroize;

use crate::ThresholdError;

use super::{prefilter::ShareReleaseAuthorization, types::AttemptId};

/// Single-use preprocessed attempt material.
pub struct PreprocessedAttempt {
    attempt_id: AttemptId,
    secret_material: Vec<u8>,
}

impl core::fmt::Debug for PreprocessedAttempt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let secret_material_redacted = !self.secret_material().is_empty();
        f.debug_struct("PreprocessedAttempt")
            .field("attempt_id", &self.attempt_id)
            .field("secret_material_redacted", &secret_material_redacted)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        production::{
            epsilon::{EpsilonLedger, EpsilonUnit},
            prefilter::{BlindedCommitmentSummary, BlindedPreFilter, PreFilterOutcome},
        },
        ValidatorId,
    };

    use super::{AttemptId, PreprocessedAttempt, PreprocessingStore, ThresholdError};

    fn authorization_for(attempt_id: AttemptId) -> super::ShareReleaseAuthorization {
        let mut ledger = EpsilonLedger::default();
        match BlindedPreFilter::evaluate(
            attempt_id,
            10,
            EpsilonUnit::from_units(1),
            vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 5)],
            &mut ledger,
        )
        .unwrap()
        {
            PreFilterOutcome::Passed(token) => token.into_share_release_authorization(),
            PreFilterOutcome::Aborted(_) => panic!("expected pass"),
        }
    }

    #[test]
    fn duplicate_attempt_does_not_replace_existing_secret_material() {
        let first = PreprocessedAttempt::new(AttemptId([9; 32]), vec![1, 2, 3]).unwrap();
        let duplicate = PreprocessedAttempt::new(AttemptId([9; 32]), vec![9, 9, 9]).unwrap();
        let mut store = PreprocessingStore::default();
        store.insert(first).unwrap();

        assert_eq!(
            store.insert(duplicate).unwrap_err(),
            ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt already exists",
            }
        );

        let consumed = store
            .consume(authorization_for(AttemptId([9; 32])))
            .unwrap();
        assert_eq!(consumed.secret_material(), &[1, 2, 3]);
    }

    #[test]
    fn debug_output_redacts_secret_material() {
        let attempt = PreprocessedAttempt::new(AttemptId([10; 32]), vec![4, 5, 6]).unwrap();
        let mut store = PreprocessingStore::default();
        store
            .insert(PreprocessedAttempt::new(AttemptId([11; 32]), vec![4, 5, 6]).unwrap())
            .unwrap();

        let attempt_debug = format!("{attempt:?}");
        let store_debug = format!("{store:?}");
        assert!(attempt_debug.contains("secret_material_redacted"));
        assert!(store_debug.contains("secret_material_redacted"));
        assert!(!attempt_debug.contains("4, 5, 6"));
        assert!(!store_debug.contains("4, 5, 6"));
    }

    #[test]
    fn abort_and_zeroize_clears_secret_material() {
        let mut attempt = PreprocessedAttempt::new(AttemptId([12; 32]), vec![9, 8, 7]).unwrap();
        attempt.abort_and_zeroize();
        assert_eq!(attempt.secret_material(), &[0, 0, 0]);
    }
}

impl Drop for PreprocessedAttempt {
    fn drop(&mut self) {
        self.secret_material.zeroize();
    }
}

impl PreprocessedAttempt {
    /// Construct attempt state.
    pub fn new(attempt_id: AttemptId, secret_material: Vec<u8>) -> Result<Self, ThresholdError> {
        if secret_material.is_empty() {
            return Err(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt secret material is empty",
            });
        }
        Ok(Self {
            attempt_id,
            secret_material,
        })
    }

    /// Return attempt ID.
    pub fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Zeroize attempt-local secret material after an abort gate.
    pub fn abort_and_zeroize(&mut self) {
        self.secret_material.as_mut_slice().zeroize();
    }

    /// Borrow secret material for backend use.
    pub(crate) fn secret_material(&self) -> &[u8] {
        &self.secret_material
    }
}

/// In-memory one-time attempt store.
#[derive(Debug, Default)]
pub struct PreprocessingStore {
    attempts: HashMap<AttemptId, PreprocessedAttempt>,
}

impl PreprocessingStore {
    /// Insert one attempt.
    pub fn insert(&mut self, attempt: PreprocessedAttempt) -> Result<(), ThresholdError> {
        let attempt_id = attempt.attempt_id();
        match self.attempts.entry(attempt_id) {
            Entry::Vacant(slot) => {
                slot.insert(attempt);
                Ok(())
            }
            Entry::Occupied(_) => Err(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt already exists",
            }),
        }
    }

    /// Consume an attempt exactly once.
    pub fn consume(
        &mut self,
        authorization: ShareReleaseAuthorization,
    ) -> Result<PreprocessedAttempt, ThresholdError> {
        let attempt_id = authorization.attempt_id();
        self.attempts
            .remove(&attempt_id)
            .ok_or(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt is unknown or already consumed",
            })
    }
}
