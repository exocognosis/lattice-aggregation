//! Epsilon residual accounting for coordinator-assisted conformance gates.

use crate::ThresholdError;

/// Deterministic fixed-point epsilon unit used in tests and transcripts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EpsilonUnit(u64);

impl EpsilonUnit {
    /// Zero epsilon budget.
    pub const ZERO: Self = Self(0);

    /// Construct from deterministic ledger units.
    pub const fn from_units(units: u64) -> Self {
        Self(units)
    }

    /// Return raw deterministic ledger units.
    pub const fn units(self) -> u64 {
        self.0
    }
}

/// Residual ledger for public conformance accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EpsilonLedger {
    epsilon_mask: EpsilonUnit,
    epsilon_rej: EpsilonUnit,
    epsilon_withhold: EpsilonUnit,
}

impl EpsilonLedger {
    /// Return the Renyi-divergence masking residual budget.
    pub const fn epsilon_mask(self) -> EpsilonUnit {
        self.epsilon_mask
    }

    /// Return the rejection/abort residual budget.
    pub const fn epsilon_rej(self) -> EpsilonUnit {
        self.epsilon_rej
    }

    /// Return the withholding residual budget.
    pub const fn epsilon_withhold(self) -> EpsilonUnit {
        self.epsilon_withhold
    }

    /// Increment the Renyi-divergence masking residual.
    pub fn increment_mask(&mut self, amount: EpsilonUnit) {
        self.epsilon_mask = EpsilonUnit(self.epsilon_mask.0.saturating_add(amount.0));
    }

    /// Increment the public rejection residual.
    pub fn increment_rejection(&mut self, amount: EpsilonUnit) {
        self.epsilon_rej = EpsilonUnit(self.epsilon_rej.0.saturating_add(amount.0));
    }

    /// Increment the public withholding residual.
    pub fn increment_withholding(&mut self, amount: EpsilonUnit) {
        self.epsilon_withhold = EpsilonUnit(self.epsilon_withhold.0.saturating_add(amount.0));
    }
}

/// Conformance parameters for asymmetric noise flooding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoiseFloodingParameters {
    beta: u32,
    gaussian_sigma_bound: u32,
    renyi_epsilon_increment: EpsilonUnit,
}

impl NoiseFloodingParameters {
    /// Construct parameters, enforcing `sigma <= beta / 4`.
    pub fn new(
        beta: u32,
        gaussian_sigma_bound: u32,
        renyi_epsilon_increment: EpsilonUnit,
    ) -> Result<Self, ThresholdError> {
        if gaussian_sigma_bound > beta / 4 {
            return Err(ThresholdError::InvalidNoiseFloodingParameters {
                reason: "gaussian sigma bound exceeds beta / 4",
            });
        }
        Ok(Self {
            beta,
            gaussian_sigma_bound,
            renyi_epsilon_increment,
        })
    }

    /// Return beta bound.
    pub const fn beta(self) -> u32 {
        self.beta
    }

    /// Return configured Gaussian sigma upper bound.
    pub const fn gaussian_sigma_bound(self) -> u32 {
        self.gaussian_sigma_bound
    }

    /// Return the Renyi epsilon increment supplied by the reviewed backend.
    pub const fn renyi_epsilon_increment(self) -> EpsilonUnit {
        self.renyi_epsilon_increment
    }
}
