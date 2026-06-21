//! Coordinator-assisted production-candidate ML-DSA-65 profile.
//!
//! This module is gated and does not make a production-readiness claim. It
//! contains typed boundaries for future reviewed ML-DSA-65 threshold signing.

#[cfg(feature = "coordinator-assisted")]
pub mod abort_bias;
#[cfg(feature = "coordinator-assisted")]
pub mod acceptance;
#[cfg(feature = "coordinator-assisted")]
pub mod coordinator;
#[cfg(feature = "coordinator-assisted")]
pub mod epsilon;
#[cfg(feature = "coordinator-assisted")]
pub mod evidence;
#[cfg(feature = "coordinator-assisted")]
pub mod hints;
#[cfg(feature = "coordinator-assisted")]
pub mod mask_distribution;
#[cfg(feature = "coordinator-assisted")]
pub mod partial_soundness;
#[cfg(feature = "coordinator-assisted")]
pub mod policy;
#[cfg(feature = "coordinator-assisted")]
pub mod prefilter;
#[cfg(feature = "coordinator-assisted")]
pub mod preprocess;
pub mod provider;
#[cfg(feature = "coordinator-assisted")]
pub mod rejection_equivalence;
#[cfg(feature = "coordinator-assisted")]
pub mod transcript;
#[cfg(feature = "coordinator-assisted")]
pub mod types;
