//! Placeholder signing protocol API surface for a later implementation task.

use core::marker::PhantomData;

/// Protocol state marker types reserved for the type-state signing task.
pub mod state {
    /// Initial signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Initialized;

    /// State reserved for collecting validator commitments.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct AwaitingCommitments;

    /// State reserved for collecting partial signatures.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct AwaitingPartialSignatures;

    /// Finalized signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Finalized;
}

/// Type-state signing session reserved for the signing protocol task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningSession<State = state::Initialized> {
    state: PhantomData<State>,
}

/// Threshold signing interface reserved for the signing protocol task.
#[allow(private_bounds)]
pub trait ThresholdSigner: sealed::Sealed {}

impl<State> ThresholdSigner for SigningSession<State> {}

mod sealed {
    pub trait Sealed {}

    impl<State> Sealed for super::SigningSession<State> {}
}
