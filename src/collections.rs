//! Placeholder collection API surface for a later implementation task.

/// Canonical commitment collection reserved for the validation collections task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitmentSet;

/// Canonical partial-share collection reserved for the validation collections task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PartialShareSet;

/// Validated DKG share collection reserved for the DKG task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatedDkgShares;
