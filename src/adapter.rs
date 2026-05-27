//! Simulation infrastructure for threshold protocol adapter experiments.
//!
//! This module provides temporary scaffolding for simulation-facing adapter
//! work. It does not integrate with the real production L1 P2P network, state
//! trie, gas, or slashing runtime.

pub mod actor;
pub mod evidence;
pub mod traits;
pub mod wire;
