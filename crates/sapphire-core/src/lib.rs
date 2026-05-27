//! Sapphire core.
//!
//! Shared protocol types and FROST primitives for the Sapphire MPC signing
//! network. Higher-level crates (`sapphire-signer`, `sapphire-coordinator`,
//! `sapphire-client`) build on top of this layer.

pub mod ciphersuite;
pub mod error;
pub mod params;
pub mod protocol;

pub use ciphersuite::SapphireCiphersuite;
pub use error::{Error, Result};
pub use params::MpcParams;
pub use protocol::{SigningRequest, SigningResponse};

pub use frost_core as frost;
