//! Sapphire core.
//!
//! Shared protocol types and FROST primitives for the Sapphire MPC signing
//! network. Higher-level crates (`sapphire-node`, `sapphire-chain`,
//! `sapphire-escrow`) build on top of this layer.

pub mod ciphersuite;
pub mod error;
pub mod params;
pub mod protocol;

pub use error::{Error, Result};
pub use params::MpcParams;
pub use protocol::{SigningRequest, SigningResponse};

pub use frost_core as frost;
