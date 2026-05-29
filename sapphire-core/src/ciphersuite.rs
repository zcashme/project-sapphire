//! Ciphersuite abstraction.
//!
//! Sapphire is generic over any FROST `Ciphersuite`. Tests use Ed25519 (clean
//! upstream dependency, fast); the Zcash-facing path uses RedPallas
//! (rerandomized), pulled directly from `reddsa` where it is needed.

pub use frost_core::Ciphersuite;
