//! Ciphersuite abstraction.
//!
//! Sapphire is generic over any FROST `Ciphersuite`. The default is Ed25519
//! (clean upstream dependency, fast tests). The `redpallas` feature exposes
//! the Zcash Orchard spend-auth ciphersuite for Phase-2 work.

pub use frost_core::Ciphersuite;

/// Default ciphersuite used by demos and tests.
pub type SapphireCiphersuite = frost_ed25519::Ed25519Sha512;

/// RedPallas — Zcash Orchard spend authorization (Schnorr over Pallas).
///
/// The plain ciphersuite here produces valid Schnorr signatures over Pallas
/// but does NOT incorporate the per-spend randomizer required by Orchard's
/// spend-auth check. Wiring up rerandomization (via `frost-rerandomized` +
/// the Orchard bundle's `randomizer`) is V0.3 work.
#[cfg(feature = "redpallas")]
pub type RedPallas = reddsa::frost::redpallas::PallasBlake2b512;
