//! Sapphire keygen.
//!
//! * [`generate_with_dkg`] — proper Distributed Key Generation. No single
//!   party ever sees the full secret. Simulated in-process here; the real
//!   distributed protocol needs the same network transport as signing.
//!
//! Trusted-dealer keygen (one party generating and splitting the whole key)
//! was removed: a single party holding the full secret is antithetical to a
//! non-custodial design, so DKG is the only supported path.

pub mod dkg;

pub use dkg::generate_with_dkg;
