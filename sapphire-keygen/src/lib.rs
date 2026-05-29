//! Sapphire keygen.
//!
//! Two ceremonies are supported:
//!
//! * [`generate_with_trusted_dealer`] — a single trusted party generates the
//!   full key, splits it, and distributes shares. Pragmatic for tests/demos.
//! * [`generate_with_dkg`] — proper Distributed Key Generation. No single
//!   party ever sees the full secret. Simulated in-process here; the real
//!   distributed protocol needs the same network transport as signing.

pub mod dkg;
pub mod trusted_dealer;

pub use dkg::generate_with_dkg;
pub use trusted_dealer::generate_with_trusted_dealer;
