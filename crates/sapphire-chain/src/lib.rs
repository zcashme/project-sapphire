//! Sapphire coordination state machine.
//!
//! Validators are also the MPC signers. Every step of a signing session — the
//! request itself, each participant's round-1 commitment, each participant's
//! round-2 share — flows as a [`Tx`] applied to the deterministic [`State`].
//! DKG runs the same way: each round is a tx, the state machine cross-checks,
//! and the ceremony promotes itself into a `GroupConfig` when complete.
//!
//! Consensus is *not* this crate's problem. `apply_tx` is monotonic and
//! commutative across non-conflicting inputs, so eventual delivery of all
//! txs to every validator suffices. The mesh layer (`sapphire-net`) provides
//! that delivery; the in-memory simulator [`sim::ChainSim`] is the test
//! equivalent.
//!
//! ## What lives here
//!
//! * [`Tx`] — the transaction types.
//! * [`State`] — the deterministic state.
//! * [`apply_tx`] — the pure state-transition function.
//! * `mod sim` — in-process simulator for tests and demos.
//! * `mod dkg_envelope` — sealed-box layer for DKG round-2 packages.
//!
//! ## Why this works without smart contracts on Zcash
//!
//! Sapphire's coordination state is *off* Zcash. Its sole purpose is to
//! sequence sign requests, gather FROST messages between validator-signers,
//! and produce the final signature deterministically. The resulting Zcash
//! transaction is broadcast to Zcash L1 by whichever party wants the signed
//! tx (typically the caller).

pub mod dkg_envelope;
pub mod sim;
pub mod state;
pub mod tx;

pub use dkg_envelope::{open as open_envelope, seal as seal_envelope, EncPublicKey, Sealed};
pub use state::{
    apply_tx, ApplyError, DkgCeremony, RequestEntry, RequestStatus, State,
};
pub use tx::Tx;
