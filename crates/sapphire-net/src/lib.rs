//! Sapphire validator mesh.
//!
//! A small Noise-XX-encrypted, length-prefixed-JSON p2p layer connecting the
//! N (typically 8) Sapphire validators to each other. Each validator dials
//! every peer with a higher identifier and accepts incoming connections
//! from every peer with a lower identifier — that gives one authenticated
//! bidirectional channel per pair, no duplicate connections.
//!
//! ## Surface
//!
//!  * [`Mesh::start`] — boot the mesh: bind listener, dial peers, perform
//!    Noise handshakes. Returns a handle + a `mpsc::Receiver<Tx<C>>` of
//!    txs received from peers.
//!  * [`Mesh::broadcast`] — send a [`Tx<C>`] to every peer. The local node
//!    is responsible for applying it to its own state separately.
//!
//! Conscious non-features for v1:
//!
//!  * No peer discovery (validator set is fixed and pre-shared).
//!  * No anti-entropy / replay (TCP reliability is assumed; transient
//!    disconnects may drop in-flight txs and require the originator to
//!    re-broadcast).
//!  * No rate limiting / DoS hardening (validators trust each other within
//!    the protocol envelope; misbehavior is detected by the state machine
//!    and slashed accountably).

mod codec;
mod handshake;
mod mesh;

pub use handshake::generate_static_keypair;
pub use mesh::{Mesh, MeshConfig, MeshError, PeerConfig};
