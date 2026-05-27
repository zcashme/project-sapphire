//! Sapphire client.
//!
//! Caller-facing convenience layer. Provides:
//!  * [`LocalTransport`] — in-process signer transport for tests and demos.
//!  * [`HttpTransport`] — remote signer transport (feature `http`).

pub mod local;

#[cfg(feature = "http")]
pub mod http;

pub use local::LocalTransport;

#[cfg(feature = "http")]
pub use http::HttpTransport;
