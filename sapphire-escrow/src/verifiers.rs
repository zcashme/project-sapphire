//! Built-in [`ConditionVerifier`](crate::ConditionVerifier) implementations.
//!
//! These are application-agnostic conditions Sapphire can enforce out of the
//! box. Application-specific verifiers (e.g. ZcashName's on-chain rebind check,
//! or a zkVM-proof verifier) live with their applications and plug in through
//! the same trait.

use sha2::{Digest, Sha256};

use crate::{ConditionVerifier, EscrowTerms};

/// A hash-preimage (HTLC-style) condition: release is unlocked by revealing a
/// preimage whose SHA-256 digest equals the escrow's `condition`.
///
/// This is the canonical trustless escrow lock — the buyer learns/holds a
/// secret, and revealing it both proves a fact and authorizes the release.
/// The witness is the preimage bytes.
pub struct HashPreimage;

impl HashPreimage {
    /// The digest function this condition commits to. Use it to compute the
    /// `condition` field of [`EscrowTerms`] from a chosen preimage.
    pub fn digest(preimage: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        hasher.finalize().into()
    }
}

impl ConditionVerifier for HashPreimage {
    type Witness = Vec<u8>;

    fn verify(&self, terms: &EscrowTerms, witness: &Self::Witness) -> bool {
        // Constant-length compare against the committed digest. A malformed
        // (non-32-byte) condition can never match a real digest.
        terms.condition.as_slice() == Self::digest(witness)
    }
}

/// A condition that is always satisfied. Useful for tests and for escrows
/// whose only gate is the timeout/refund logic. The witness is `()`.
pub struct AcceptAll;

impl ConditionVerifier for AcceptAll {
    type Witness = ();

    fn verify(&self, _terms: &EscrowTerms, _witness: &Self::Witness) -> bool {
        true
    }
}
