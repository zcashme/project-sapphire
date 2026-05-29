//! Signing policy — the gate that makes a [`Node`](crate::Node) a *validating*
//! signer instead of a blind one.
//!
//! Before a node emits its round-1 FROST commitment for a request, it asks its
//! policy whether the message is one it should sign. A blind signer signs
//! anything ([`AcceptAll`]); an escrow signer ([`EscrowPolicy`]) only signs a
//! release that matches the terms it independently holds.
//!
//! Because every honest validator runs this check and a signature only forms
//! at the threshold, the party that *proposes* a release need not be trusted:
//! a bad proposal simply fails to gather enough shares.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;

use sapphire_escrow::{validate_settlement, ConditionVerifier, EscrowTerms, ReleaseProposal};

/// Decides whether this node should sign a proposed message. [`Node::react`]
/// consults it before emitting a commitment; `Err` means "refuse — emit
/// nothing for this request."
///
/// [`Node::react`]: crate::Node::react
pub trait SignPolicy: Send + Sync {
    /// Returns `Ok` iff this node should sign `message`.
    fn approve(&self, message: &[u8]) -> Result<(), String>;
}

/// Signs anything. The default policy — preserves blind-signer behaviour for
/// callers that don't opt into validation (e.g. generic FROST tests/demos).
pub struct AcceptAll;

impl SignPolicy for AcceptAll {
    fn approve(&self, _message: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

/// Validates escrow release proposals against the node's *own* trusted terms.
///
/// The message must deserialize to a [`ReleaseProposal`]. The node looks up the
/// [`EscrowTerms`] for the proposal's `escrow_id` from its own registry — never
/// from the proposal — and runs the escrow predicate via the injected
/// [`ConditionVerifier`].
pub struct EscrowPolicy<V: ConditionVerifier> {
    escrows: BTreeMap<[u8; 32], EscrowTerms>,
    verifier: V,
}

impl<V: ConditionVerifier> EscrowPolicy<V> {
    /// Create a policy backed by `verifier`, knowing about no escrows yet.
    pub fn new(verifier: V) -> Self {
        Self {
            escrows: BTreeMap::new(),
            verifier,
        }
    }

    /// Register an escrow this node will honour release proposals for. These
    /// terms are the node's *trusted reference*; proposals are checked against
    /// them, not the other way round.
    pub fn with_escrow(mut self, terms: EscrowTerms) -> Self {
        self.escrows.insert(terms.escrow_id, terms);
        self
    }
}

impl<V> SignPolicy for EscrowPolicy<V>
where
    V: ConditionVerifier + Send + Sync,
    V::Witness: DeserializeOwned,
{
    fn approve(&self, message: &[u8]) -> Result<(), String> {
        let proposal: ReleaseProposal<V::Witness> = serde_json::from_slice(message)
            .map_err(|e| format!("message is not a release proposal: {e}"))?;
        let terms = self
            .escrows
            .get(&proposal.escrow_id)
            .ok_or_else(|| format!("unknown escrow {}", hex::encode(proposal.escrow_id)))?;
        validate_settlement(terms, &proposal.intent, &self.verifier).map_err(|e| e.to_string())
    }
}
