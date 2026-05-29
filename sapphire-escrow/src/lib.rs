//! Sapphire escrow: the condition-gated validation layer.
//!
//! This crate turns Sapphire from a *blind* signer (hand it a sighash, it
//! signs) into a *validating* signer (hand it a proposed release, it signs
//! only if the release matches the escrow's terms **and** the release
//! condition is satisfied).
//!
//! ## The shape of an escrow
//!
//! Funds sit at a 5-of-8 FROST address. They may move exactly two ways:
//!
//! * **release** — pay `payee`, but only once a *release condition* is met;
//! * **refund**  — return to `refund_to`, once the timeout has passed.
//!
//! Sapphire owns one half of this and delegates the other:
//!
//! * Sapphire **owns the payment check** — "does this transaction pay exactly
//!   the escrowed amount to the agreed recipient?" That is fully within its
//!   knowledge and lives in [`validate_settlement`] / [`validate_refund`].
//! * Sapphire **delegates the condition check** — "is the release condition
//!   actually satisfied?" — to an injected [`ConditionVerifier`]. The core
//!   does not know or care what the condition *is*.
//!
//! This split is deliberate: Sapphire is a **generic escrow primitive**, not
//! tied to any one application. A hash-preimage (HTLC-style) condition ships
//! here as [`verifiers::HashPreimage`]; richer conditions — e.g. ZcashName's
//! "the name rebound to the buyer on-chain", or a future zkVM proof — are just
//! other `ConditionVerifier` implementations supplied by the caller.
//!
//! ## Why delegation, not blind signing
//!
//! Every validator runs the predicate independently before contributing a
//! FROST share, and a signature only forms at the 5-of-8 threshold. So the
//! party that *assembles* the release transaction need not be trusted: a bad
//! proposal simply fails to gather enough shares. The threshold *is* the
//! agreement mechanism; the predicate is what each validator agrees *to*.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod verifiers;

/// A Zcash address, encoded as an opaque string (e.g. a unified address
/// `u1abc...`). Sapphire compares addresses; it does not parse them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(pub String);

/// An amount in zatoshis (1 ZEC = 100_000_000 zat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Zatoshis(pub u64);

/// The binding terms of one escrow, fixed when the funds are deposited.
///
/// These are the *reference* a proposed release is checked against — the
/// escrow will only move funds in a way that matches them exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowTerms {
    /// Unique id for this escrow. Binds a condition witness to *this* deposit,
    /// so one witness cannot drain a different escrow.
    #[serde(with = "hex::serde")]
    pub escrow_id: [u8; 32],
    /// The escrowed amount. A release or refund must move exactly this.
    pub amount: Zatoshis,
    /// Who gets paid on a successful release.
    pub payee: Address,
    /// Who the funds return to if the escrow times out.
    pub refund_to: Address,
    /// Block height at or after which a refund becomes valid.
    pub timeout_height: u64,
    /// Opaque descriptor of the release condition, interpreted by the
    /// [`ConditionVerifier`]. For a hash-preimage condition this is the
    /// 32-byte digest; for other conditions it is whatever that verifier
    /// needs. Sapphire core treats it as bytes.
    #[serde(with = "hex::serde")]
    pub condition: Vec<u8>,
}

/// The spend a release/refund transaction performs: pay `amount` to `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentLeg {
    pub amount: Zatoshis,
    pub to: Address,
}

/// What a proposed *release* transaction claims to do: a payment, plus a
/// `witness` that the release condition is satisfied. The witness type is
/// chosen by the [`ConditionVerifier`] in play (a preimage, a proof, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementIntent<W> {
    pub payment: PaymentLeg,
    pub witness: W,
}

/// What a proposed *refund* transaction claims to do: a plain return of funds.
/// There is no condition — the only gate is the timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundIntent {
    pub payment: PaymentLeg,
}

/// A release request as it travels to the signers: "release escrow `escrow_id`
/// per `intent`." The signed message bytes are this, serialized.
///
/// The proposal names the escrow by id but does **not** carry the terms — a
/// validator looks up its *own* trusted [`EscrowTerms`] for `escrow_id` and
/// validates `intent` against those. Taking terms from the proposal would be
/// circular (a malicious proposer would just supply terms matching its theft).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseProposal<W> {
    #[serde(with = "hex::serde")]
    pub escrow_id: [u8; 32],
    pub intent: SettlementIntent<W>,
}

/// Injected capability: decide whether an escrow's release condition is met.
///
/// Sapphire core never interprets the condition; it hands the verifier the
/// agreed [`EscrowTerms`] (which carry `condition`) plus the witness from the
/// release proposal, and trusts the verifier's yes/no. Applications supply the
/// implementation — see [`verifiers`] for the built-in hash-preimage one.
pub trait ConditionVerifier {
    /// The proof-of-condition a release must carry for this verifier.
    type Witness;

    /// Returns `true` iff `witness` proves `terms`' release condition holds.
    fn verify(&self, terms: &EscrowTerms, witness: &Self::Witness) -> bool;
}

/// Why a proposed release/refund was rejected. Each variant is a check a
/// validator runs *before* contributing a FROST share; any failure means
/// "do not sign."
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EscrowError {
    #[error("payment moves {got:?}, escrow holds {want:?}")]
    AmountMismatch { want: Zatoshis, got: Zatoshis },

    #[error("release pays the wrong recipient")]
    PayeeMismatch,

    #[error("release condition is not satisfied")]
    ConditionNotMet,

    #[error("refund is not yet valid: current height {current} < timeout {timeout}")]
    RefundTooEarly { current: u64, timeout: u64 },

    #[error("refund pays the wrong recipient")]
    RefundPayeeMismatch,
}

/// The release predicate. A validator signs a release **only if this returns
/// `Ok`**.
///
/// 1. the payment moves exactly `terms.amount` to `terms.payee`;
/// 2. the injected `verifier` accepts the witness for `terms`' condition.
pub fn validate_settlement<V: ConditionVerifier>(
    terms: &EscrowTerms,
    intent: &SettlementIntent<V::Witness>,
    verifier: &V,
) -> Result<(), EscrowError> {
    if intent.payment.amount != terms.amount {
        return Err(EscrowError::AmountMismatch {
            want: terms.amount,
            got: intent.payment.amount,
        });
    }
    if intent.payment.to != terms.payee {
        return Err(EscrowError::PayeeMismatch);
    }
    if !verifier.verify(terms, &intent.witness) {
        return Err(EscrowError::ConditionNotMet);
    }
    Ok(())
}

/// The refund predicate. A validator signs a refund **only if this returns
/// `Ok`**: the timeout has passed and the funds return, in full, to
/// `refund_to`.
pub fn validate_refund(
    terms: &EscrowTerms,
    intent: &RefundIntent,
    current_height: u64,
) -> Result<(), EscrowError> {
    if current_height < terms.timeout_height {
        return Err(EscrowError::RefundTooEarly {
            current: current_height,
            timeout: terms.timeout_height,
        });
    }
    if intent.payment.to != terms.refund_to {
        return Err(EscrowError::RefundPayeeMismatch);
    }
    if intent.payment.amount != terms.amount {
        return Err(EscrowError::AmountMismatch {
            want: terms.amount,
            got: intent.payment.amount,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verifiers::{AcceptAll, HashPreimage};
    use super::*;

    fn terms(condition: Vec<u8>) -> EscrowTerms {
        EscrowTerms {
            escrow_id: [7u8; 32],
            amount: Zatoshis(800_000_000), // 8 ZEC
            payee: Address("u_alice".into()),
            refund_to: Address("u_bob".into()),
            timeout_height: 1000,
            condition,
        }
    }

    fn payment_of(amount: u64, to: &str) -> PaymentLeg {
        PaymentLeg {
            amount: Zatoshis(amount),
            to: Address(to.into()),
        }
    }

    #[test]
    fn valid_release_passes() {
        let intent = SettlementIntent {
            payment: payment_of(800_000_000, "u_alice"),
            witness: (),
        };
        assert_eq!(
            validate_settlement(&terms(vec![]), &intent, &AcceptAll),
            Ok(())
        );
    }

    #[test]
    fn underpayment_is_rejected() {
        let intent = SettlementIntent {
            payment: payment_of(1, "u_alice"),
            witness: (),
        };
        assert!(matches!(
            validate_settlement(&terms(vec![]), &intent, &AcceptAll),
            Err(EscrowError::AmountMismatch { .. })
        ));
    }

    #[test]
    fn paying_the_wrong_person_is_rejected() {
        let intent = SettlementIntent {
            payment: payment_of(800_000_000, "u_attacker"),
            witness: (),
        };
        assert_eq!(
            validate_settlement(&terms(vec![]), &intent, &AcceptAll),
            Err(EscrowError::PayeeMismatch)
        );
    }

    #[test]
    fn htlc_correct_preimage_releases() {
        let preimage = b"open sesame".to_vec();
        let digest = HashPreimage::digest(&preimage).to_vec();
        let intent = SettlementIntent {
            payment: payment_of(800_000_000, "u_alice"),
            witness: preimage,
        };
        assert_eq!(
            validate_settlement(&terms(digest), &intent, &HashPreimage),
            Ok(())
        );
    }

    #[test]
    fn htlc_wrong_preimage_is_rejected() {
        let digest = HashPreimage::digest(b"the real secret").to_vec();
        let intent = SettlementIntent {
            payment: payment_of(800_000_000, "u_alice"),
            witness: b"a wrong guess".to_vec(),
        };
        assert_eq!(
            validate_settlement(&terms(digest), &intent, &HashPreimage),
            Err(EscrowError::ConditionNotMet)
        );
    }

    #[test]
    fn refund_before_timeout_is_rejected() {
        let intent = RefundIntent {
            payment: payment_of(800_000_000, "u_bob"),
        };
        assert!(matches!(
            validate_refund(&terms(vec![]), &intent, 999),
            Err(EscrowError::RefundTooEarly { .. })
        ));
    }

    #[test]
    fn refund_after_timeout_to_bob_passes() {
        let intent = RefundIntent {
            payment: payment_of(800_000_000, "u_bob"),
        };
        assert_eq!(validate_refund(&terms(vec![]), &intent, 1000), Ok(()));
    }

    #[test]
    fn refund_to_the_wrong_person_is_rejected() {
        let intent = RefundIntent {
            payment: payment_of(800_000_000, "u_attacker"),
        };
        assert_eq!(
            validate_refund(&terms(vec![]), &intent, 1000),
            Err(EscrowError::RefundPayeeMismatch)
        );
    }
}
