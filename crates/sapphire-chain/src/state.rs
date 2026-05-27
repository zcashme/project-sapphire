//! The Sapphire coordination chain state machine.
//!
//! [`apply_tx`] is the pure deterministic transition function. Given a
//! [`State`] and a [`Tx`], it either returns an updated state or an
//! [`ApplyError`] describing why the transaction is invalid. All validators
//! that apply the same sequence of valid transactions reach the same state —
//! this is what lets BFT consensus (CometBFT, etc.) sit on top without
//! changing any of the logic here.

use std::collections::{BTreeMap, BTreeSet};

use frost_core::{
    aggregate,
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
    Ciphersuite, Identifier, Signature, SigningPackage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use sapphire_core::{protocol::uuid_lite::Uuid, MpcParams};

use crate::tx::Tx;

/// Per-request entry on the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct RequestEntry<C: Ciphersuite> {
    pub request_id: Uuid,
    pub message: Vec<u8>,
    pub status: RequestStatus<C>,
}

/// Lifecycle of a signing request as the chain processes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub enum RequestStatus<C: Ciphersuite> {
    /// Awaiting round-1 commitments. Once `threshold` are collected the
    /// state advances to [`RequestStatus::Signing`].
    AwaitingCommitments {
        commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
    },
    /// Selected participants have committed; collecting their round-2 shares.
    Signing {
        signing_package: SigningPackage<C>,
        participants: BTreeSet<Identifier<C>>,
        shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
    },
    /// Final signature aggregated and verified against the group key.
    Completed {
        participants: BTreeSet<Identifier<C>>,
        signature: Signature<C>,
    },
    /// Aggregation or validation failed. Records the reason for audit.
    Failed { reason: String },
}

/// The chain's full state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct State<C: Ciphersuite> {
    pub group: Option<GroupConfig<C>>,
    pub requests: BTreeMap<Uuid, RequestEntry<C>>,
}

impl<C: Ciphersuite> Default for State<C> {
    fn default() -> Self {
        Self {
            group: None,
            requests: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct GroupConfig<C: Ciphersuite> {
    pub params: MpcParams,
    pub pkp: PublicKeyPackage<C>,
    pub validators: BTreeSet<Identifier<C>>,
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("group already initialized")]
    AlreadyInitialized,

    #[error("group not initialized; submit InitGroup first")]
    NotInitialized,

    #[error("validator set in InitGroup does not match the public key package")]
    ValidatorSetMismatch,

    #[error("request {0} already exists")]
    DuplicateRequest(Uuid),

    #[error("request {0} not found")]
    UnknownRequest(Uuid),

    #[error("validator {0:?} not in the validator set")]
    UnknownValidator(String),

    #[error("validator already submitted commitment for this request")]
    DuplicateCommitment,

    #[error("validator already submitted share for this request")]
    DuplicateShare,

    #[error("request is not awaiting commitments")]
    NotAwaitingCommitments,

    #[error("request is not in signing phase")]
    NotSigning,

    #[error("validator was not selected for this signing session")]
    NotSelectedParticipant,

    #[error("signature aggregation failed: {0}")]
    AggregationFailed(String),
}

/// Apply a single transaction to the state. Returns a new state on success.
///
/// This is the pure deterministic core of the chain. A real BFT runtime
/// (CometBFT via tower-abci, etc.) drives this from `DeliverTx` / equivalent
/// in block order.
pub fn apply_tx<C: Ciphersuite>(state: &State<C>, tx: &Tx<C>) -> Result<State<C>, ApplyError> {
    let mut next = state.clone();
    match tx {
        Tx::InitGroup {
            params,
            pkp,
            validators,
        } => {
            if next.group.is_some() {
                return Err(ApplyError::AlreadyInitialized);
            }
            // Validators must exactly match the verifying shares in the PKP.
            let pkp_ids: BTreeSet<Identifier<C>> =
                pkp.verifying_shares().keys().copied().collect();
            let vs: BTreeSet<Identifier<C>> = validators.iter().copied().collect();
            if pkp_ids != vs {
                return Err(ApplyError::ValidatorSetMismatch);
            }
            next.group = Some(GroupConfig {
                params: *params,
                pkp: pkp.clone(),
                validators: vs,
            });
        }

        Tx::SubmitRequest {
            request_id,
            message,
        } => {
            let _ = require_group(&next)?;
            if next.requests.contains_key(request_id) {
                return Err(ApplyError::DuplicateRequest(*request_id));
            }
            next.requests.insert(
                *request_id,
                RequestEntry {
                    request_id: *request_id,
                    message: message.clone(),
                    status: RequestStatus::AwaitingCommitments {
                        commitments: BTreeMap::new(),
                    },
                },
            );
        }

        Tx::SubmitCommitment {
            request_id,
            validator,
            commitments,
        } => {
            let group = require_group(&next)?.clone();
            if !group.validators.contains(validator) {
                return Err(ApplyError::UnknownValidator(format!("{:?}", validator)));
            }
            let entry = next
                .requests
                .get_mut(request_id)
                .ok_or(ApplyError::UnknownRequest(*request_id))?;
            let message = entry.message.clone();
            match &mut entry.status {
                RequestStatus::AwaitingCommitments { commitments: map } => {
                    if map.contains_key(validator) {
                        return Err(ApplyError::DuplicateCommitment);
                    }
                    map.insert(*validator, commitments.clone());

                    // If we've reached threshold, transition to Signing using
                    // the first `threshold` commits in identifier order. This
                    // selection is deterministic, so all validators agree.
                    if (map.len() as u16) >= group.params.threshold {
                        let chosen: BTreeMap<_, _> = map
                            .iter()
                            .take(group.params.threshold as usize)
                            .map(|(k, v)| (*k, v.clone()))
                            .collect();
                        let participants: BTreeSet<_> = chosen.keys().copied().collect();
                        let signing_package = SigningPackage::<C>::new(chosen, &message);
                        entry.status = RequestStatus::Signing {
                            signing_package,
                            participants,
                            shares: BTreeMap::new(),
                        };
                    }
                }
                _ => return Err(ApplyError::NotAwaitingCommitments),
            }
        }

        Tx::SubmitShare {
            request_id,
            validator,
            share,
        } => {
            let group = require_group(&next)?.clone();
            if !group.validators.contains(validator) {
                return Err(ApplyError::UnknownValidator(format!("{:?}", validator)));
            }
            let entry = next
                .requests
                .get_mut(request_id)
                .ok_or(ApplyError::UnknownRequest(*request_id))?;
            // Read what we need before mutating to keep the borrow checker happy.
            let (signing_package, participants, shares_map) = match &mut entry.status {
                RequestStatus::Signing {
                    signing_package,
                    participants,
                    shares,
                } => (signing_package.clone(), participants.clone(), shares),
                _ => return Err(ApplyError::NotSigning),
            };
            if !participants.contains(validator) {
                return Err(ApplyError::NotSelectedParticipant);
            }
            if shares_map.contains_key(validator) {
                return Err(ApplyError::DuplicateShare);
            }
            shares_map.insert(*validator, share.clone());

            // Once all selected participants have submitted, aggregate.
            if shares_map.len() == participants.len() {
                let shares_snapshot = shares_map.clone();
                match aggregate::<C>(&signing_package, &shares_snapshot, &group.pkp) {
                    Ok(signature) => {
                        entry.status = RequestStatus::Completed {
                            participants,
                            signature,
                        };
                    }
                    Err(e) => {
                        let reason = e.to_string();
                        entry.status = RequestStatus::Failed { reason };
                    }
                }
            }
        }
    }
    Ok(next)
}

fn require_group<C: Ciphersuite>(state: &State<C>) -> Result<&GroupConfig<C>, ApplyError> {
    state.group.as_ref().ok_or(ApplyError::NotInitialized)
}
