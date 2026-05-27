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
    keys::{dkg::round1 as dkg_r1, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    Ciphersuite, Identifier, Signature, SigningPackage,
};
use frost_rerandomized::{RandomizedParams, Randomizer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use sapphire_core::{protocol::uuid_lite::Uuid, MpcParams};

use crate::dkg_envelope::{EncPublicKey, Sealed};
use crate::tx::Tx;

/// Per-request entry on the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct RequestEntry<C: Ciphersuite> {
    pub request_id: Uuid,
    pub message: Vec<u8>,
    pub randomizer: Randomizer<C>,
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
    /// Final signature aggregated. Verifies against the *rerandomized*
    /// verifying key `rk = group_vk + randomizer·G`, not the original group
    /// verifying key. Callers reconstruct `rk` from `group.pkp.verifying_key()`
    /// and the request's `randomizer`.
    Completed {
        participants: BTreeSet<Identifier<C>>,
        signature: Signature<C>,
    },
    /// Aggregation or validation failed. Records the reason for audit.
    Failed { reason: String },
}

/// Distributed key generation ceremony, as a chain-resident state machine.
///
/// Mirrors the three rounds of FROST DKG:
///  * `round1` — public polynomial-commitment packages, broadcast from each
///    participant to the rest.
///  * `round2` — per-(sender, recipient) secret-share contributions, sealed
///    to the recipient's X25519 key. The chain stores the ciphertexts.
///  * `finalize` — each participant's locally-derived [`PublicKeyPackage`].
///    When all `total` participants submit matching PKPs, the ceremony
///    "promotes" into a [`GroupConfig`] and is cleared from `state.ceremony`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct DkgCeremony<C: Ciphersuite> {
    pub params: MpcParams,
    /// Identifier → X25519 public key used to seal round-2 packages.
    pub validators: BTreeMap<Identifier<C>, EncPublicKey>,
    /// Round-1 packages submitted by each participant. Public.
    pub round1: BTreeMap<Identifier<C>, dkg_r1::Package<C>>,
    /// Round-2 sealed envelopes, keyed by `(from, to)`. The chain never
    /// decrypts these.
    pub round2: BTreeMap<(Identifier<C>, Identifier<C>), Sealed>,
    /// Locally-derived [`PublicKeyPackage`]s submitted by each participant.
    /// The state machine confirms all agree before promoting to GroupConfig.
    pub finalize: BTreeMap<Identifier<C>, PublicKeyPackage<C>>,
}

impl<C: Ciphersuite> DkgCeremony<C> {
    fn total(&self) -> usize {
        self.params.total as usize
    }

    pub fn r1_complete(&self) -> bool {
        self.round1.len() == self.total()
    }

    pub fn r2_complete(&self) -> bool {
        // Every ordered pair (from, to) with from != to must have an envelope.
        let total = self.total();
        self.round2.len() == total * (total - 1)
    }

    pub fn finalize_complete(&self) -> bool {
        self.finalize.len() == self.total()
    }
}

/// The chain's full state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct State<C: Ciphersuite> {
    pub ceremony: Option<DkgCeremony<C>>,
    pub group: Option<GroupConfig<C>>,
    pub requests: BTreeMap<Uuid, RequestEntry<C>>,
}

impl<C: Ciphersuite> Default for State<C> {
    fn default() -> Self {
        Self {
            ceremony: None,
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

    #[error("DKG ceremony already in progress")]
    CeremonyAlreadyInProgress,

    #[error("DKG ceremony not in progress")]
    NoCeremony,

    #[error("DKG validator set must have exactly `total` participants")]
    BadDkgValidatorCount,

    #[error("DKG: round 1 not complete yet")]
    Round1NotComplete,

    #[error("DKG: round 2 not complete yet")]
    Round2NotComplete,

    #[error("DKG: participant {0:?} already submitted round-1 package")]
    DuplicateRound1(String),

    #[error("DKG: participant {0:?} already submitted round-2 envelope to {1:?}")]
    DuplicateRound2(String, String),

    #[error("DKG: participant {0:?} already submitted finalize")]
    DuplicateFinalize(String),

    #[error("DKG: participant {0:?} cannot self-address a round-2 envelope")]
    SelfAddressedRound2(String),

    #[error("DKG: validator {0:?} not in the ceremony validator set")]
    UnknownDkgValidator(String),

    #[error("DKG: participant {0:?} submitted a PKP that disagrees with the rest")]
    PkpMismatch(String),

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
            if next.ceremony.is_some() {
                return Err(ApplyError::CeremonyAlreadyInProgress);
            }
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

        Tx::DkgBegin { params, validators } => {
            if next.group.is_some() {
                return Err(ApplyError::AlreadyInitialized);
            }
            if next.ceremony.is_some() {
                return Err(ApplyError::CeremonyAlreadyInProgress);
            }
            if validators.len() != params.total as usize {
                return Err(ApplyError::BadDkgValidatorCount);
            }
            next.ceremony = Some(DkgCeremony {
                params: *params,
                validators: validators.clone(),
                round1: BTreeMap::new(),
                round2: BTreeMap::new(),
                finalize: BTreeMap::new(),
            });
        }

        Tx::DkgRound1 { from, package } => {
            let ceremony = next.ceremony.as_mut().ok_or(ApplyError::NoCeremony)?;
            if !ceremony.validators.contains_key(from) {
                return Err(ApplyError::UnknownDkgValidator(format!("{:?}", from)));
            }
            if ceremony.round1.contains_key(from) {
                return Err(ApplyError::DuplicateRound1(format!("{:?}", from)));
            }
            ceremony.round1.insert(*from, package.clone());
        }

        Tx::DkgRound2 { from, to, sealed } => {
            let ceremony = next.ceremony.as_mut().ok_or(ApplyError::NoCeremony)?;
            if !ceremony.r1_complete() {
                return Err(ApplyError::Round1NotComplete);
            }
            if from == to {
                return Err(ApplyError::SelfAddressedRound2(format!("{:?}", from)));
            }
            if !ceremony.validators.contains_key(from) {
                return Err(ApplyError::UnknownDkgValidator(format!("{:?}", from)));
            }
            if !ceremony.validators.contains_key(to) {
                return Err(ApplyError::UnknownDkgValidator(format!("{:?}", to)));
            }
            let key = (*from, *to);
            if ceremony.round2.contains_key(&key) {
                return Err(ApplyError::DuplicateRound2(
                    format!("{:?}", from),
                    format!("{:?}", to),
                ));
            }
            ceremony.round2.insert(key, sealed.clone());
        }

        Tx::DkgFinalize { from, pkp } => {
            let ceremony = next.ceremony.as_mut().ok_or(ApplyError::NoCeremony)?;
            if !ceremony.r2_complete() {
                return Err(ApplyError::Round2NotComplete);
            }
            if !ceremony.validators.contains_key(from) {
                return Err(ApplyError::UnknownDkgValidator(format!("{:?}", from)));
            }
            if ceremony.finalize.contains_key(from) {
                return Err(ApplyError::DuplicateFinalize(format!("{:?}", from)));
            }
            // All participants must derive the same PKP. Check against the
            // first submitted one if any exists.
            if let Some((_, first)) = ceremony.finalize.iter().next() {
                if first.verifying_key() != pkp.verifying_key()
                    || first.verifying_shares() != pkp.verifying_shares()
                {
                    return Err(ApplyError::PkpMismatch(format!("{:?}", from)));
                }
            }
            ceremony.finalize.insert(*from, pkp.clone());

            // Promote: if every participant has finalized (and they all
            // agreed by construction above), commit the GroupConfig.
            if ceremony.finalize_complete() {
                let ceremony = next.ceremony.take().expect("just confirmed present");
                let validators: BTreeSet<_> = ceremony.validators.keys().copied().collect();
                let agreed_pkp = ceremony
                    .finalize
                    .into_values()
                    .next()
                    .expect("finalize_complete implies non-empty");
                next.group = Some(GroupConfig {
                    params: ceremony.params,
                    pkp: agreed_pkp,
                    validators,
                });
            }
        }

        Tx::SubmitRequest {
            request_id,
            message,
            randomizer,
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
                    randomizer: *randomizer,
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
            let randomizer = entry.randomizer;
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

            // Once all selected participants have submitted, aggregate
            // against the rerandomized verifying key. The randomizer was
            // committed to the chain by the caller in SubmitRequest, so every
            // validator replays the same RandomizedParams here.
            if shares_map.len() == participants.len() {
                let shares_snapshot = shares_map.clone();
                let randomized_params =
                    RandomizedParams::from_randomizer(group.pkp.verifying_key(), randomizer);
                match frost_rerandomized::aggregate::<C>(
                    &signing_package,
                    &shares_snapshot,
                    &group.pkp,
                    &randomized_params,
                ) {
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
