//! End-to-end test: chain-driven DKG followed by chain-driven signing.
//!
//! Spins up `total` `DkgParticipant`s, runs the ceremony through the in-memory
//! coordination chain (`ChainSim`) — `DkgBegin` → r1 → r2 (sealed) → finalize
//! — then promotes them to `Validator`s and signs a message using the same
//! chain-driven FROST flow that V1 already uses.
//!
//! Assertions:
//!   1. After finalize, `state.ceremony` is `None` and `state.group` is `Some`.
//!   2. The signing flow produces a valid rerandomized RedPallas signature
//!      under `rk = ak + α·G`.

use std::collections::BTreeMap;

use frost_core::{Ciphersuite, Field, Group};
use frost_rerandomized::{RandomizedParams, Randomizer};
use rand::rngs::OsRng;
use reddsa::frost::redpallas::PallasBlake2b512 as Cs;

use sapphire_chain::{
    sim::ChainSim,
    state::RequestStatus,
    tx::Tx as ChainTx,
};
use sapphire_core::{protocol::uuid_lite::Uuid, MpcParams};
use sapphire_validator::{DkgParticipant, Validator};

const THRESHOLD: u16 = 5;
const TOTAL: u16 = 8;

#[test]
fn five_of_eight_dkg_then_sign() {
    let mut rng = OsRng;
    let params = MpcParams::new(THRESHOLD, TOTAL).unwrap();

    // ---- Pre-DKG: make `total` participants ----
    let mut participants: Vec<DkgParticipant<Cs>> = (1..=TOTAL)
        .map(|i| {
            let id: frost_core::Identifier<Cs> = i.try_into().unwrap();
            DkgParticipant::<Cs>::new(id, &mut rng)
        })
        .collect();

    let mut chain: ChainSim<Cs> = ChainSim::new();

    // Block 1: DkgBegin advertises the validator set + their X25519 pubkeys.
    let dkg_validators: BTreeMap<_, _> = participants
        .iter()
        .map(|p| (p.identifier, p.enc_public))
        .collect();
    chain.submit(ChainTx::DkgBegin {
        params,
        validators: dkg_validators,
    });
    chain.commit_block();
    assert!(chain.state.ceremony.is_some(), "DkgBegin should open ceremony");
    assert!(chain.state.group.is_none());

    // Run the ceremony to completion: each block, every participant reacts
    // to the current state and produces whatever is next (r1, r2 envelopes,
    // finalize). Bounded loop so a stuck protocol can't hang the test.
    let mut steps = 0;
    while chain.state.group.is_none() {
        steps += 1;
        assert!(steps < 20, "DKG did not converge within 20 blocks");
        for p in participants.iter_mut() {
            for tx in p.react(&chain.state, &mut rng).expect("dkg react") {
                chain.submit(tx);
            }
        }
        chain.commit_block();
    }
    assert!(chain.state.ceremony.is_none(), "ceremony should clear on promotion");
    let group = chain.state.group.as_ref().expect("promoted GroupConfig");
    assert_eq!(group.validators.len(), TOTAL as usize);

    // Every participant should hold a key package locally.
    for p in &participants {
        assert!(p.is_complete(), "participant {:?} didn't finish DKG", p.identifier);
    }

    // Sanity: every participant's local PKP matches the chain's promoted PKP.
    let chain_pkp = group.pkp.clone();
    for p in &participants {
        let local = p.public_key_package.as_ref().unwrap();
        assert_eq!(local.verifying_key(), chain_pkp.verifying_key());
    }

    // ---- Switch to signing mode ----
    let mut validators: Vec<Validator<Cs>> = participants
        .into_iter()
        .map(|p| p.into_validator().expect("complete DKG → validator"))
        .collect();

    // Client picks an Orchard-style randomizer.
    let request_id = Uuid::new(&mut rng);
    let randomizer = {
        let scalar = <<<Cs as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
        Randomizer::<Cs>::from_scalar(scalar)
    };
    let message = b"hello dkg-over-chain";

    chain.submit(ChainTx::SubmitRequest {
        request_id,
        message: message.to_vec(),
        randomizer,
    });
    chain.commit_block();

    // Validators react: round-1 commitments.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).expect("sign react r1") {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    // Validators react: round-2 (rerandomized) shares.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).expect("sign react r2") {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    // ---- Verify completed signature ----
    let entry = chain.state.requests.get(&request_id).expect("request entry");
    match &entry.status {
        RequestStatus::Completed {
            signature,
            participants,
        } => {
            assert_eq!(participants.len(), THRESHOLD as usize);
            let rparams = RandomizedParams::<Cs>::from_randomizer(
                chain_pkp.verifying_key(),
                randomizer,
            );
            rparams
                .randomized_verifying_key()
                .verify(message, signature)
                .expect("rerandomized verify");
        }
        other => panic!("expected Completed, got {:?}", other),
    }
}
