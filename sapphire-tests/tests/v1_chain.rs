//! V1 end-to-end: BFT coordination chain with validators-are-signers.
//!
//! Walks the full lifecycle of a *rerandomized* RedPallas signing request
//! through the in-process chain simulator:
//!
//! 1. DKG-generate a 2-of-3 RedPallas group (no trusted dealer).
//! 2. Build 3 validator-signers.
//! 3. `InitGroup` tx → group configured on-chain.
//! 4. Client picks a per-request randomizer (the Orchard `α`).
//! 5. Client `SubmitRequest` tx → request in `AwaitingCommitments`.
//! 6. Nodes react → 3 `SubmitCommitment` txs.
//! 7. Threshold (2) reached → state machine builds `SigningPackage`, advances
//!    to `Signing`.
//! 8. Selected validators react → `SubmitShare` txs, each signing against the
//!    rerandomized key derived from the on-chain randomizer.
//! 9. All shares in → state machine aggregates via
//!    `frost_rerandomized::aggregate` → `Completed { signature }`.
//! 10. Verify the signature against the **rerandomized** verifying key
//!     `rk = group_vk + α·G`, which is what Orchard's spend-auth check uses.

use std::collections::BTreeSet;

use frost_core::{Ciphersuite, Field, Group};
use frost_rerandomized::{RandomizedParams, Randomizer};
use rand::rngs::OsRng;
use reddsa::frost::redpallas::PallasBlake2b512;

use sapphire_chain::{
    sim::ChainSim,
    state::RequestStatus,
    tx::Tx,
};
use sapphire_core::{
    protocol::{uuid_lite::Uuid, KeyShareBundle},
    MpcParams,
};
use sapphire_keygen::generate_with_dkg;
use sapphire_node::Node;

type Cs = PallasBlake2b512;

/// Generate a fresh per-request randomizer. In a real Orchard flow the caller
/// uses the `α` value from the Orchard bundle; for tests we sample one.
fn fresh_randomizer(rng: &mut OsRng) -> Randomizer<Cs> {
    let scalar = <<<Cs as Ciphersuite>::Group as Group>::Field as Field>::random(rng);
    Randomizer::<Cs>::from_scalar(scalar)
}

#[test]
fn v1_two_of_three_full_round_trip() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();

    let mut validators: Vec<Node<Cs>> = key_packages.into_values().map(|kp| {
            Node::new(KeyShareBundle {
                key_package: kp,
                public_key_package: pkp.clone(),
            })
        })
        .collect();

    let mut chain = ChainSim::<Cs>::new();

    // Block 1: InitGroup
    chain.submit(Tx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: validators.iter().map(|v| v.identifier).collect(),
    });
    let results = chain.commit_block();
    assert!(results.iter().all(|(_, r)| r.is_ok()), "InitGroup failed: {:?}", results);
    assert!(chain.state.group.is_some());

    // Block 2: client picks a randomizer and submits the request.
    let request_id = Uuid::new(&mut rng);
    let message = b"sign me on the v1 chain".to_vec();
    let randomizer = fresh_randomizer(&mut rng);
    chain.submit(Tx::SubmitRequest {
        request_id,
        message: message.clone(),
        randomizer,
    });
    chain.commit_block();
    let entry = chain.state.requests.get(&request_id).unwrap();
    assert!(matches!(entry.status, RequestStatus::AwaitingCommitments { .. }));

    // Block 3: each validator reacts → submits commitments.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).unwrap() {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    let entry = chain.state.requests.get(&request_id).unwrap();
    let chosen_participants: BTreeSet<_> = match &entry.status {
        RequestStatus::Signing { participants, .. } => participants.clone(),
        other => panic!("expected Signing after threshold commits, got: {:?}", other),
    };
    assert_eq!(chosen_participants.len(), 2);

    // Block 4: selected validators react → submit rerandomized shares.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).unwrap() {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    let entry = chain.state.requests.get(&request_id).unwrap();
    let signature = match &entry.status {
        RequestStatus::Completed { signature, .. } => *signature,
        other => panic!("expected Completed, got: {:?}", other),
    };

    // The signature verifies against the rerandomized verifying key —
    // that's what an Orchard spend description's `rk` carries.
    let randomized_params =
        RandomizedParams::<Cs>::from_randomizer(pkp.verifying_key(), randomizer);
    randomized_params
        .randomized_verifying_key()
        .verify(&message, &signature)
        .expect("signature does not verify against rerandomized verifying key");
}

#[test]
fn v1_init_group_rejects_mismatched_validators() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (_, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();

    let bogus: frost_core::Identifier<Cs> =
        frost_core::Identifier::try_from(99u16).unwrap();
    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp,
        validators: vec![bogus],
    });
    let results = chain.commit_block();
    assert!(results[0].1.is_err(), "expected mismatch error");
}

#[test]
fn v1_unknown_request_rejected() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();
    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: key_packages.keys().copied().collect(),
    });
    chain.commit_block();

    let some_id = *key_packages.keys().next().unwrap();
    let kp = key_packages.values().next().unwrap();
    let node = Node::<Cs>::new(KeyShareBundle {
        key_package: kp.clone(),
        public_key_package: pkp,
    });
    let bogus_request_id = Uuid::new(&mut rng);
    let commitments = node
        .commit(bogus_request_id, &mut rng)
        .unwrap();
    chain.submit(Tx::SubmitCommitment {
        request_id: bogus_request_id,
        validator: some_id,
        commitments,
    });
    let results = chain.commit_block();
    assert!(results[0].1.is_err());
}
