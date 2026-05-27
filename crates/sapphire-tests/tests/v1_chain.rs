//! V1 end-to-end: BFT coordination chain with validators-are-signers.
//!
//! Walks the full lifecycle of a signing request through the in-process
//! chain simulator:
//!
//! 1. DKG-generate a 2-of-3 group (no trusted dealer).
//! 2. Build 3 validator-signers.
//! 3. `InitGroup` tx → group configured on-chain.
//! 4. Client `SubmitRequest` tx → request in `AwaitingCommitments`.
//! 5. Validators react → 3 `SubmitCommitment` txs.
//! 6. Threshold (2) reached → state machine builds `SigningPackage`, advances
//!    to `Signing`.
//! 7. Selected validators react → `SubmitShare` txs.
//! 8. All shares in → state machine aggregates → `Completed { signature }`.
//! 9. Verify signature against the group key.

use std::collections::BTreeSet;

use frost_ed25519::Ed25519Sha512;
use rand::rngs::OsRng;

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
use sapphire_validator::Validator;

type Cs = Ed25519Sha512;

#[test]
fn v1_two_of_three_full_round_trip() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();

    let mut validators: Vec<Validator<Cs>> = key_packages
        .into_iter()
        .map(|(_, kp)| {
            Validator::new(KeyShareBundle {
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

    // Block 2: client submits a sign request.
    let request_id = Uuid::new(&mut rng);
    let message = b"sign me on the v1 chain".to_vec();
    chain.submit(Tx::SubmitRequest {
        request_id,
        message: message.clone(),
    });
    chain.commit_block();
    let entry = chain.state.requests.get(&request_id).unwrap();
    assert!(matches!(entry.status, RequestStatus::AwaitingCommitments { .. }));

    // Block 3: each validator reacts to the new request → submits commitments.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).unwrap() {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    // After threshold (2) commits land, the state machine must transition.
    let entry = chain.state.requests.get(&request_id).unwrap();
    let chosen_participants: BTreeSet<_> = match &entry.status {
        RequestStatus::Signing { participants, .. } => participants.clone(),
        other => panic!("expected Signing after threshold commits, got: {:?}", other),
    };
    assert_eq!(chosen_participants.len(), 2);

    // Block 4: selected validators react → submit shares.
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng).unwrap() {
            chain.submit(tx);
        }
    }
    chain.commit_block();

    // Final state: Completed with valid signature.
    let entry = chain.state.requests.get(&request_id).unwrap();
    let signature = match &entry.status {
        RequestStatus::Completed { signature, .. } => signature.clone(),
        other => panic!("expected Completed, got: {:?}", other),
    };

    pkp.verifying_key()
        .verify(&message, &signature)
        .expect("signature does not verify against group key");
}

#[test]
fn v1_init_group_rejects_mismatched_validators() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (_, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();

    // Pass a fabricated validator identifier that's not in the PKP.
    let bogus: frost_core::Identifier<Cs> =
        frost_core::Identifier::try_from(99u16).unwrap();
    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp,
        validators: vec![bogus],
    });
    let results = chain.commit_block();
    assert!(matches!(results[0].1, Err(_)), "expected mismatch error");
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
    let validator = Validator::<Cs>::new(KeyShareBundle {
        key_package: kp.clone(),
        public_key_package: pkp,
    });
    let bogus_request_id = Uuid::new(&mut rng);
    // Trigger commit + manually retarget to a request that doesn't exist.
    let commitments = validator
        .signer
        .commit(bogus_request_id, &mut rng)
        .unwrap();
    chain.submit(Tx::SubmitCommitment {
        request_id: bogus_request_id,
        validator: some_id,
        commitments,
    });
    let results = chain.commit_block();
    assert!(matches!(results[0].1, Err(_)));
}
