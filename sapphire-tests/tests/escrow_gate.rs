//! Increment 2 end-to-end: the validating signer.
//!
//! Proves that a `Node` configured with an `EscrowPolicy` will only contribute
//! its FROST share to a release that matches the escrow terms it independently
//! holds — and refuses (emits no commitment) for one that doesn't. The refusal
//! is enforced *inside* `react`, not by an external caller.

use frost_core::{Ciphersuite, Field, Group};
use frost_rerandomized::{RandomizedParams, Randomizer};
use rand::rngs::OsRng;
use reddsa::frost::redpallas::PallasBlake2b512;

use sapphire_chain::{sim::ChainSim, state::RequestStatus, tx::Tx};
use sapphire_core::{
    protocol::{uuid_lite::Uuid, KeyShareBundle},
    MpcParams,
};
use sapphire_escrow::{
    verifiers::HashPreimage, Address, EscrowTerms, PaymentLeg, ReleaseProposal, SettlementIntent,
    Zatoshis,
};
use sapphire_keygen::generate_with_dkg;
use sapphire_node::{EscrowPolicy, Node};

type Cs = PallasBlake2b512;

fn fresh_randomizer(rng: &mut OsRng) -> Randomizer<Cs> {
    let scalar = <<<Cs as Ciphersuite>::Group as Group>::Field as Field>::random(rng);
    Randomizer::<Cs>::from_scalar(scalar)
}

const SECRET: &[u8] = b"parcel #4417 delivered";

fn demo_terms() -> EscrowTerms {
    EscrowTerms {
        escrow_id: [0x5a; 32],
        amount: Zatoshis(800_000_000),
        payee: Address("u_alice".into()),
        refund_to: Address("u_bob".into()),
        timeout_height: 1_000,
        condition: HashPreimage::digest(SECRET).to_vec(),
    }
}

/// Build a 2-of-3 group whose nodes each enforce the escrow policy for
/// `demo_terms()`, then `InitGroup` it onto a fresh chain.
fn group_with_escrow_policy(rng: &mut OsRng) -> (ChainSim<Cs>, Vec<Node<Cs>>, sapphire_core::frost::keys::PublicKeyPackage<Cs>) {
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, rng).unwrap();

    let validators: Vec<Node<Cs>> = key_packages
        .into_iter()
        .map(|(_, kp)| {
            Node::new(KeyShareBundle {
                key_package: kp,
                public_key_package: pkp.clone(),
            })
            .with_policy(EscrowPolicy::new(HashPreimage).with_escrow(demo_terms()))
        })
        .collect();

    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: validators.iter().map(|v| v.identifier).collect(),
    });
    chain.commit_block();
    assert!(chain.state.group.is_some());
    (chain, validators, pkp)
}

/// Drive react/commit until terminal or `max_blocks` exhausted.
fn drive(chain: &mut ChainSim<Cs>, validators: &mut [Node<Cs>], rng: &mut OsRng, max_blocks: usize) {
    for _ in 0..max_blocks {
        let mut emitted = false;
        for v in validators.iter_mut() {
            for tx in v.react(&chain.state, rng).unwrap() {
                chain.submit(tx);
                emitted = true;
            }
        }
        chain.commit_block();
        if !emitted {
            break;
        }
    }
}

#[test]
fn valid_release_is_signed() {
    let mut rng = OsRng;
    let (mut chain, mut validators, pkp) = group_with_escrow_policy(&mut rng);

    // A correct release: pay the agreed price to the agreed payee, revealing
    // the preimage as the witness.
    let proposal = ReleaseProposal {
        escrow_id: demo_terms().escrow_id,
        intent: SettlementIntent {
            payment: PaymentLeg {
                amount: Zatoshis(800_000_000),
                to: Address("u_alice".into()),
            },
            witness: SECRET.to_vec(),
        },
    };
    let message = serde_json::to_vec(&proposal).unwrap();
    let randomizer = fresh_randomizer(&mut rng);
    let request_id = Uuid::new(&mut rng);
    chain.submit(Tx::SubmitRequest {
        request_id,
        message: message.clone(),
        randomizer,
    });
    chain.commit_block();

    drive(&mut chain, &mut validators, &mut rng, 8);

    let entry = chain.state.requests.get(&request_id).unwrap();
    let signature = match &entry.status {
        RequestStatus::Completed { signature, .. } => signature.clone(),
        other => panic!("expected Completed for a valid release, got: {:?}", other),
    };
    // The signature authorizes exactly these bytes, under the rerandomized key.
    RandomizedParams::<Cs>::from_randomizer(pkp.verifying_key(), randomizer)
        .randomized_verifying_key()
        .verify(&message, &signature)
        .expect("signature must verify against the rerandomized key");
}

#[test]
fn tampered_release_gets_no_signature() {
    let mut rng = OsRng;
    let (mut chain, mut validators, _pkp) = group_with_escrow_policy(&mut rng);

    // Same money, same valid preimage — but redirected to an attacker. The
    // payment leg no longer matches the trusted terms' payee.
    let proposal = ReleaseProposal {
        escrow_id: demo_terms().escrow_id,
        intent: SettlementIntent {
            payment: PaymentLeg {
                amount: Zatoshis(800_000_000),
                to: Address("u_attacker".into()),
            },
            witness: SECRET.to_vec(),
        },
    };
    let message = serde_json::to_vec(&proposal).unwrap();
    let request_id = Uuid::new(&mut rng);
    chain.submit(Tx::SubmitRequest {
        request_id,
        message,
        randomizer: fresh_randomizer(&mut rng),
    });
    chain.commit_block();

    drive(&mut chain, &mut validators, &mut rng, 8);

    // Every honest node refused, so the request never left AwaitingCommitments
    // and not a single commitment was collected.
    let entry = chain.state.requests.get(&request_id).unwrap();
    match &entry.status {
        RequestStatus::AwaitingCommitments { commitments } => {
            assert!(
                commitments.is_empty(),
                "no validator should have committed to a tampered release"
            );
        }
        other => panic!("tampered release must NOT progress; got: {:?}", other),
    }
}

#[test]
fn unknown_escrow_is_refused() {
    let mut rng = OsRng;
    let (mut chain, mut validators, _pkp) = group_with_escrow_policy(&mut rng);

    // Correct shape, but an escrow id the nodes don't know about.
    let proposal = ReleaseProposal {
        escrow_id: [0xee; 32],
        intent: SettlementIntent {
            payment: PaymentLeg {
                amount: Zatoshis(800_000_000),
                to: Address("u_alice".into()),
            },
            witness: SECRET.to_vec(),
        },
    };
    let message = serde_json::to_vec(&proposal).unwrap();
    let request_id = Uuid::new(&mut rng);
    chain.submit(Tx::SubmitRequest {
        request_id,
        message,
        randomizer: fresh_randomizer(&mut rng),
    });
    chain.commit_block();

    drive(&mut chain, &mut validators, &mut rng, 8);

    let entry = chain.state.requests.get(&request_id).unwrap();
    assert!(
        matches!(&entry.status, RequestStatus::AwaitingCommitments { commitments } if commitments.is_empty()),
        "unknown escrow must be refused; got: {:?}",
        entry.status
    );
}

#[test]
fn default_node_still_signs_arbitrary_messages() {
    // Sanity: a Node *without* a policy is still a blind signer (AcceptAll),
    // so the generic FROST path is unchanged.
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();
    let mut validators: Vec<Node<Cs>> = key_packages
        .into_iter()
        .map(|(_, kp)| {
            Node::new(KeyShareBundle {
                key_package: kp,
                public_key_package: pkp.clone(),
            })
        })
        .collect();
    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: validators.iter().map(|v| v.identifier).collect(),
    });
    chain.commit_block();

    let request_id = Uuid::new(&mut rng);
    chain.submit(Tx::SubmitRequest {
        request_id,
        message: b"arbitrary bytes, no escrow".to_vec(),
        randomizer: fresh_randomizer(&mut rng),
    });
    chain.commit_block();
    drive(&mut chain, &mut validators, &mut rng, 8);

    assert!(matches!(
        chain.state.requests.get(&request_id).unwrap().status,
        RequestStatus::Completed { .. }
    ));
}
