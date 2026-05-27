//! DKG → signing integration test.
//!
//! Exercises the V0.2 path: generate a group via FROST DKG (no trusted
//! dealer ever sees the full key), then drive a signing round and verify.

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_ed25519::Ed25519Sha512;
use rand::rngs::OsRng;

use sapphire_client::LocalTransport;
use sapphire_coordinator::{verify, Coordinator};
use sapphire_core::{protocol::KeyShareBundle, MpcParams};
use sapphire_keygen::generate_with_dkg;
use sapphire_signer::Signer;

type Cs = Ed25519Sha512;

#[tokio::test]
async fn dkg_three_of_five_then_sign() {
    let mut rng = OsRng;
    let params = MpcParams::new(3, 5).unwrap();
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();

    let mut signers = BTreeMap::new();
    for (id, kp) in key_packages {
        let bundle = KeyShareBundle {
            key_package: kp,
            public_key_package: pkp.clone(),
        };
        signers.insert(id, Arc::new(Signer::<Cs>::new(bundle)));
    }

    let participants: Vec<_> = signers.keys().copied().take(3).collect();
    let transport = LocalTransport::new(signers);
    let coord = Coordinator::new(params, pkp.clone());

    let message = b"signed after dkg, no trusted dealer";
    let sig = coord
        .sign(&transport, message, &participants, &mut rng)
        .await
        .expect("signing failed");
    verify(&pkp, message, &sig).expect("verification failed");
}
