//! RedPallas (Zcash Orchard spend-auth) integration test.
//!
//! Exercises the same in-process FROST signing pipeline as `end_to_end.rs`
//! but with the Pallas-curve ciphersuite, demonstrating Sapphire's core is
//! truly generic over ciphersuite.
//!
//! Note: this signs with the *plain* RedPallas FROST ciphersuite. Production
//! Zcash spend authorization additionally requires the per-spend randomizer
//! from the Orchard bundle (`frost-rerandomized`); that integration lives in
//! V0.3 alongside Zcash transaction assembly via `librustzcash`.

use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;
use reddsa::frost::redpallas::PallasBlake2b512;

use sapphire_client::LocalTransport;
use sapphire_coordinator::{verify, Coordinator};
use sapphire_core::{protocol::KeyShareBundle, MpcParams};
use sapphire_keygen::generate_with_trusted_dealer;
use sapphire_signer::Signer;

type Cs = PallasBlake2b512;

#[tokio::test]
async fn redpallas_two_of_three_round_trip() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) =
        generate_with_trusted_dealer::<Cs, _>(params, &mut rng).unwrap();

    let mut signers = BTreeMap::new();
    for (id, kp) in key_packages {
        let bundle = KeyShareBundle {
            key_package: kp,
            public_key_package: pkp.clone(),
        };
        signers.insert(id, Arc::new(Signer::<Cs>::new(bundle)));
    }

    let participants: Vec<_> = signers.keys().copied().take(2).collect();
    let transport = LocalTransport::new(signers);
    let coord = Coordinator::new(params, pkp.clone());

    let message = b"hello pallas";
    let sig = coord
        .sign(&transport, message, &participants, &mut rng)
        .await
        .expect("RedPallas signing failed");
    verify(&pkp, message, &sig).expect("RedPallas verification failed");

    // Sanity-check the signature serializes to the expected length for Pallas:
    // 32-byte R + 32-byte s = 64 bytes.
    let bytes = sig.serialize().unwrap();
    assert_eq!(bytes.len(), 64, "expected 64-byte RedPallas Schnorr sig");
}
