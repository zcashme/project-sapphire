//! End-to-end HTTP transport test.
//!
//! Spins up N signer HTTP servers on ephemeral localhost ports, then drives a
//! signing round through `HttpTransport`. Verifies the signature against the
//! group public key.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use frost_ed25519::Ed25519Sha512;
use rand::rngs::OsRng;
use tokio::time::sleep;

use sapphire_client::HttpTransport;
use sapphire_coordinator::{verify, Coordinator};
use sapphire_core::{protocol::KeyShareBundle, MpcParams};
use sapphire_keygen::generate_with_trusted_dealer;
use sapphire_signer::{server, Signer};

type Cs = Ed25519Sha512;

async fn pick_addr() -> SocketAddr {
    // Bind 0 → ask the OS for an ephemeral port, then immediately drop the listener
    // so the signer server can bind it. There's a brief race window in theory, but
    // in practice the kernel doesn't recycle the port that fast.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_two_of_three_round_trip() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();
    let (key_packages, pkp) =
        generate_with_trusted_dealer::<Cs, _>(params, &mut rng).unwrap();

    // Spawn one server per signer; collect (Identifier, URL) pairs.
    let mut base_urls: BTreeMap<frost_core::Identifier<Cs>, String> = BTreeMap::new();
    let mut handles = Vec::new();
    for (id, kp) in key_packages {
        let bundle = KeyShareBundle {
            key_package: kp,
            public_key_package: pkp.clone(),
        };
        let signer = Arc::new(Signer::new(bundle));
        let addr = pick_addr().await;
        base_urls.insert(id, format!("http://{}", addr));
        let s = signer.clone();
        let h = tokio::spawn(async move {
            server::serve(s, addr).await.unwrap();
        });
        handles.push(h);
    }

    // Give servers a moment to bind.
    sleep(Duration::from_millis(100)).await;

    let participants: Vec<_> = base_urls.keys().copied().take(2).collect();
    let transport = HttpTransport::<Cs>::new(base_urls);
    let coord = Coordinator::new(params, pkp.clone());

    let message = b"hello sapphire over http";
    let sig = coord
        .sign(&transport, message, &participants, &mut rng)
        .await
        .expect("signing failed");
    verify(&pkp, message, &sig).expect("verification failed");

    // Shut down servers (in tests we can just abort the tasks).
    for h in handles {
        h.abort();
    }
}
