//! Mesh integration test: four nodes converge on the same chain state.
//!
//! Spins up four `sapphire-net::Mesh` nodes on localhost ports, has node 0
//! broadcast a `Tx::DkgBegin`, and asserts that all four end up with
//! `state.ceremony == Some(_)` after a tick. This proves the mesh's
//! authenticated gossip path delivers `Tx<C>` end-to-end and that the
//! deterministic state machine converges without any central coordinator.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use frost_ed25519::Ed25519Sha512 as Cs;
use sapphire_chain::{
    dkg_envelope::EncPublicKey,
    state::{apply_tx, State},
    tx::Tx,
};
use sapphire_core::MpcParams;
use sapphire_net::{generate_static_keypair, Mesh, MeshConfig, PeerConfig};

const N: u16 = 4;

fn make_identifiers() -> Vec<frost_core::Identifier<Cs>> {
    (1..=N)
        .map(|i| i.try_into().expect("valid identifier"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_node_mesh_converges_on_dkg_begin() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("sapphire_net=debug")
        .try_init();

    // ---- Set up keypairs + addresses ----
    let mut keypairs = Vec::with_capacity(N as usize);
    let mut addrs: Vec<SocketAddr> = Vec::with_capacity(N as usize);
    for _ in 0..N {
        keypairs.push(generate_static_keypair());
        // OS-assigned port — bind to :0, then read .local_addr() — except we
        // need ports known *before* boot so peers can dial. Allocate sockets
        // first and pick free ports.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        addrs.push(listener.local_addr().unwrap());
        // Drop the listener; tokio rebinds the same port in start() below.
        // There's a small race window where another process could grab the
        // port — fine for tests.
        drop(listener);
    }

    // ---- Boot N meshes, each with the other N-1 as peers ----
    let mut meshes = Vec::with_capacity(N as usize);
    let mut incomings = Vec::with_capacity(N as usize);
    for i in 0..N as usize {
        let (local_sk, local_pk) = keypairs[i];
        let peers: Vec<PeerConfig> = (0..N as usize)
            .filter(|j| *j != i)
            .map(|j| PeerConfig {
                addr: addrs[j],
                static_public: keypairs[j].1,
            })
            .collect();
        let (mesh, incoming) = Mesh::start(MeshConfig {
            local_static_secret: local_sk,
            local_static_public: local_pk,
            bind_addr: addrs[i],
            peers,
        })
        .await
        .expect("mesh start");
        meshes.push(mesh);
        incomings.push(incoming);
    }

    // Give the dial/accept loops a moment to settle.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // ---- Node 0 broadcasts DkgBegin ----
    let params = MpcParams::new(3, N).unwrap();
    let ids = make_identifiers();
    let validators: BTreeMap<_, _> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            // The DKG enc_public here is unrelated to the mesh static key; we
            // just need *some* X25519 pubkey for the ceremony field. Use the
            // mesh static pubkey bytes — they're X25519 too.
            (*id, EncPublicKey(keypairs[i].1))
        })
        .collect();
    let begin = Tx::<Cs>::DkgBegin { params, validators };
    let bytes = serde_json::to_vec(&begin).unwrap();
    let receivers = meshes[0].broadcast(bytes.clone());
    assert!(receivers >= (N - 1) as usize, "node 0 has {} writers", receivers);

    // Locally apply on node 0 too (broadcast goes to peers only).
    let mut states: Vec<State<Cs>> = (0..N as usize).map(|_| State::<Cs>::default()).collect();
    states[0] = apply_tx(&states[0], &begin).unwrap();

    // ---- Pull one frame off each other node's incoming queue ----
    for i in 1..N as usize {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            incomings[i].recv(),
        )
        .await
        .unwrap_or_else(|_| panic!("node {} timed out waiting for DkgBegin", i))
        .expect("incoming channel open");
        let tx: Tx<Cs> = serde_json::from_slice(&frame).unwrap();
        states[i] = apply_tx(&states[i], &tx).unwrap();
    }

    // ---- Every node should see the ceremony ----
    for (i, s) in states.iter().enumerate() {
        assert!(
            s.ceremony.is_some(),
            "node {} did not converge: ceremony is None",
            i
        );
        assert_eq!(s.ceremony.as_ref().unwrap().validators.len(), N as usize);
    }
}
