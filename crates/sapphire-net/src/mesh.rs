//! Validator mesh: dial peers, accept incoming, broadcast opaque frames.
//!
//! Connection topology: each validator dials every peer whose Noise static
//! public key has higher byte-order than its own, and accepts incoming
//! connections from peers with lower keys. With `n` validators that's
//! `n(n-1)/2` authenticated bidirectional channels, each carrying both
//! sides' broadcasts.
//!
//! Wire-layer reasoning: the mesh moves *opaque bytes*. It deliberately
//! doesn't know about `Tx<C>` because FROST ciphersuite associated types
//! don't carry blanket `Send + Sync` bounds, and tokio's multi-threaded
//! scheduler needs them. The serialization happens at the [`Mesh::broadcast`]
//! call site (caller's thread, where `Tx<C>` is already in hand); the
//! receiver yields raw frames and the caller's reactor loop deserializes
//! before applying. Sapphire-chain types stay invisible to the network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use snow::TransportState;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::codec::{decrypt_frame, encrypt_frame, read_frame_bytes, write_frame_bytes};
use crate::handshake::{run_initiator, run_responder};

/// One peer in the validator mesh.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Where to dial (only used for peers we dial — i.e. peers whose static
    /// public key is greater than ours).
    pub addr: SocketAddr,
    /// Their long-term Noise static public key. The handshake authenticates
    /// the remote against this; mismatch closes the connection.
    pub static_public: [u8; 32],
}

/// Local mesh node configuration.
pub struct MeshConfig {
    pub local_static_secret: [u8; 32],
    pub local_static_public: [u8; 32],
    pub bind_addr: SocketAddr,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("handshake completed but remote static {seen:?} not in expected peer set")]
    UnknownPeer { seen: [u8; 32] },
}

/// Running mesh handle. Drop = drop task handles; the tasks themselves will
/// continue until their connections close (they don't poll the JoinHandles).
/// For v1 we don't implement explicit shutdown.
pub struct Mesh {
    local_static_public: [u8; 32],
    /// Fan-out channel: every connected outgoing-writer task subscribes.
    /// [`Mesh::broadcast`] pushes one frame that every per-peer writer sends.
    outgoing: broadcast::Sender<Vec<u8>>,
    _tasks: Vec<JoinHandle<()>>,
}

impl Mesh {
    /// Boot the mesh and return a handle plus a receiver of raw frames from
    /// peers. Each received frame is the bytes of one `serde_json::to_vec`
    /// of a sender-side payload (e.g. a `Tx<C>`). The caller deserializes
    /// and applies to its local state.
    pub async fn start(config: MeshConfig) -> Result<(Self, mpsc::Receiver<Vec<u8>>), MeshError> {
        let MeshConfig {
            local_static_secret,
            local_static_public,
            bind_addr,
            peers,
        } = config;

        // Set of allowed peer static pubkeys (for handshake authentication).
        let allowed: Arc<HashMap<[u8; 32], ()>> =
            Arc::new(peers.iter().map(|p| (p.static_public, ())).collect());

        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (outgoing_tx, _) = broadcast::channel::<Vec<u8>>(1024);

        let mut tasks = Vec::new();

        // ---- Listener: accept inbound from peers with lower static pubkey ----
        let listener = TcpListener::bind(bind_addr).await?;
        info!(?bind_addr, "mesh listening");
        let listener_secret = local_static_secret;
        let listener_allowed = allowed.clone();
        let listener_incoming = incoming_tx.clone();
        let listener_outgoing = outgoing_tx.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(?e, "accept failed");
                        continue;
                    }
                };
                debug!(?peer_addr, "incoming connection");
                let secret = listener_secret;
                let allowed = listener_allowed.clone();
                let incoming = listener_incoming.clone();
                let outgoing = listener_outgoing.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        serve_responder(stream, &secret, allowed, incoming, outgoing.subscribe())
                            .await
                    {
                        warn!(?e, ?peer_addr, "responder connection closed");
                    }
                });
            }
        }));

        // ---- Dialers: dial peers whose static pubkey is greater than ours ----
        for peer in &peers {
            if peer.static_public <= local_static_public {
                continue; // they dial us
            }
            let peer = peer.clone();
            let secret = local_static_secret;
            let allowed = allowed.clone();
            let incoming = incoming_tx.clone();
            let outgoing = outgoing_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) =
                    serve_initiator(peer, &secret, allowed, incoming, outgoing.subscribe()).await
                {
                    warn!(?e, "initiator connection closed");
                }
            }));
        }

        Ok((
            Self {
                local_static_public,
                outgoing: outgoing_tx,
                _tasks: tasks,
            },
            incoming_rx,
        ))
    }

    /// Send a payload to every connected peer. Returns the number of writer
    /// tasks that received the payload into their queue (≈ live connections).
    pub fn broadcast(&self, payload: Vec<u8>) -> usize {
        self.outgoing.send(payload).unwrap_or(0)
    }

    pub fn local_static_public(&self) -> [u8; 32] {
        self.local_static_public
    }
}

async fn serve_initiator(
    peer: PeerConfig,
    secret: &[u8; 32],
    allowed: Arc<HashMap<[u8; 32], ()>>,
    incoming: mpsc::Sender<Vec<u8>>,
    outgoing: broadcast::Receiver<Vec<u8>>,
) -> Result<(), MeshError> {
    let mut stream = retrying_connect(peer.addr).await?;
    let (transport, remote_static) = run_initiator(&mut stream, secret).await?;
    if remote_static != peer.static_public {
        return Err(MeshError::UnknownPeer {
            seen: remote_static,
        });
    }
    if !allowed.contains_key(&remote_static) {
        return Err(MeshError::UnknownPeer {
            seen: remote_static,
        });
    }
    info!(addr = ?peer.addr, "outbound peer authenticated");
    drive_connection(stream, transport, incoming, outgoing).await
}

async fn serve_responder(
    mut stream: TcpStream,
    secret: &[u8; 32],
    allowed: Arc<HashMap<[u8; 32], ()>>,
    incoming: mpsc::Sender<Vec<u8>>,
    outgoing: broadcast::Receiver<Vec<u8>>,
) -> Result<(), MeshError> {
    let (transport, remote_static) = run_responder(&mut stream, secret).await?;
    if !allowed.contains_key(&remote_static) {
        return Err(MeshError::UnknownPeer {
            seen: remote_static,
        });
    }
    info!("inbound peer authenticated");
    drive_connection(stream, transport, incoming, outgoing).await
}

async fn drive_connection(
    stream: TcpStream,
    transport: TransportState,
    incoming: mpsc::Sender<Vec<u8>>,
    mut outgoing: broadcast::Receiver<Vec<u8>>,
) -> Result<(), MeshError> {
    let (mut reader, mut writer) = stream.into_split();
    let transport = Arc::new(Mutex::new(transport));

    let reader_transport = transport.clone();
    let reader_incoming = incoming.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            let ct = match read_frame_bytes(&mut reader).await {
                Ok(b) => b,
                Err(e) => {
                    debug!(?e, "reader closed");
                    return;
                }
            };
            // Acquire the transport mutex only to decrypt — release it before
            // the next socket read so the writer task can proceed.
            let pt = {
                let mut t = reader_transport.lock().await;
                match decrypt_frame(&mut t, &ct) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(?e, "decrypt failed; closing reader");
                        return;
                    }
                }
            };
            if reader_incoming.send(pt).await.is_err() {
                debug!("incoming channel closed");
                return;
            }
        }
    });

    let writer_transport = transport.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            let payload = match outgoing.recv().await {
                Ok(p) => p,
                Err(broadcast::error::RecvError::Closed) => return,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(?n, "outgoing channel lagged; some payloads dropped");
                    continue;
                }
            };
            // Encrypt under the lock, release it, then write.
            let ct = {
                let mut t = writer_transport.lock().await;
                match encrypt_frame(&mut t, &payload) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(?e, "encrypt failed");
                        continue;
                    }
                }
            };
            if let Err(e) = write_frame_bytes(&mut writer, &ct).await {
                debug!(?e, "writer closed");
                let _ = writer.shutdown().await;
                return;
            }
        }
    });

    let _ = tokio::join!(reader_task, writer_task);
    debug!("connection torn down");
    Ok(())
}

async fn retrying_connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    use std::time::Duration;
    let mut delay = Duration::from_millis(20);
    for _ in 0..20 {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(_e) => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
        }
    }
    TcpStream::connect(addr).await
}
