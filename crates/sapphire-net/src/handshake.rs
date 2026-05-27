//! Noise-XX handshake helpers.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` — three-message handshake,
//! both sides have static keys, mutually authenticated.
//!
//! ```text
//!   initiator              responder
//!      |  ── e ─────────────► |
//!      | ◄──── e, ee, s, es ─ |
//!      |  ── s, se ─────────► |
//!      └─────────┬────────────┘
//!         TransportState
//! ```
//!
//! After the handshake, [`snow::HandshakeState::get_remote_static`] reveals
//! the peer's static public key, which the caller can match against its
//! expected peer set to identify *which* validator this connection is to/from.

use std::io;

use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Build a fresh `snow::Builder` with the Sapphire pattern.
pub fn builder() -> snow::Builder<'static> {
    let params = NOISE_PATTERN
        .parse()
        .expect("Noise pattern compiles in build()");
    snow::Builder::new(params)
}

/// Run the initiator side of a Noise XX handshake over `stream`.
///
/// `local_static_secret` is this node's static X25519 private key. On
/// success, returns the post-handshake `TransportState` plus the peer's
/// static public key (caller maps it to a validator identifier).
pub async fn run_initiator(
    stream: &mut TcpStream,
    local_static_secret: &[u8; 32],
) -> io::Result<(TransportState, [u8; 32])> {
    let mut state: HandshakeState = builder()
        .local_private_key(local_static_secret)
        .build_initiator()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("noise build: {e}")))?;

    // msg 1: -> e
    write_msg(stream, &mut state, &[]).await?;
    // msg 2: <- e, ee, s, es
    let _ = read_msg(stream, &mut state).await?;
    // msg 3: -> s, se
    write_msg(stream, &mut state, &[]).await?;

    finish(state)
}

/// Run the responder side of a Noise XX handshake over `stream`.
pub async fn run_responder(
    stream: &mut TcpStream,
    local_static_secret: &[u8; 32],
) -> io::Result<(TransportState, [u8; 32])> {
    let mut state: HandshakeState = builder()
        .local_private_key(local_static_secret)
        .build_responder()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("noise build: {e}")))?;

    // msg 1: <- e
    let _ = read_msg(stream, &mut state).await?;
    // msg 2: -> e, ee, s, es
    write_msg(stream, &mut state, &[]).await?;
    // msg 3: <- s, se
    let _ = read_msg(stream, &mut state).await?;

    finish(state)
}

async fn write_msg(
    stream: &mut TcpStream,
    state: &mut HandshakeState,
    payload: &[u8],
) -> io::Result<()> {
    let mut buf = vec![0u8; 65535];
    let n = state
        .write_message(payload, &mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("handshake write: {e}")))?;
    let len_be = (n as u32).to_be_bytes();
    stream.write_all(&len_be).await?;
    stream.write_all(&buf[..n]).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_msg(stream: &mut TcpStream, state: &mut HandshakeState) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handshake msg too big",
        ));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    let mut out = vec![0u8; n];
    let m = state
        .read_message(&buf, &mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("handshake read: {e}")))?;
    out.truncate(m);
    Ok(out)
}

fn finish(state: HandshakeState) -> io::Result<(TransportState, [u8; 32])> {
    let remote_static = state
        .get_remote_static()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no remote static after XX"))?
        .to_vec();
    if remote_static.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected remote static length {}", remote_static.len()),
        ));
    }
    let mut remote = [0u8; 32];
    remote.copy_from_slice(&remote_static);
    let transport = state
        .into_transport_mode()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("noise transport: {e}")))?;
    Ok((transport, remote))
}

/// Generate a fresh static X25519 keypair for a validator. The 32-byte
/// secret is what goes into [`MeshConfig::local_static_secret`]; the public
/// is what peers list under [`PeerConfig::static_public`].
pub fn generate_static_keypair() -> ([u8; 32], [u8; 32]) {
    let kp = builder()
        .generate_keypair()
        .expect("snow generate_keypair never fails");
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    sk.copy_from_slice(&kp.private);
    pk.copy_from_slice(&kp.public);
    (sk, pk)
}
