//! Length-prefixed frames over a Noise-encrypted TCP stream.
//!
//! Wire format per frame:
//!
//! ```text
//!     | 4 bytes BE u32: ciphertext length | N bytes: ciphertext |
//! ```
//!
//! Crypto and network I/O are split so the caller can release the
//! [`TransportState`] mutex *between* the socket read/write and the
//! encrypt/decrypt step. Otherwise a long-blocking `read_exact` on one
//! direction would hold the lock and starve the other direction.

use std::io;

use snow::TransportState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// Plaintext payload size cap (leaves room for Noise's 16-byte AEAD tag).
pub const MAX_PAYLOAD: usize = 65535 - 16;

/// Read one length-prefixed *encrypted* frame off the wire. Doesn't touch
/// the [`TransportState`] — caller decrypts via [`decrypt_frame`] under the
/// lock.
pub async fn read_frame_bytes(reader: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > MAX_PAYLOAD + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame {} exceeds {}", n, MAX_PAYLOAD + 16),
        ));
    }
    let mut ct = vec![0u8; n];
    reader.read_exact(&mut ct).await?;
    Ok(ct)
}

/// Decrypt a frame produced by [`read_frame_bytes`].
pub fn decrypt_frame(transport: &mut TransportState, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let mut pt = vec![0u8; ciphertext.len()];
    let m = transport
        .read_message(ciphertext, &mut pt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("noise decrypt: {e}")))?;
    pt.truncate(m);
    Ok(pt)
}

/// Encrypt `payload` under the transport state, returning the bytes to
/// write on the wire (no length prefix yet — [`write_frame_bytes`] adds it).
pub fn encrypt_frame(transport: &mut TransportState, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payload {} exceeds {}", payload.len(), MAX_PAYLOAD),
        ));
    }
    let mut ct = vec![0u8; payload.len() + 16];
    let n = transport
        .write_message(payload, &mut ct)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("noise encrypt: {e}")))?;
    ct.truncate(n);
    Ok(ct)
}

/// Send a pre-encrypted frame, prefixing it with its length.
pub async fn write_frame_bytes(
    writer: &mut OwnedWriteHalf,
    ciphertext: &[u8],
) -> io::Result<()> {
    let len_be = (ciphertext.len() as u32).to_be_bytes();
    writer.write_all(&len_be).await?;
    writer.write_all(ciphertext).await?;
    writer.flush().await?;
    Ok(())
}
