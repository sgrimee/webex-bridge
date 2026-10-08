//! Authenticated encryption for mirrored personal free text.
//! Each column value has an independent random XChaCha20-Poly1305 nonce.

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

/// A 256-bit mirror key; intentionally not Debug or Clone.
pub struct MirrorCrypto {
    key: Zeroizing<[u8; 32]>,
}

impl MirrorCrypto {
    /// Construct from bytes retrieved from the user's Keychain.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid mirror encryption key"))
    }

    /// Seal bytes with a random per-value nonce and a row/column-specific AAD.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Mirror encryption failed"))?;
        Ok((ciphertext, nonce.to_vec()))
    }

    /// Authenticate and decrypt bytes, failing closed on a wrong key, row or nonce.
    pub fn open(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            bail!("Invalid mirror nonce length");
        }
        self.cipher()?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Mirror ciphertext authentication failed"))
    }

    /// Store a nonce prefix for columns without a separate nonce column.
    pub fn seal_prefixed(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let (ciphertext, mut nonce) = self.seal(plaintext, aad)?;
        nonce.extend_from_slice(&ciphertext);
        Ok(nonce)
    }

    /// Authenticate a nonce-prefixed value.
    pub fn open_prefixed(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ciphertext) = blob
            .split_at_checked(NONCE_LEN)
            .context("Mirror encrypted value has no nonce")?;
        self.open(ciphertext, nonce, aad)
    }
}

/// Bind ciphertext to its table, column and immutable row key.
#[must_use]
pub fn aad(table: &str, column: &str, row_key: &str) -> Vec<u8> {
    format!("webex-bridge/v1/{table}/{column}/{row_key}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_is_randomized_and_row_bound() {
        let crypto = MirrorCrypto::new([7_u8; 32]);
        let row = aad("messages", "body", "message-a/0");
        let (first, nonce_a) = crypto.seal(b"private body", &row).unwrap();
        let (second, nonce_b) = crypto.seal(b"private body", &row).unwrap();
        assert_ne!(nonce_a, nonce_b);
        assert_ne!(first, second);
        assert_eq!(
            crypto.open(&first, &nonce_a, &row).unwrap(),
            b"private body"
        );
        assert!(crypto
            .open(&first, &nonce_a, &aad("messages", "body", "message-b/0"))
            .is_err());
        let mut tampered = first;
        tampered[0] ^= 1;
        assert!(crypto.open(&tampered, &nonce_a, &row).is_err());
    }

    #[test]
    fn prefix_round_trip_and_truncation() {
        let crypto = MirrorCrypto::new([42_u8; 32]);
        let row = aad("rooms", "title", "room-id");
        let blob = crypto.seal_prefixed(b"Sensitive room name", &row).unwrap();
        assert_eq!(
            crypto.open_prefixed(&blob, &row).unwrap(),
            b"Sensitive room name"
        );
        assert!(crypto.open_prefixed(&blob[..10], &row).is_err());
    }
}
