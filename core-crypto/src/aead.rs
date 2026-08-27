use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{RngCore, OsRng};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SymmetricKey {
    pub key: [u8; 32],
}

impl SymmetricKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }
}

pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

/// Encrypts plaintext using ChaCha20-Poly1305 with Associated Data (AD).
/// The Associated Data is cryptographically authenticated by Poly1305 tag without being encrypted.
pub fn encrypt_aead(
    key: &SymmetricKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPayload, &'static str> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| "ChaCha20-Poly1305 encryption failure")?;

    Ok(EncryptedPayload {
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypts ciphertext using ChaCha20-Poly1305 and verifies the authentication tag.
/// Any tampering with ciphertext or associated data immediately returns an error.
pub fn decrypt_aead(
    key: &SymmetricKey,
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| "ChaCha20-Poly1305 authentication failed: message was tampered or corrupted!")
}
