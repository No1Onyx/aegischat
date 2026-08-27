use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::aead::{encrypt_aead, decrypt_aead, SymmetricKey};
use crate::double_ratchet::EncryptedWireMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedSenderInnerPayload {
    pub sender_verifying_key_ed25519: String,
    pub timestamp: u64,
    pub double_ratchet_message: EncryptedWireMessage,
    pub signature: String, // Ed25519 signature over ratchet_message + timestamp
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedSenderEnvelope {
    pub recipient_blind_token: String, // Visible to server for blind routing
    pub ephemeral_nonce: String,
    pub encrypted_inner_payload: String, // Opaque to server; only recipient can decrypt
}

/// Seals an encrypted message inside an anonymous outer envelope.
/// The relay server sees ONLY the recipient_blind_token and cannot identify the sender.
pub fn seal_message(
    sender_signing_key: &SigningKey,
    recipient_blind_token: String,
    recipient_transport_key: &SymmetricKey,
    wire_message: EncryptedWireMessage,
    timestamp: u64,
) -> Result<SealedSenderEnvelope, &'static str> {
    let wire_bytes = serde_json::to_vec(&wire_message).map_err(|_| "Serialization error")?;

    // Sign the inner message + timestamp with sender's identity key
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&timestamp.to_be_bytes());
    sign_data.extend_from_slice(&wire_bytes);

    let signature = sender_signing_key.sign(&sign_data);
    let sender_pub = sender_signing_key.verifying_key();

    let inner = SealedSenderInnerPayload {
        sender_verifying_key_ed25519: BASE64.encode(sender_pub.as_bytes()),
        timestamp,
        double_ratchet_message: wire_message,
        signature: BASE64.encode(signature.to_bytes()),
    };

    let inner_json = serde_json::to_vec(&inner).map_err(|_| "Serialization error")?;

    // Encrypt inner payload with recipient's transport key (Associated data = blind token)
    let encrypted = encrypt_aead(recipient_transport_key, &inner_json, recipient_blind_token.as_bytes())?;

    Ok(SealedSenderEnvelope {
        recipient_blind_token,
        ephemeral_nonce: BASE64.encode(&encrypted.nonce),
        encrypted_inner_payload: BASE64.encode(&encrypted.ciphertext),
    })
}

/// Unseals an anonymous envelope on the recipient's device and verifies the sender's signature.
pub fn unseal_message(
    recipient_transport_key: &SymmetricKey,
    envelope: &SealedSenderEnvelope,
) -> Result<SealedSenderInnerPayload, &'static str> {
    let nonce_bytes = BASE64.decode(&envelope.ephemeral_nonce)
        .map_err(|_| "Invalid nonce base64")?;
    if nonce_bytes.len() != 12 {
        return Err("Nonce must be 12 bytes");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let ciphertext = BASE64.decode(&envelope.encrypted_inner_payload)
        .map_err(|_| "Invalid ciphertext base64")?;

    // Decrypt inner payload using transport key
    let decrypted_inner_json = decrypt_aead(
        recipient_transport_key,
        &nonce,
        &ciphertext,
        envelope.recipient_blind_token.as_bytes(),
    )?;

    let inner: SealedSenderInnerPayload = serde_json::from_slice(&decrypted_inner_json)
        .map_err(|_| "Failed to deserialize inner sealed sender payload")?;

    // Verify sender's signature to prevent impersonation
    let sender_pub_bytes = BASE64.decode(&inner.sender_verifying_key_ed25519)
        .map_err(|_| "Invalid sender key base64")?;
    if sender_pub_bytes.len() != 32 {
        return Err("Sender key must be 32 bytes");
    }
    let mut sender_key_arr = [0u8; 32];
    sender_key_arr.copy_from_slice(&sender_pub_bytes);
    let verifying_key = VerifyingKey::from_bytes(&sender_key_arr)
        .map_err(|_| "Invalid Ed25519 verifying key")?;

    let sig_bytes = BASE64.decode(&inner.signature)
        .map_err(|_| "Invalid signature base64")?;
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes");
    }
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| "Invalid signature format")?;

    let wire_bytes = serde_json::to_vec(&inner.double_ratchet_message)
        .map_err(|_| "Serialization error")?;
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&inner.timestamp.to_be_bytes());
    sign_data.extend_from_slice(&wire_bytes);

    verifying_key
        .verify(&sign_data, &signature)
        .map_err(|_| "CRYPTOGRAPHIC VERIFICATION FAILED: Sender signature invalid!")?;

    Ok(inner)
}
