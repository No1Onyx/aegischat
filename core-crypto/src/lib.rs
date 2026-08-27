pub mod identity;
pub mod aead;
pub mod kdf;
pub mod double_ratchet;
pub mod sealed_sender;
pub mod safety_number;
pub mod storage;
pub mod ffi;
pub mod mesh_discovery;

pub use identity::{IdentityVault, PublicIdentityBundle};
pub use aead::{encrypt_aead, decrypt_aead, SymmetricKey};
pub use double_ratchet::{DoubleRatchetState, EncryptedWireMessage, RatchetHeader};
pub use sealed_sender::{seal_message, unseal_message, SealedSenderEnvelope};
pub use safety_number::compute_safety_number;
pub use storage::{EncryptedDatabase, StoredChatMessage, DatabaseContent};
pub use mesh_discovery::{MeshBeacon, MeshBeaconManager};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_zero_anchor_identity_and_mnemonic_recovery() {
        // 1. Generate new identity
        let alice = IdentityVault::generate_new();
        assert_eq!(alice.mnemonic.split_whitespace().count(), 12);

        // 2. Recover from mnemonic
        let alice_recovered = IdentityVault::from_mnemonic_str(&alice.mnemonic).expect("Recovery must succeed");
        assert_eq!(alice.ed25519_verifying_key.as_bytes(), alice_recovered.ed25519_verifying_key.as_bytes());
        assert_eq!(alice.x25519_identity_public.as_bytes(), alice_recovered.x25519_identity_public.as_bytes());
    }

    #[test]
    fn test_identity_derivation_cross_impl_vector() {
        // Canonical BIP-39 all-zero-entropy mnemonic. These public keys are the
        // shared contract between the Rust core and the TypeScript client
        // (client/src/crypto/primitives.ts deriveIdentityFromMnemonic). If this
        // vector changes, restore-from-seed interop is broken — do not "fix" the
        // test without updating both sides.
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let v = IdentityVault::from_mnemonic_str(m).expect("valid mnemonic");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(v.ed25519_verifying_key.as_bytes()),
            "hDYSjEsTrA/teLyscrqXESpWiBcZrXkEASHVZx+YGTA="
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(v.x25519_identity_public.as_bytes()),
            "+z7q9nrzovnqDoap1LRJHG8xQSEeh6K7i+wvPgj3djY="
        );
        // Blind delivery token must also match the TS client
        // (client/src/crypto/primitives.ts blindDeliveryToken).
        assert_eq!(
            v.compute_blind_delivery_token(),
            "edpq9L4YWwMOlnEca3dJvoXRDmCTomzCS6QM/XZjYDs="
        );
    }

    #[test]
    fn test_double_ratchet_full_conversation_cycle() {
        let master_shared_secret = [42u8; 32];

        let mut rng = rand::thread_rng();
        let bob_dhr_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let bob_dhr_public = x25519_dalek::PublicKey::from(&bob_dhr_secret);

        // Initialize Alice (Initiator) and Bob (Responder)
        let mut alice = DoubleRatchetState::init_alice(master_shared_secret, bob_dhr_public);
        let mut bob = DoubleRatchetState::init_bob(master_shared_secret, Some(bob_dhr_secret));

        // Alice -> Bob: Message 1
        let text1 = b"Freedom of speech is a fundamental human right.";
        let wire1 = alice.encrypt(text1).expect("Encryption must succeed");
        let dec1 = bob.decrypt(&wire1).expect("Decryption must succeed");
        assert_eq!(dec1, text1);

        // Alice -> Bob: Message 2 (Forward Secrecy in same chain)
        let text2 = b"Second message under same DH ratchet turn.";
        let wire2 = alice.encrypt(text2).expect("Encryption must succeed");
        let dec2 = bob.decrypt(&wire2).expect("Decryption must succeed");
        assert_eq!(dec2, text2);

        // Bob -> Alice: Message 3 (DH Ratchet step + Root Key Rotation)
        let text3 = b"Acknowledged. Rotating Diffie-Hellman keys now.";
        let wire3 = bob.encrypt(text3).expect("Encryption must succeed");
        let dec3 = alice.decrypt(&wire3).expect("Decryption must succeed");
        assert_eq!(dec3, text3);

        assert_eq!(alice.ratchet_step_count, 2);
        assert_eq!(bob.ratchet_step_count, 1);
    }

    #[test]
    fn test_sealed_sender_metadata_stripping() {
        let alice = IdentityVault::generate_new();
        let bob = IdentityVault::generate_new();

        let recipient_blind_token = bob.compute_blind_delivery_token();
        let transport_key = SymmetricKey::from_bytes([99u8; 32]);

        // Fake a ratchet wire message
        let dummy_wire = EncryptedWireMessage {
            header: RatchetHeader {
                ratchet_key: "AAAA".to_string(),
                message_number: 0,
                previous_chain_length: 0,
            },
            nonce: "BBBB".to_string(),
            ciphertext: "CCCC".to_string(),
        };

        // Seal message
        let envelope = seal_message(
            &alice.ed25519_signing_key,
            recipient_blind_token.clone(),
            &transport_key,
            dummy_wire,
            1720000000,
        ).expect("Sealing must succeed");

        // The outer envelope contains ZERO sender information
        assert_eq!(envelope.recipient_blind_token, recipient_blind_token);

        // Recipient unseals and verifies signature
        let unsealed = unseal_message(&transport_key, &envelope).expect("Unsealing must succeed");
        assert_eq!(
            unsealed.sender_verifying_key_ed25519,
            base64::engine::general_purpose::STANDARD.encode(alice.ed25519_verifying_key.as_bytes())
        );
    }

    #[test]
    fn test_safety_number_matching() {
        let alice = IdentityVault::generate_new();
        let bob = IdentityVault::generate_new();

        let alice_view = compute_safety_number(
            alice.ed25519_verifying_key.as_bytes(),
            bob.ed25519_verifying_key.as_bytes(),
        );

        let bob_view = compute_safety_number(
            bob.ed25519_verifying_key.as_bytes(),
            alice.ed25519_verifying_key.as_bytes(),
        );

        assert_eq!(alice_view, bob_view);
        assert_eq!(alice_view.len(), 12);
    }

    #[test]
    fn test_tamper_rejection() {
        let key = SymmetricKey::from_bytes([77u8; 32]);
        let msg = b"Top secret data";
        let encrypted = encrypt_aead(&key, msg, b"aad").unwrap();

        // Tamper with one byte of the ciphertext
        let mut tampered_ciphertext = encrypted.ciphertext.clone();
        let last_idx = tampered_ciphertext.len() - 1;
        tampered_ciphertext[last_idx] ^= 0xFF;

        let result = decrypt_aead(&key, &encrypted.nonce, &tampered_ciphertext, b"aad");
        assert!(result.is_err(), "Tampered ciphertext must be rejected by Poly1305 MAC");
    }

    #[test]
    fn test_encrypted_database_argon2id_lifecycle() {
        let test_db_path = "test_encrypted.aegis";
        let passphrase = "UltraSecureFreedomPassphrase2026!";
        let wrong_passphrase = "WrongPassword123";

        // Clean up any stale file
        let _ = std::fs::remove_file(test_db_path);

        // 1. Create database
        let mut db = EncryptedDatabase::create_new(test_db_path, passphrase).expect("DB creation must succeed");

        // 2. Store message
        let msg = StoredChatMessage {
            id: "msg_1".to_string(),
            peer: "Bob".to_string(),
            sender: "Alice".to_string(),
            text: "This text is encrypted with Argon2id on disk.".to_string(),
            timestamp: 1720000000,
            expires_at: None,
            is_self: true,
            ratchet_step: 1,
        };
        db.store_message(msg).expect("Message store must succeed");

        // 3. Opening with wrong passphrase must fail
        let open_wrong = EncryptedDatabase::open(test_db_path, wrong_passphrase, None);
        assert!(open_wrong.is_err(), "Opening with wrong password must fail");

        // 4. Opening with correct passphrase must succeed
        let open_correct = EncryptedDatabase::open(test_db_path, passphrase, None).expect("Must open with correct password");
        assert_eq!(open_correct.content.messages.len(), 1);
        assert_eq!(open_correct.content.messages[0].text, "This text is encrypted with Argon2id on disk.");

        // Clean up
        let _ = std::fs::remove_file(test_db_path);
    }

    #[test]
    fn test_duress_emergency_wipe() {
        let test_db_path = "test_duress.aegis";
        let passphrase = "RealSecretPassword";
        let duress_code = "9999EmergencyPanic";

        let _ = std::fs::remove_file(test_db_path);

        // Create db
        let _db = EncryptedDatabase::create_new(test_db_path, passphrase).expect("DB creation must succeed");
        assert!(std::path::Path::new(test_db_path).exists());

        // Trigger duress wipe
        let duress_attempt = EncryptedDatabase::open(test_db_path, duress_code, Some(duress_code));
        assert!(duress_attempt.is_err());
        assert!(duress_attempt.err().unwrap().contains("DURESS TRIGGERED"));

        // Verify the database file was shredded and removed
        assert!(!std::path::Path::new(test_db_path).exists(), "File must be deleted after duress wipe");
    }
}
