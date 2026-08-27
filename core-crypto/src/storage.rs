use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::ZeroizeOnDrop;
use rand_core::{RngCore, OsRng};
use serde::{Serialize, Deserialize};

use crate::aead::{encrypt_aead, decrypt_aead, SymmetricKey};

const DB_MAGIC: &[u8; 4] = b"AEGS";
const DEFAULT_M_COST: u32 = 64 * 1024; // 64 MB memory-hard cost against GPU/ASIC attacks
const DEFAULT_T_COST: u32 = 3;         // 3 iterations
const DEFAULT_P_COST: u32 = 4;         // 4 parallel threads

/// Master encryption key for the database at rest, scrubbed on drop
#[derive(ZeroizeOnDrop)]
pub struct DatabaseMasterKey {
    pub key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredChatMessage {
    pub id: String,
    pub peer: String,
    pub sender: String,
    pub text: String,
    pub timestamp: u64,
    pub expires_at: Option<u64>, // For auto-disappearing / self-destructing messages
    pub is_self: bool,
    pub ratchet_step: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DatabaseContent {
    pub identity_mnemonic: Option<String>,
    pub contacts: Vec<String>,
    pub messages: Vec<StoredChatMessage>,
    pub sessions_json: HashMap<String, String>,
}

/// Anti-forensics encrypted database file on disk.
/// Protected by Argon2id key derivation and ChaCha20-Poly1305 AEAD.
pub struct EncryptedDatabase {
    pub path: String,
    pub salt: [u8; 16],
    pub master_key: DatabaseMasterKey,
    pub content: DatabaseContent,
    pub duress_passphrase_hash: Option<String>,
}

impl EncryptedDatabase {
    /// Derives a 32-byte Database Master Key from user passphrase using Argon2id (RFC 9106)
    pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<DatabaseMasterKey, &'static str> {
        let params = Params::new(DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST, Some(32))
            .map_err(|_| "Invalid Argon2 parameters")?;
        
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key_out = [0u8; 32];
        
        argon.hash_password_into(passphrase.as_bytes(), salt, &mut key_out)
            .map_err(|_| "Argon2id key derivation failed")?;

        Ok(DatabaseMasterKey { key: key_out })
    }

    /// Creates a new encrypted database file at the specified path
    pub fn create_new(file_path: &str, passphrase: &str) -> Result<Self, &'static str> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let master_key = Self::derive_key(passphrase, &salt)?;
        let content = DatabaseContent::default();

        let db = Self {
            path: file_path.to_string(),
            salt,
            master_key,
            content,
            duress_passphrase_hash: None,
        };

        db.save_to_disk()?;
        Ok(db)
    }

    /// Opens and decrypts an existing database.
    /// If a duress passphrase is provided, triggers anti-forensic emergency wipe.
    pub fn open(
        file_path: &str,
        passphrase: &str,
        duress_trigger_phrase: Option<&str>,
    ) -> Result<Self, &'static str> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err("Database file does not exist");
        }

        // Check if duress phrase was entered
        if let Some(duress) = duress_trigger_phrase {
            if !duress.is_empty() && passphrase == duress {
                Self::emergency_wipe(file_path)?;
                return Err("DURESS TRIGGERED: Database cryptographically wiped!");
            }
        }

        let mut file = File::open(path).map_err(|_| "Cannot open database file")?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|_| "Cannot read database file")?;

        if buffer.len() < 4 + 16 + 12 + 16 {
            return Err("Corrupt database file (too small)");
        }

        // 1. Verify Magic Header
        if &buffer[0..4] != DB_MAGIC {
            return Err("Invalid database header (Not an Aegis encrypted database)");
        }

        // 2. Extract Salt & Nonce
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buffer[4..20]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buffer[20..32]);

        let ciphertext = &buffer[32..];

        // 3. Derive Key via Argon2id
        let master_key = Self::derive_key(passphrase, &salt)?;
        let sym_key = SymmetricKey::from_bytes(master_key.key);

        // 4. Decrypt & Authenticate via ChaCha20-Poly1305 (AAD = Magic + Salt)
        let aad = &buffer[0..20];
        let decrypted_bytes = decrypt_aead(&sym_key, &nonce, ciphertext, aad)
            .map_err(|_| "INCORRECT PASSPHRASE or database was tampered with!")?;

        let mut content: DatabaseContent = serde_json::from_slice(&decrypted_bytes)
            .map_err(|_| "Corrupted database contents")?;

        // 5. Auto-scrub any expired disappearing messages on load
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        content.messages.retain(|msg| {
            match msg.expires_at {
                Some(exp) => exp > current_time,
                None => true,
            }
        });

        Ok(Self {
            path: file_path.to_string(),
            salt,
            master_key,
            content,
            duress_passphrase_hash: None,
        })
    }

    /// Encrypts and writes current state to disk
    pub fn save_to_disk(&self) -> Result<(), &'static str> {
        let sym_key = SymmetricKey::from_bytes(self.master_key.key);
        let serialized_content = serde_json::to_vec(&self.content)
            .map_err(|_| "Serialization error")?;

        let mut header = Vec::with_capacity(32);
        header.extend_from_slice(DB_MAGIC);
        header.extend_from_slice(&self.salt);

        // Encrypt with ChaCha20-Poly1305, binding to the header AAD
        let encrypted = encrypt_aead(&sym_key, &serialized_content, &header)?;

        let mut file_payload = Vec::new();
        file_payload.extend_from_slice(&header);
        file_payload.extend_from_slice(&encrypted.nonce);
        file_payload.extend_from_slice(&encrypted.ciphertext);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|_| "Cannot open file for writing")?;

        file.write_all(&file_payload)
            .map_err(|_| "Failed to write database file")?;
        file.sync_all().map_err(|_| "Failed to sync to disk")?;

        Ok(())
    }

    /// Stores a message with optional self-destruct / disappearing timer
    pub fn store_message(&mut self, msg: StoredChatMessage) -> Result<(), &'static str> {
        self.content.messages.push(msg);
        self.save_to_disk()
    }

    /// Anti-Forensics: Irreversibly shreds and overwrites the database file on disk with random bytes.
    /// Used when a user activates the panic button or enters a duress passphrase.
    pub fn emergency_wipe(file_path: &str) -> Result<(), &'static str> {
        let path = Path::new(file_path);
        if path.exists() {
            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(4096) as usize;
            let mut random_noise = vec![0u8; len];
            OsRng.fill_bytes(&mut random_noise);

            // Overwrite with random cryptographic noise before unlinking
            let mut file = OpenOptions::new().write(true).open(path)
                .map_err(|_| "Failed to open file for wipe")?;
            file.write_all(&random_noise).map_err(|_| "Wipe overwrite failed")?;
            file.sync_all().map_err(|_| "Wipe sync failed")?;

            std::fs::remove_file(path).map_err(|_| "Failed to delete wiped file")?;
        }
        Ok(())
    }
}
