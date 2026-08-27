/**
 * AegisChat - Hardened Cross-Platform Cryptographic C-FFI Header
 * Target platforms: Windows, macOS, Linux, iOS, Android
 */

#ifndef AEGIS_CORE_CRYPTO_H
#define AEGIS_CORE_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

// Free string allocated by Rust
void aegis_free_string(char* ptr);

// Zero-Anchor Identity Generation (12-word BIP-39 mnemonic + Ed25519 + X25519)
// Returns JSON string: { "mnemonic": "...", "blind_token": "...", "public_bundle": { ... } }
char* aegis_identity_generate_new(void);

// Restore Zero-Anchor Identity from 12-word mnemonic
char* aegis_identity_restore(const char* mnemonic_c);

// Compute 60-digit safety number fingerprint (12 blocks of 5 digits)
char* aegis_safety_number(const char* key_a_b64, const char* key_b_b64);

// Opaque Double Ratchet session pointer
typedef struct DoubleRatchetState DoubleRatchetState;

// Free Double Ratchet session pointer
void aegis_ratchet_free(DoubleRatchetState* state);

// Encrypt plaintext with Double Ratchet (advances symmetric sending chain)
// Returns JSON string of EncryptedWireMessage
char* aegis_ratchet_encrypt(DoubleRatchetState* state, const char* plaintext_c);

// Decrypt wire message JSON with Double Ratchet (triggers DH ratchet if key rotated)
// Returns decrypted UTF-8 plaintext string
char* aegis_ratchet_decrypt(DoubleRatchetState* state, const char* wire_json_c);

// Opaque Encrypted Database handle
typedef struct EncryptedDatabase EncryptedDatabase;

// Creates a new Argon2id encrypted database file on disk
EncryptedDatabase* aegis_db_create_new(const char* file_path_c, const char* passphrase_c);

// Opens an existing encrypted database file with Argon2id passphrase.
// If duress_phrase matches, triggers an instant anti-forensic emergency wipe.
EncryptedDatabase* aegis_db_open(const char* file_path_c, const char* passphrase_c, const char* duress_phrase_c);

// Stores a message JSON into the encrypted database and syncs to disk
bool aegis_db_store_message(EncryptedDatabase* db_ptr, const char* msg_json_c);

// Returns all decrypted messages from the database as a JSON string
char* aegis_db_get_messages(EncryptedDatabase* db_ptr);

// Closes the encrypted database and securely scrubs master key from RAM
void aegis_db_close(EncryptedDatabase* db_ptr);

// Panic Button: Irreversibly shreds and deletes the encrypted database from disk
bool aegis_db_emergency_wipe(const char* file_path_c);

#ifdef __cplusplus
}
#endif

#endif // AEGIS_CORE_CRYPTO_H
