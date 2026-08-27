use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::identity::IdentityVault;
use crate::double_ratchet::{DoubleRatchetState, EncryptedWireMessage};
use crate::safety_number::compute_safety_number;

/// Frees a string allocated by the Rust core library
#[no_mangle]
pub unsafe extern "C" fn aegis_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Generates a brand new zero-anchor cryptographic identity (12-word mnemonic)
/// Returns a JSON string with mnemonic and public keys
#[no_mangle]
pub extern "C" fn aegis_identity_generate_new() -> *mut c_char {
    let vault = IdentityVault::generate_new();
    let spk = vault.generate_signed_prekey(1);
    let opks = vault.generate_one_time_prekeys(1, 10);
    let bundle = vault.build_public_bundle(&spk, &opks);

    let result = serde_json::json!({
        "mnemonic": vault.mnemonic,
        "blind_token": vault.compute_blind_delivery_token(),
        "public_bundle": bundle,
    });

    CString::new(result.to_string()).unwrap().into_raw()
}

/// Restores an identity from a 12-word recovery mnemonic
#[no_mangle]
pub unsafe extern "C" fn aegis_identity_restore(mnemonic_c: *const c_char) -> *mut c_char {
    if mnemonic_c.is_null() {
        return std::ptr::null_mut();
    }
    let phrase = match CStr::from_ptr(mnemonic_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match IdentityVault::from_mnemonic_str(phrase) {
        Ok(vault) => {
            let spk = vault.generate_signed_prekey(1);
            let opks = vault.generate_one_time_prekeys(1, 10);
            let bundle = vault.build_public_bundle(&spk, &opks);

            let result = serde_json::json!({
                "mnemonic": vault.mnemonic,
                "blind_token": vault.compute_blind_delivery_token(),
                "public_bundle": bundle,
            });
            CString::new(result.to_string()).unwrap().into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Computes the 60-digit safety number fingerprint from two Ed25519 public keys
#[no_mangle]
pub unsafe extern "C" fn aegis_safety_number(key_a_b64: *const c_char, key_b_b64: *const c_char) -> *mut c_char {
    if key_a_b64.is_null() || key_b_b64.is_null() {
        return std::ptr::null_mut();
    }

    let a_str = match CStr::from_ptr(key_a_b64).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let b_str = match CStr::from_ptr(key_b_b64).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let bytes_a = match BASE64.decode(a_str) {
        Ok(b) if b.len() == 32 => b,
        _ => return std::ptr::null_mut(),
    };
    let bytes_b = match BASE64.decode(b_str) {
        Ok(b) if b.len() == 32 => b,
        _ => return std::ptr::null_mut(),
    };

    let mut arr_a = [0u8; 32];
    let mut arr_b = [0u8; 32];
    arr_a.copy_from_slice(&bytes_a);
    arr_b.copy_from_slice(&bytes_b);

    let blocks = compute_safety_number(&arr_a, &arr_b);
    let joined = blocks.join(" ");

    CString::new(joined).unwrap().into_raw()
}

/// Frees an active Double Ratchet session pointer
#[no_mangle]
pub unsafe extern "C" fn aegis_ratchet_free(state: *mut DoubleRatchetState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

/// Encrypts plaintext bytes using an active Double Ratchet instance
#[no_mangle]
pub unsafe extern "C" fn aegis_ratchet_encrypt(
    state: *mut DoubleRatchetState,
    plaintext_c: *const c_char,
) -> *mut c_char {
    if state.is_null() || plaintext_c.is_null() {
        return std::ptr::null_mut();
    }

    let ratchet = &mut *state;
    let plaintext_bytes = match CStr::from_ptr(plaintext_c).to_str() {
        Ok(s) => s.as_bytes(),
        Err(_) => return std::ptr::null_mut(),
    };

    match ratchet.encrypt(plaintext_bytes) {
        Ok(wire_msg) => {
            let json = serde_json::to_string(&wire_msg).unwrap();
            CString::new(json).unwrap().into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypts wire message JSON using an active Double Ratchet instance
#[no_mangle]
pub unsafe extern "C" fn aegis_ratchet_decrypt(
    state: *mut DoubleRatchetState,
    wire_json_c: *const c_char,
) -> *mut c_char {
    if state.is_null() || wire_json_c.is_null() {
        return std::ptr::null_mut();
    }

    let ratchet = &mut *state;
    let wire_json_str = match CStr::from_ptr(wire_json_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let wire_msg: EncryptedWireMessage = match serde_json::from_str(wire_json_str) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    match ratchet.decrypt(&wire_msg) {
        Ok(decrypted_bytes) => {
            match String::from_utf8(decrypted_bytes) {
                Ok(plain) => CString::new(plain).unwrap().into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

use crate::storage::{EncryptedDatabase, StoredChatMessage};

/// Creates a new Argon2id encrypted database file on disk
#[no_mangle]
pub unsafe extern "C" fn aegis_db_create_new(
    file_path_c: *const c_char,
    passphrase_c: *const c_char,
) -> *mut EncryptedDatabase {
    if file_path_c.is_null() || passphrase_c.is_null() {
        return std::ptr::null_mut();
    }
    let path = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let passphrase = match CStr::from_ptr(passphrase_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match EncryptedDatabase::create_new(path, passphrase) {
        Ok(db) => Box::into_raw(Box::new(db)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Opens an existing encrypted database file with Argon2id passphrase.
/// If duress phrase matches, triggers anti-forensic emergency wipe.
#[no_mangle]
pub unsafe extern "C" fn aegis_db_open(
    file_path_c: *const c_char,
    passphrase_c: *const c_char,
    duress_phrase_c: *const c_char,
) -> *mut EncryptedDatabase {
    if file_path_c.is_null() || passphrase_c.is_null() {
        return std::ptr::null_mut();
    }
    let path = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let passphrase = match CStr::from_ptr(passphrase_c).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let duress = if !duress_phrase_c.is_null() {
        CStr::from_ptr(duress_phrase_c).to_str().ok()
    } else {
        None
    };

    match EncryptedDatabase::open(path, passphrase, duress) {
        Ok(db) => Box::into_raw(Box::new(db)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Stores a message JSON into the encrypted database and syncs to disk
#[no_mangle]
pub unsafe extern "C" fn aegis_db_store_message(
    db_ptr: *mut EncryptedDatabase,
    msg_json_c: *const c_char,
) -> bool {
    if db_ptr.is_null() || msg_json_c.is_null() {
        return false;
    }
    let db = &mut *db_ptr;
    let json_str = match CStr::from_ptr(msg_json_c).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let msg: StoredChatMessage = match serde_json::from_str(json_str) {
        Ok(m) => m,
        Err(_) => return false,
    };
    db.store_message(msg).is_ok()
}

/// Returns all decrypted messages from the database as a JSON string
#[no_mangle]
pub unsafe extern "C" fn aegis_db_get_messages(db_ptr: *mut EncryptedDatabase) -> *mut c_char {
    if db_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let db = &*db_ptr;
    let json = serde_json::to_string(&db.content.messages).unwrap_or_default();
    CString::new(json).unwrap().into_raw()
}

/// Closes the encrypted database and securely scrubs master key from RAM
#[no_mangle]
pub unsafe extern "C" fn aegis_db_close(db_ptr: *mut EncryptedDatabase) {
    if !db_ptr.is_null() {
        drop(Box::from_raw(db_ptr));
    }
}

/// Panic Button: Irreversibly shreds and deletes the encrypted database from disk
#[no_mangle]
pub unsafe extern "C" fn aegis_db_emergency_wipe(file_path_c: *const c_char) -> bool {
    if file_path_c.is_null() {
        return false;
    }
    let path = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    EncryptedDatabase::emergency_wipe(path).is_ok()
}
