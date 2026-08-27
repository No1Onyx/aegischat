#![no_main]
//! Feed arbitrary bytes as an on-disk encrypted database. The header parse
//! (magic / salt / nonce slicing, Argon2 params, AEAD) must never panic on a
//! corrupt or truncated file — only return Err.
use libfuzzer_sys::fuzz_target;
use aegis_core_crypto::EncryptedDatabase;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("aegis_fuzz_{}.db", std::process::id()));
    {
        let Ok(mut f) = std::fs::File::create(&path) else { return; };
        let _ = f.write_all(data);
    }
    let _ = EncryptedDatabase::open(path.to_str().unwrap(), "fuzz-passphrase", None);
    let _ = EncryptedDatabase::open(path.to_str().unwrap(), "fuzz-passphrase", Some("duress"));
    let _ = std::fs::remove_file(&path);
});
