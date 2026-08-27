#![no_main]
//! Arbitrary UTF-8 into the BIP-39 identity restore path. Must return Err on
//! anything that isn't a valid mnemonic, never panic.
use libfuzzer_sys::fuzz_target;
use aegis_core_crypto::IdentityVault;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = IdentityVault::from_mnemonic_str(s);
    }
});
