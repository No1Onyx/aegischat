#![no_main]
//! Arbitrary bytes as a sealed-sender envelope JSON, then unseal with a fixed
//! transport key. Exercises base64 decoding, length checks, and the inner
//! payload deserialisation / signature-verification path.
use libfuzzer_sys::fuzz_target;
use aegis_core_crypto::{unseal_message, SealedSenderEnvelope, SymmetricKey};

fuzz_target!(|data: &[u8]| {
    let Ok(env) = serde_json::from_slice::<SealedSenderEnvelope>(data) else {
        return;
    };
    let key = SymmetricKey::from_bytes([0x42u8; 32]);
    let _ = unseal_message(&key, &env);
});
