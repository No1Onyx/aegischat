#![no_main]
//! Feed arbitrary bytes as a serialized wire message into a fresh Double
//! Ratchet session. Must never panic (only return Err) — this guards the
//! base64 parsing, the MAX_SKIP bound, and all array indexing on the
//! decrypt path.
use libfuzzer_sys::fuzz_target;
use aegis_core_crypto::{DoubleRatchetState, EncryptedWireMessage};

fuzz_target!(|data: &[u8]| {
    let Ok(wire) = serde_json::from_slice::<EncryptedWireMessage>(data) else {
        return;
    };
    let mut session = DoubleRatchetState::init_bob([7u8; 32], None);
    let _ = session.decrypt(&wire);
    // Decrypt again to exercise the "not a new remote key" branch too.
    let _ = session.decrypt(&wire);
});
