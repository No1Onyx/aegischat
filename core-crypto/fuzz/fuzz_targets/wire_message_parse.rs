#![no_main]
//! Structure-aware variant: build the wire message from four arbitrary
//! byte slices so the fuzzer can reach the ratchet-key / nonce / ciphertext
//! decoders directly without having to synthesise valid JSON.
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use aegis_core_crypto::{DoubleRatchetState, EncryptedWireMessage, RatchetHeader};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    ratchet_key: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
    message_number: u32,
    previous_chain_length: u32,
}

fuzz_target!(|input: Input| {
    let wire = EncryptedWireMessage {
        header: RatchetHeader {
            ratchet_key: B64.encode(input.ratchet_key),
            message_number: input.message_number,
            previous_chain_length: input.previous_chain_length,
        },
        nonce: B64.encode(input.nonce),
        ciphertext: B64.encode(input.ciphertext),
    };
    let mut session = DoubleRatchetState::init_bob([9u8; 32], None);
    let _ = session.decrypt(&wire);
});
