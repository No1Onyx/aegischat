//! Adversarial-input regression tests. A corpus of malformed / hostile inputs
//! run through the parsing + decrypt paths that a network attacker controls.
//! The contract: every one of these returns `Err` (or `Ok` with sane output),
//! and NONE of them panic. Runs on stable; the libFuzzer targets in `fuzz/`
//! are the deeper, continuous version of this.

use aegis_core_crypto::{
    DoubleRatchetState, EncryptedWireMessage, RatchetHeader, IdentityVault,
    EncryptedDatabase, SymmetricKey, unseal_message, SealedSenderEnvelope,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

fn wire(rk: &str, n: &str, ct: &str, mn: u32, pn: u32) -> EncryptedWireMessage {
    EncryptedWireMessage {
        header: RatchetHeader { ratchet_key: rk.into(), message_number: mn, previous_chain_length: pn },
        nonce: n.into(),
        ciphertext: ct.into(),
    }
}

#[test]
fn ratchet_decrypt_never_panics_on_garbage() {
    let good_key = B64.encode([1u8; 32]);
    let good_nonce = B64.encode([2u8; 12]);
    let cases = vec![
        wire("", "", "", 0, 0),
        wire("not base64!!!", "!!!", "!!!", 0, 0),
        wire(&good_key, &good_nonce, &B64.encode([0u8; 16]), 0, 0),
        // absurd skip counts must hit the MAX_SKIP guard, not loop
        wire(&good_key, &good_nonce, &B64.encode([0u8; 16]), u32::MAX, 0),
        wire(&good_key, &good_nonce, &B64.encode([0u8; 16]), 0, u32::MAX),
        wire(&good_key, &good_nonce, &B64.encode([0u8; 16]), 5_000_000, 5_000_000),
        // wrong-length ratchet key / nonce
        wire(&B64.encode([1u8; 5]), &good_nonce, &B64.encode([0u8; 16]), 0, 0),
        wire(&good_key, &B64.encode([2u8; 3]), &B64.encode([0u8; 16]), 0, 0),
        // ciphertext shorter than an AEAD tag
        wire(&good_key, &good_nonce, &B64.encode([0u8; 1]), 0, 0),
    ];
    for (i, w) in cases.into_iter().enumerate() {
        let mut s = DoubleRatchetState::init_bob([7u8; 32], None);
        let r = s.decrypt(&w);
        assert!(r.is_err(), "case {i}: expected Err on garbage input, got Ok");
        // second pass must also be safe
        let _ = s.decrypt(&w);
    }
}

#[test]
fn ratchet_decrypt_from_raw_json_never_panics() {
    let blobs: Vec<&[u8]> = vec![
        b"", b"{}", b"[]", b"null", b"not json",
        b"{\"header\":{}}",
        b"{\"header\":{\"ratchet_key\":\"\",\"message_number\":-1,\"previous_chain_length\":0},\"nonce\":\"\",\"ciphertext\":\"\"}",
        &[0xff; 4096],
    ];
    for b in blobs {
        if let Ok(w) = serde_json::from_slice::<EncryptedWireMessage>(b) {
            let mut s = DoubleRatchetState::init_bob([3u8; 32], None);
            let _ = s.decrypt(&w);
        }
    }
}

#[test]
fn db_open_never_panics_on_corrupt_file() {
    let path = std::env::temp_dir().join("aegis_adversarial_db.bin");
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 3],
        vec![0u8; 47],                         // one byte under the minimum
        b"AEGS".to_vec(),                       // magic only
        {
            let mut v = b"AEGS".to_vec();
            v.extend_from_slice(&[0u8; 44]);    // magic + zero salt/nonce/ct
            v
        },
        vec![0xff; 5000],
        b"NOPEsaltsaltsaltsaltnoncenonceabciphertext-tail".to_vec(),
    ];
    for c in cases {
        std::fs::write(&path, &c).unwrap();
        let _ = EncryptedDatabase::open(path.to_str().unwrap(), "pw", None);
        let _ = EncryptedDatabase::open(path.to_str().unwrap(), "pw", Some("duress"));
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn mnemonic_parse_never_panics() {
    for s in [
        "", " ", "\0", "abandon", "abandon ".repeat(11).as_str(),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz",
        "🙂 🙂 🙂 🙂 🙂 🙂 🙂 🙂 🙂 🙂 🙂 🙂",
        &"word ".repeat(1000),
    ] {
        let _ = IdentityVault::from_mnemonic_str(s);
    }
}

#[test]
fn sealed_envelope_unseal_never_panics() {
    let key = SymmetricKey::from_bytes([0x42u8; 32]);
    let blobs: Vec<&[u8]> = vec![
        b"", b"{}", b"null",
        b"{\"recipient_blind_token\":\"x\",\"ephemeral_nonce\":\"!!!\",\"encrypted_inner_payload\":\"!!!\"}",
        b"{\"recipient_blind_token\":\"x\",\"ephemeral_nonce\":\"AAAA\",\"encrypted_inner_payload\":\"AAAA\"}",
        &[0x7b; 2048],
    ];
    for b in blobs {
        if let Ok(env) = serde_json::from_slice::<SealedSenderEnvelope>(b) {
            let _ = unseal_message(&key, &env);
        }
    }
}
