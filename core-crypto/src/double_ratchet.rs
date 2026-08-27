use std::collections::HashMap;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::aead::{encrypt_aead, decrypt_aead, SymmetricKey};
use crate::kdf::kdf_pair;

const INFO_RK: &[u8] = b"AegisChat_Ratchet_RK_v1";
const INFO_CK: &[u8] = b"AegisChat_Ratchet_CK_v1";
const ZERO_SALT: [u8; 32] = [0u8; 32];

/// Upper bound on message keys derived to catch a chain up to an incoming
/// message number. A header requesting more than this is a denial-of-service
/// attempt (unbounded KDF loop) and is rejected. Mandated by the Signal spec.
const MAX_SKIP: u32 = 1000;
/// Cap on retained out-of-order message keys.
const MAX_SKIPPED_KEYS: usize = 2000;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RatchetHeader {
    pub ratchet_key: String,
    pub message_number: u32,
    pub previous_chain_length: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedWireMessage {
    pub header: RatchetHeader,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    pub dhrs_secret: StaticSecret,
    #[zeroize(skip)]
    pub dhrs_public: X25519PublicKey,
    #[zeroize(skip)]
    pub dhrr: Option<X25519PublicKey>,
    pub root_key: [u8; 32],
    pub chain_key_send: Option<[u8; 32]>,
    pub chain_key_recv: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub ratchet_step_count: u32,
    #[zeroize(skip)]
    pub skipped_keys: HashMap<String, [u8; 32]>,
}

impl DoubleRatchetState {
    /// Initializes Double Ratchet for Alice (Initiator)
    pub fn init_alice(shared_key: [u8; 32], their_ratchet_public: X25519PublicKey) -> Self {
        let mut rng = rand::thread_rng();
        let dhrs_secret = StaticSecret::random_from_rng(&mut rng);
        let dhrs_public = X25519PublicKey::from(&dhrs_secret);

        // Initial DH Ratchet step
        let dh = dhrs_secret.diffie_hellman(&their_ratchet_public);
        let (new_rk, new_cks) = kdf_pair(dh.as_bytes(), &shared_key, INFO_RK);

        Self {
            dhrs_secret,
            dhrs_public,
            dhrr: Some(their_ratchet_public),
            root_key: new_rk,
            chain_key_send: Some(new_cks),
            chain_key_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            ratchet_step_count: 1,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initializes Double Ratchet for Bob (Responder)
    pub fn init_bob(shared_key: [u8; 32], our_keypair: Option<StaticSecret>) -> Self {
        let dhrs_secret = our_keypair.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            StaticSecret::random_from_rng(&mut rng)
        });
        let dhrs_public = X25519PublicKey::from(&dhrs_secret);

        Self {
            dhrs_secret,
            dhrs_public,
            dhrr: None,
            root_key: shared_key,
            chain_key_send: None,
            chain_key_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            ratchet_step_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypts an outgoing message, ratcheting the symmetric sending chain forward
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedWireMessage, &'static str> {
        let cks = self.chain_key_send.as_mut().ok_or("Sending chain not initialized")?;

        // Advance sending chain: (CKs_next, MK) = KDF_CK(CKs)
        let (next_cks, message_key_bytes) = kdf_pair(cks, &ZERO_SALT, INFO_CK);
        *cks = next_cks;

        let header = RatchetHeader {
            ratchet_key: BASE64.encode(self.dhrs_public.as_bytes()),
            message_number: self.ns,
            previous_chain_length: self.pn,
        };

        let header_json = serde_json::to_vec(&header).map_err(|_| "Header serialization failed")?;
        let message_key = SymmetricKey::from_bytes(message_key_bytes);

        // Encrypt with ChaCha20-Poly1305 (Associated Data = serialized header)
        let encrypted = encrypt_aead(&message_key, plaintext, &header_json)?;

        self.ns += 1;

        Ok(EncryptedWireMessage {
            header,
            nonce: BASE64.encode(&encrypted.nonce),
            ciphertext: BASE64.encode(&encrypted.ciphertext),
        })
    }

    /// Decrypts an incoming message, performing a Diffie-Hellman ratchet step if
    /// a new remote key is detected.
    ///
    /// Security properties:
    ///  - All derivation runs against local copies; `self` is mutated only after
    ///    the AEAD tag verifies. A forged/corrupt packet cannot desync the
    ///    session.
    ///  - Chain catch-up is bounded by `MAX_SKIP`.
    ///  - Skipped message keys are retained and reused for reordered delivery.
    pub fn decrypt(&mut self, wire_msg: &EncryptedWireMessage) -> Result<Vec<u8>, &'static str> {
        let raw_remote_key = BASE64.decode(&wire_msg.header.ratchet_key)
            .map_err(|_| "Invalid base64 ratchet key")?;
        if raw_remote_key.len() != 32 {
            return Err("Ratchet key must be 32 bytes");
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&raw_remote_key);
        let remote_ratchet_key = X25519PublicKey::from(key_arr);
        let remote_key_b64 = BASE64.encode(remote_ratchet_key.as_bytes());

        let nonce_bytes = BASE64.decode(&wire_msg.nonce)
            .map_err(|_| "Invalid base64 nonce")?;
        if nonce_bytes.len() != 12 {
            return Err("Nonce must be 12 bytes");
        }
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce_bytes);

        let ciphertext_bytes = BASE64.decode(&wire_msg.ciphertext)
            .map_err(|_| "Invalid base64 ciphertext")?;
        let header_json = serde_json::to_vec(&wire_msg.header)
            .map_err(|_| "Header serialization failed")?;

        let msg_num = wire_msg.header.message_number;
        let prev_chain_len = wire_msg.header.previous_chain_length;

        // 1. A message key we already skipped past (out-of-order / duplicate).
        let direct_id = format!("{}:{}", remote_key_b64, msg_num);
        if let Some(mk) = self.skipped_keys.get(&direct_id).copied() {
            let key = SymmetricKey::from_bytes(mk);
            let pt = decrypt_aead(&key, &nonce_arr, &ciphertext_bytes, &header_json)?;
            self.skipped_keys.remove(&direct_id);
            return Ok(pt);
        }

        let is_new_remote_key = match self.dhrr {
            Some(existing) => existing.as_bytes() != remote_ratchet_key.as_bytes(),
            None => true,
        };

        // 2. Derive against locals.
        let mut rk = self.root_key;
        let mut ckr = self.chain_key_recv;
        let mut cks = self.chain_key_send;
        let mut dhrr = self.dhrr;
        let mut ns = self.ns;
        let mut nr = self.nr;
        let mut pn = self.pn;
        let mut ratchet_step_count = self.ratchet_step_count;
        let mut new_dhrs: Option<StaticSecret> = None;
        let mut new_dhrs_pub: Option<X25519PublicKey> = None;
        let mut freshly_skipped: Vec<(String, [u8; 32])> = Vec::new();

        if is_new_remote_key {
            // Finish the current receiving chain up to the reported count.
            if let (Some(mut c), Some(prev)) = (ckr, dhrr) {
                if prev_chain_len.saturating_sub(nr) > MAX_SKIP {
                    return Err("Refusing to skip too many messages (previous chain) — possible DoS");
                }
                let prev_b64 = BASE64.encode(prev.as_bytes());
                while nr < prev_chain_len {
                    let (next_c, mk) = kdf_pair(&c, &ZERO_SALT, INFO_CK);
                    c = next_c;
                    freshly_skipped.push((format!("{}:{}", prev_b64, nr), mk));
                    nr += 1;
                }
                // `c` (the drained old receiving chain key) is intentionally
                // discarded: the DH ratchet step below installs a fresh
                // receiving chain. We only needed the loop to derive and retain
                // the skipped message keys above.
                let _ = c;
            }

            pn = ns;
            ns = 0;
            nr = 0;
            dhrr = Some(remote_ratchet_key);

            // DH Ratchet Step 1: receiving chain
            let dh1 = self.dhrs_secret.diffie_hellman(&remote_ratchet_key);
            let (rk1, ckr1) = kdf_pair(dh1.as_bytes(), &rk, INFO_RK);
            rk = rk1;
            ckr = Some(ckr1);

            // DH Ratchet Step 2: fresh keypair, sending chain
            let mut rng = rand::thread_rng();
            let fresh_secret = StaticSecret::random_from_rng(&mut rng);
            let fresh_public = X25519PublicKey::from(&fresh_secret);
            let dh2 = fresh_secret.diffie_hellman(&remote_ratchet_key);
            let (rk2, cks2) = kdf_pair(dh2.as_bytes(), &rk, INFO_RK);
            rk = rk2;
            cks = Some(cks2);
            new_dhrs = Some(fresh_secret);
            new_dhrs_pub = Some(fresh_public);

            ratchet_step_count += 1;
        }

        let mut chain = ckr.ok_or("Receiving chain not initialized")?;

        if msg_num.saturating_sub(nr) > MAX_SKIP {
            return Err("Refusing to skip too many messages — possible DoS");
        }
        while nr < msg_num {
            let (next_c, mk) = kdf_pair(&chain, &ZERO_SALT, INFO_CK);
            chain = next_c;
            freshly_skipped.push((format!("{}:{}", remote_key_b64, nr), mk));
            nr += 1;
        }

        let (chain_after, message_key_bytes) = kdf_pair(&chain, &ZERO_SALT, INFO_CK);
        let message_key = SymmetricKey::from_bytes(message_key_bytes);

        // 3. Verify + decrypt BEFORE committing.
        let plaintext = decrypt_aead(&message_key, &nonce_arr, &ciphertext_bytes, &header_json)?;

        // 4. Commit.
        self.root_key = rk;
        self.chain_key_recv = Some(chain_after);
        self.chain_key_send = cks;
        self.dhrr = dhrr;
        self.ns = ns;
        self.nr = nr + 1;
        self.pn = pn;
        self.ratchet_step_count = ratchet_step_count;
        if let (Some(s), Some(p)) = (new_dhrs, new_dhrs_pub) {
            self.dhrs_secret = s;
            self.dhrs_public = p;
        }
        for (id, mk) in freshly_skipped {
            self.skipped_keys.insert(id, mk);
        }
        while self.skipped_keys.len() > MAX_SKIPPED_KEYS {
            let victim = match self.skipped_keys.keys().next().cloned() {
                Some(k) => k,
                None => break,
            };
            self.skipped_keys.remove(&victim);
        }

        Ok(plaintext)
    }
}
