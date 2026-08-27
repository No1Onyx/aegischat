use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand_core::{RngCore, OsRng};

/// Zero-Anchor Identity: No phone numbers, no emails, no SMS.
/// Entire cryptographic identity is derived deterministically from a 12-word BIP-39 mnemonic seed.
#[derive(ZeroizeOnDrop)]
pub struct IdentityVault {
    #[zeroize(skip)]
    pub mnemonic: String,
    pub ed25519_signing_key: SigningKey,
    #[zeroize(skip)]
    pub ed25519_verifying_key: VerifyingKey,
    pub x25519_identity_secret: StaticSecret,
    #[zeroize(skip)]
    pub x25519_identity_public: X25519PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicIdentityBundle {
    pub identity_key_x25519: String,
    pub signing_key_ed25519: String,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekeys: Vec<OneTimePreKeyPublic>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPreKeyPublic {
    pub key_id: u32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OneTimePreKeyPublic {
    pub key_id: u32,
    pub public_key: String,
}

#[derive(ZeroizeOnDrop)]
pub struct SignedPreKeySecret {
    pub key_id: u32,
    pub secret: StaticSecret,
    #[zeroize(skip)]
    pub public: X25519PublicKey,
    #[zeroize(skip)]
    pub signature: ed25519_dalek::Signature,
}

#[derive(ZeroizeOnDrop)]
pub struct OneTimePreKeySecret {
    pub key_id: u32,
    pub secret: StaticSecret,
    #[zeroize(skip)]
    pub public: X25519PublicKey,
}

impl IdentityVault {
    /// Generates a brand new zero-anchor cryptographic identity with a 12-word mnemonic.
    pub fn generate_new() -> Self {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("16 bytes is valid entropy");
        let phrase = mnemonic.to_string();
        Self::from_mnemonic_str(&phrase).expect("Valid mnemonic generated")
    }

    /// Restores a zero-anchor cryptographic identity from an existing 12-word or 24-word phrase.
    pub fn from_mnemonic_str(phrase: &str) -> Result<Self, &'static str> {
        let mnemonic: Mnemonic = phrase.parse().map_err(|_| "Invalid BIP-39 mnemonic phrase")?;
        let seed = mnemonic.to_seed("");

        // Sub-derive Ed25519 signing key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(None, &seed);
        let mut ed25519_bytes = [0u8; 32];
        hk.expand(b"AegisChat_Ed25519_Identity_v1", &mut ed25519_bytes)
            .map_err(|_| "HKDF expansion failed for Ed25519")?;
        
        let signing_key = SigningKey::from_bytes(&ed25519_bytes);
        let verifying_key = signing_key.verifying_key();

        // Sub-derive X25519 identity key using HKDF-SHA256
        let mut x25519_bytes = [0u8; 32];
        hk.expand(b"AegisChat_X25519_Identity_v1", &mut x25519_bytes)
            .map_err(|_| "HKDF expansion failed for X25519")?;
        
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Wipe temporary sub-keys from RAM
        ed25519_bytes.zeroize();
        x25519_bytes.zeroize();

        Ok(Self {
            mnemonic: phrase.to_string(),
            ed25519_signing_key: signing_key,
            ed25519_verifying_key: verifying_key,
            x25519_identity_secret: x25519_secret,
            x25519_identity_public: x25519_public,
        })
    }

    /// Generates a signed prekey, verified by our Ed25519 identity key.
    pub fn generate_signed_prekey(&self, key_id: u32) -> SignedPreKeySecret {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = X25519PublicKey::from(&secret);

        // Sign the X25519 public key with our Ed25519 signing key
        let signature = self.ed25519_signing_key.sign(public.as_bytes());

        SignedPreKeySecret {
            key_id,
            secret,
            public,
            signature,
        }
    }

    /// Generates a batch of one-time ephemeral prekeys for X3DH async forward secrecy.
    pub fn generate_one_time_prekeys(&self, start_id: u32, count: u32) -> Vec<OneTimePreKeySecret> {
        let mut rng = rand::thread_rng();
        let mut opks = Vec::with_capacity(count as usize);

        for i in 0..count {
            let secret = StaticSecret::random_from_rng(&mut rng);
            let public = X25519PublicKey::from(&secret);
            opks.push(OneTimePreKeySecret {
                key_id: start_id + i,
                secret,
                public,
            });
        }

        opks
    }

    /// Builds a public bundle ready for blind relay registration (no private keys leak).
    pub fn build_public_bundle(
        &self,
        spk: &SignedPreKeySecret,
        opks: &[OneTimePreKeySecret],
    ) -> PublicIdentityBundle {
        PublicIdentityBundle {
            identity_key_x25519: BASE64.encode(self.x25519_identity_public.as_bytes()),
            signing_key_ed25519: BASE64.encode(self.ed25519_verifying_key.as_bytes()),
            signed_prekey: SignedPreKeyPublic {
                key_id: spk.key_id,
                public_key: BASE64.encode(spk.public.as_bytes()),
                signature: BASE64.encode(spk.signature.to_bytes()),
            },
            one_time_prekeys: opks
                .iter()
                .map(|k| OneTimePreKeyPublic {
                    key_id: k.key_id,
                    public_key: BASE64.encode(k.public.as_bytes()),
                })
                .collect(),
        }
    }

    /// Blind Delivery Token: Computed deterministically as HMAC/HKDF of the public key.
    /// The relay server uses ONLY this token to deliver messages, keeping real public key anonymous.
    pub fn compute_blind_delivery_token(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"AegisChat_Blind_Delivery_Token_v1");
        hasher.update(self.ed25519_verifying_key.as_bytes());
        BASE64.encode(hasher.finalize())
    }
}
