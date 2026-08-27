use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Derives a 32-byte symmetric key from input key material (IKM), salt, and domain separation info.
pub fn kdf_single(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes is well within HKDF limits");
    okm
}

/// Derives two 32-byte symmetric keys (e.g. for root key & chain key, or chain key & message key).
pub fn kdf_pair(ikm: &[u8], salt: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm).expect("64 bytes is well within HKDF limits");
    
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key1.copy_from_slice(&okm[0..32]);
    key2.copy_from_slice(&okm[32..64]);
    
    okm.zeroize();
    (key1, key2)
}
