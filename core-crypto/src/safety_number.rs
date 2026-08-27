use sha2::{Sha256, Digest};

/// Computes a standard 60-digit verifiable Safety Number (12 blocks of 5 digits)
/// derived deterministically from the lexicographical ordering of both Identity Keys.
pub fn compute_safety_number(
    our_identity_public: &[u8; 32],
    their_identity_public: &[u8; 32],
) -> Vec<String> {
    let mut keys = [*our_identity_public, *their_identity_public];
    keys.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"AegisChat_Safety_v1:");
    hasher.update(&keys[0]);
    hasher.update(b":");
    hasher.update(&keys[1]);
    let hash = hasher.finalize();

    let mut blocks = Vec::with_capacity(12);
    for i in 0..12 {
        let byte1 = hash[(i * 2) % hash.len()] as u32;
        let byte2 = hash[(i * 2 + 1) % hash.len()] as u32;
        let num = ((byte1 << 8) | byte2) % 100_000;
        blocks.push(format!("{:05}", num));
    }

    blocks
}
