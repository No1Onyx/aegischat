import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { mnemonicToSeedSync } from '@scure/bip39';

// Uint8Array <-> Base64 helpers
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Keypair generation
export interface DHKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface SigningKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateDHKeyPair(): DHKeyPair {
  const pair = x25519.keygen();
  return { publicKey: pair.publicKey, privateKey: pair.secretKey };
}

export function generateSigningKeyPair(): SigningKeyPair {
  const pair = ed25519.keygen();
  return { publicKey: pair.publicKey, privateKey: pair.secretKey };
}

// Domain-separation labels — MUST stay byte-identical to core-crypto/src/identity.rs.
const ED25519_IDENTITY_INFO = new TextEncoder().encode('AegisChat_Ed25519_Identity_v1');
const X25519_IDENTITY_INFO = new TextEncoder().encode('AegisChat_X25519_Identity_v1');

/**
 * Deterministically derives the long-term identity (X25519) and signing
 * (Ed25519) keypairs from a BIP-39 mnemonic, using the exact scheme of the
 * native Rust core:
 *
 *   seed        = BIP39_seed(mnemonic, passphrase="")           (64 bytes)
 *   ed25519_sk  = HKDF-SHA256(ikm=seed, salt=0, info="AegisChat_Ed25519_Identity_v1", 32)
 *   x25519_sk   = HKDF-SHA256(ikm=seed, salt=0, info="AegisChat_X25519_Identity_v1", 32)
 *
 * This is what makes "restore account from seed phrase" actually reproduce the
 * same identity on a new device. Cross-implementation test vector lives in
 * core-crypto/src/lib.rs::test_identity_derivation_cross_impl_vector.
 */
export function deriveIdentityFromMnemonic(mnemonic: string): {
  identityKeyPair: DHKeyPair;
  signingKeyPair: SigningKeyPair;
} {
  const seed = mnemonicToSeedSync(mnemonic.trim(), '');
  const edSeed = hkdf(sha256, seed, undefined, ED25519_IDENTITY_INFO, 32);
  const xSeed = hkdf(sha256, seed, undefined, X25519_IDENTITY_INFO, 32);
  return {
    signingKeyPair: {
      publicKey: ed25519.getPublicKey(edSeed),
      privateKey: edSeed,
    },
    identityKeyPair: {
      publicKey: x25519.getPublicKey(xSeed),
      privateKey: xSeed,
    },
  };
}

// Diffie-Hellman computation
export function computeDH(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(ourPrivateKey, theirPublicKey);
}

// Digital Signature
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// HKDF key derivation
export function deriveKey(
  secret: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number = 32
): Uint8Array {
  const infoBytes = new TextEncoder().encode(info);
  return hkdf(sha256, secret, salt, infoBytes, length);
}

export function deriveTwoKeys(
  secret: Uint8Array,
  salt: Uint8Array,
  info: string
): [Uint8Array, Uint8Array] {
  const derived = deriveKey(secret, salt, info, 64);
  return [derived.slice(0, 32), derived.slice(32, 64)];
}

const PADDING_MAGIC = 0x50; // 'P'

export function padPayload(data: Uint8Array, blockSize: number = 256): Uint8Array {
  const len = data.length;
  // Format: [0x50 (magic), high_len, low_len, ...data, ...random_padding]
  const totalNeeded = 3 + len;
  const rem = totalNeeded % blockSize;
  const padLen = rem === 0 ? 0 : blockSize - rem;
  const padded = new Uint8Array(totalNeeded + padLen);
  padded[0] = PADDING_MAGIC;
  padded[1] = (len >> 8) & 0xff;
  padded[2] = len & 0xff;
  padded.set(data, 3);
  if (padLen > 0) {
    crypto.getRandomValues(padded.subarray(totalNeeded));
  }
  return padded;
}

export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (padded.length >= 3 && padded[0] === PADDING_MAGIC) {
    const len = (padded[1] << 8) | padded[2];
    if (3 + len <= padded.length) {
      return padded.subarray(3, 3 + len);
    }
  }
  return padded;
}

// --- Sealed Sender -------------------------------------------------------------
// The relay must not learn who is talking to whom. Messages travel inside an
// outer envelope addressed only by a "blind delivery token" and encrypted to
// the recipient's identity key with an ephemeral DH; the real sender identity
// lives inside, where only the recipient can read it.

const BLIND_TOKEN_PREFIX = new TextEncoder().encode('AegisChat_Blind_Delivery_Token_v1');
const SEALED_SENDER_INFO = 'AegisChat_SealedSender_v1';

/**
 * Deterministic routing token for a recipient, derived from their Ed25519
 * signing public key. Mirrors core-crypto/src/identity.rs::compute_blind_delivery_token.
 */
export function blindDeliveryToken(signingPublicKey: Uint8Array): string {
  const buf = new Uint8Array(BLIND_TOKEN_PREFIX.length + signingPublicKey.length);
  buf.set(BLIND_TOKEN_PREFIX, 0);
  buf.set(signingPublicKey, BLIND_TOKEN_PREFIX.length);
  return toBase64(sha256(buf));
}

/** Encrypts `plaintext` so that only the holder of `recipientIdentityPub` (X25519) can open it. */
export function sealToRecipient(
  recipientIdentityPub: Uint8Array,
  plaintext: string,
  associatedData: Uint8Array = new Uint8Array(0)
): { ephemeralPublicKey: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array } {
  const eph = generateDHKeyPair();
  const shared = computeDH(eph.privateKey, recipientIdentityPub);
  const transportKey = deriveKey(shared, new Uint8Array(32), SEALED_SENDER_INFO, 32);
  // Padding on: normalizes envelope size so the relay can't fingerprint by length.
  const { ciphertext, nonce } = encryptAEAD(transportKey, plaintext, associatedData, true);
  return { ephemeralPublicKey: eph.publicKey, nonce, ciphertext };
}

/** Opens a sealed payload using our long-term X25519 identity private key. */
export function unsealFromSender(
  ourIdentityPriv: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0)
): string {
  const shared = computeDH(ourIdentityPriv, ephemeralPublicKey);
  const transportKey = deriveKey(shared, new Uint8Array(32), SEALED_SENDER_INFO, 32);
  return decryptAEAD(transportKey, nonce, ciphertext, associatedData);
}

// Authenticated Encryption with Associated Data (AEAD)
export function encryptAEAD(
  key: Uint8Array,
  plaintext: string,
  associatedData: Uint8Array = new Uint8Array(0),
  enablePadding: boolean = true
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = chacha20poly1305(key, nonce, associatedData);
  const encodedPlaintext = new TextEncoder().encode(plaintext);
  const dataToEncrypt = enablePadding ? padPayload(encodedPlaintext, 256) : encodedPlaintext;
  const ciphertext = cipher.encrypt(dataToEncrypt);
  return { ciphertext, nonce };
}

export function decryptAEAD(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0)
): string {
  const cipher = chacha20poly1305(key, nonce, associatedData);
  const decryptedBytes = cipher.decrypt(ciphertext);
  const unpadded = unpadPayload(decryptedBytes);
  return new TextDecoder().decode(unpadded);
}
