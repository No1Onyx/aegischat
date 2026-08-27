// Shared protocol message types for Zero-Knowledge Relay

export interface PreKeyBundle {
  username: string;
  identityPublicKey: string; // Base64 X25519 public key
  signingPublicKey: string;  // Base64 Ed25519 public key
  signedPreKey: {
    keyId: number;
    publicKey: string;       // Base64 X25519 public key
    signature: string;       // Base64 Ed25519 signature over signedPreKey
  };
  oneTimePreKey?: {
    keyId: number;
    publicKey: string;       // Base64 X25519 public key
  };
}

export interface EncryptedEnvelope {
  id: string;
  sender: string;
  recipient: string;
  timestamp: number;
  // Signal Double Ratchet Headers
  ephemeralKey?: string;     // Base64 X25519 (Used during X3DH init)
  oneTimeKeyIdUsed?: number; // Present if one-time prekey was consumed
  ratchetKey: string;        // Base64 X25519 current ratchet public key
  messageNumber: number;     // Index in current sending chain
  previousChainLength: number; // Length of previous sending chain
  // Authenticated Ciphertext
  nonce: string;             // Base64 12-byte nonce (or 24-byte for XChaCha)
  ciphertext: string;        // Base64 AEAD ciphertext + tag
}

/**
 * Sealed-sender envelope. The relay sees ONLY the blind delivery token and an
 * opaque ciphertext — never who sent it, nor (as a username) who receives it.
 */
export interface SealedEnvelope {
  id: string;
  recipientBlindToken: string; // Base64 SHA-256 routing token
  ephemeralPublicKey: string;  // Base64 X25519 — outer seal DH
  nonce: string;               // Base64 outer AEAD nonce
  ciphertext: string;          // Base64 encrypted inner payload
  timestamp: number;
}

export interface GroupMetadata {
  id: string;
  name: string;
  creator: string;
  members: string[];
  createdAt: number;
}

export interface GroupEnvelope {
  id: string;
  groupId: string;
  sender: string;
  timestamp: number;
  messageIndex: number;
  nonce: string;
  ciphertext: string;
  signature: string; // Ed25519 signature over (messageIndex + ciphertext + nonce)
}

export interface ServerAuditLog {
  id: string;
  timestamp: number;
  type:
    | 'KEY_REGISTER'
    | 'KEY_FETCH'
    | 'ENVELOPE_RELAYED'
    | 'ACK_DELIVERED'
    | 'STORE_ENCRYPTED_ATTACHMENT'
    | 'FETCH_ENCRYPTED_ATTACHMENT'
    | 'GROUP_CREATED'
    | 'GROUP_MEMBER_CHANGED'
    | 'GROUP_MESSAGE_RELAYED';
  details: string;
  ciphertextSample?: string;
}
