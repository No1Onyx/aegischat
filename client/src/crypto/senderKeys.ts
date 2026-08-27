import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { toBase64, fromBase64 } from './primitives.js';
import { secureStore } from './secureStore.js';

const ZERO_SALT = new Uint8Array(32);
const INFO_SENDER_CK = new TextEncoder().encode('AegisChat_SenderKey_CK_v1');

// Bound on how far a single incoming group message may advance a peer's sender
// chain. A larger jump is treated as a denial-of-service attempt (unbounded
// HKDF loop) and rejected.
const MAX_SENDER_SKIP = 2000;
// Retain at most this many out-of-order group message keys per peer.
const MAX_SKIPPED_SENDER_KEYS = 4000;

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export interface SenderKeyDistribution {
  groupId: string;
  sender: string;
  chainKey: string;      // Base64 32 bytes
  iteration: number;
  signingPublicKey: string; // Base64 32 bytes Ed25519
}

export interface GroupEncryptedPacket {
  messageIndex: number;
  nonce: string;       // Base64 12 bytes
  ciphertext: string;  // Base64 ChaCha20-Poly1305
  signature: string;   // Base64 Ed25519 signature
}

interface PeerSenderKeyChain {
  chainKey: Uint8Array;
  iteration: number;
  signingPublicKey: Uint8Array;
  skippedMessageKeys: Map<number, Uint8Array>;
}

export class GroupSessionManager {
  public groupId: string;
  public username: string;

  // Our own Sender Key state
  private ourChainKey: Uint8Array;
  private ourIteration: number = 0;
  private ourSigningKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array };

  // Peer Sender Keys
  private peerChains = new Map<string, PeerSenderKeyChain>();

  constructor(groupId: string, username: string) {
    this.groupId = groupId;
    this.username = username.toLowerCase();

    // Generate our initial Sender Key
    this.ourChainKey = randomBytes(32);
    this.ourIteration = 0;
    this.ourSigningKeyPair = ed25519.keygen();

    this.loadFromStorage();
  }

  /**
   * Exports our Sender Key to distribute to group members over private 1-on-1 Double Ratchet channels
   */
  exportOurDistribution(): SenderKeyDistribution {
    return {
      groupId: this.groupId,
      sender: this.username,
      chainKey: toBase64(this.ourChainKey),
      iteration: this.ourIteration,
      signingPublicKey: toBase64(this.ourSigningKeyPair.publicKey),
    };
  }

  /**
   * Imports a peer's Sender Key received over private 1-on-1 Double Ratchet
   */
  importPeerDistribution(distribution: SenderKeyDistribution): void {
    const peer = distribution.sender.toLowerCase();
    this.peerChains.set(peer, {
      chainKey: fromBase64(distribution.chainKey),
      iteration: distribution.iteration,
      signingPublicKey: fromBase64(distribution.signingPublicKey),
      skippedMessageKeys: new Map(),
    });
    this.saveToStorage();
  }

  /**
   * Encrypts a group message: O(1) complexity. Single ciphertext broadcast to all members!
   */
  encrypt(plaintext: string): GroupEncryptedPacket {
    // 1. Advance our chain key: (CK_next, MK) = HKDF(CK)
    const okm = hkdf(sha256, this.ourChainKey, ZERO_SALT, INFO_SENDER_CK, 64);
    this.ourChainKey = okm.slice(0, 32);
    const messageKey = okm.slice(32, 64);

    const currentIndex = this.ourIteration;
    this.ourIteration += 1;

    // 2. Encrypt plaintext with ChaCha20-Poly1305
    const nonce = randomBytes(12);
    const cipher = chacha20poly1305(messageKey, nonce);
    const rawPlaintext = new TextEncoder().encode(plaintext);
    const ciphertext = cipher.encrypt(rawPlaintext);

    // 3. Sign the ciphertext + index with our Ed25519 signing key
    const signPayload = new Uint8Array(4 + nonce.length + ciphertext.length);
    new DataView(signPayload.buffer).setUint32(0, currentIndex, false);
    signPayload.set(nonce, 4);
    signPayload.set(ciphertext, 4 + nonce.length);

    const signature = ed25519.sign(signPayload, this.ourSigningKeyPair.secretKey);

    this.saveToStorage();

    return {
      messageIndex: currentIndex,
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
      signature: toBase64(signature),
    };
  }

  /**
   * Decrypts an incoming group message from a peer, verifying Ed25519 signature
   */
  decrypt(sender: string, packet: GroupEncryptedPacket): string {
    const peerKey = sender.toLowerCase();
    const peerChain = this.peerChains.get(peerKey);
    if (!peerChain) {
      throw new Error(`No sender key established for peer "${sender}" in group ${this.groupId}`);
    }

    const nonceBytes = fromBase64(packet.nonce);
    const ciphertextBytes = fromBase64(packet.ciphertext);
    const signatureBytes = fromBase64(packet.signature);

    // 1. Verify Ed25519 digital signature
    const signPayload = new Uint8Array(4 + nonceBytes.length + ciphertextBytes.length);
    new DataView(signPayload.buffer).setUint32(0, packet.messageIndex, false);
    signPayload.set(nonceBytes, 4);
    signPayload.set(ciphertextBytes, 4 + nonceBytes.length);

    if (!Number.isInteger(packet.messageIndex) || packet.messageIndex < 0) {
      throw new Error('Malformed group message index');
    }

    const isValidSig = ed25519.verify(signatureBytes, signPayload, peerChain.signingPublicKey);
    if (!isValidSig) {
      throw new Error('SECURITY ERROR: Group message signature verification failed! Impersonation detected.');
    }

    // 2. Derive message key for packet.messageIndex. All chain mutation is done
    //    against locals and committed only after the ciphertext authenticates,
    //    so a malformed packet cannot desync the chain.
    let messageKey: Uint8Array;
    const freshlySkipped: Array<[number, Uint8Array]> = [];
    let workingChainKey = peerChain.chainKey;
    let workingIteration = peerChain.iteration;

    if (packet.messageIndex < peerChain.iteration) {
      const skipped = peerChain.skippedMessageKeys.get(packet.messageIndex);
      if (!skipped) {
        throw new Error('Message key already consumed or expired');
      }
      messageKey = skipped;
    } else {
      if (packet.messageIndex - peerChain.iteration > MAX_SENDER_SKIP) {
        throw new Error(
          `Refusing to skip ${packet.messageIndex - peerChain.iteration} group messages ` +
          `(max ${MAX_SENDER_SKIP}) — possible DoS`
        );
      }

      while (workingIteration < packet.messageIndex) {
        const okm = hkdf(sha256, workingChainKey, ZERO_SALT, INFO_SENDER_CK, 64);
        workingChainKey = okm.slice(0, 32);
        freshlySkipped.push([workingIteration, okm.slice(32, 64)]);
        workingIteration += 1;
      }

      const okm = hkdf(sha256, workingChainKey, ZERO_SALT, INFO_SENDER_CK, 64);
      workingChainKey = okm.slice(0, 32);
      messageKey = okm.slice(32, 64);
      workingIteration += 1;
    }

    // 3. Decrypt with ChaCha20-Poly1305 BEFORE committing chain state.
    const cipher = chacha20poly1305(messageKey, nonceBytes);
    const decryptedBytes = cipher.decrypt(ciphertextBytes);

    // 4. Commit.
    if (packet.messageIndex < peerChain.iteration) {
      peerChain.skippedMessageKeys.delete(packet.messageIndex);
    } else {
      peerChain.chainKey = workingChainKey;
      peerChain.iteration = workingIteration;
      for (const [idx, mk] of freshlySkipped) {
        peerChain.skippedMessageKeys.set(idx, mk);
      }
      while (peerChain.skippedMessageKeys.size > MAX_SKIPPED_SENDER_KEYS) {
        const oldest = peerChain.skippedMessageKeys.keys().next().value;
        if (oldest === undefined) break;
        peerChain.skippedMessageKeys.delete(oldest);
      }
    }

    this.saveToStorage();
    return new TextDecoder().decode(decryptedBytes);
  }

  hasSenderKeyFor(peer: string): boolean {
    return this.peerChains.has(peer.toLowerCase());
  }

  /**
   * Rotate our own sender key. Call this whenever a member leaves the group so
   * the departed member's copy of the chain can no longer decrypt new messages.
   * The fresh key must then be re-distributed to the remaining members.
   */
  rotateOurSenderKey(): void {
    this.ourChainKey = randomBytes(32);
    this.ourIteration = 0;
    this.ourSigningKeyPair = ed25519.keygen();
    this.saveToStorage();
  }

  /** Forget a peer's sender chain (they left the group). */
  removePeer(peer: string): void {
    if (this.peerChains.delete(peer.toLowerCase())) this.saveToStorage();
  }

  private saveToStorage() {
    try {
      const state = {
        ourChainKey: toBase64(this.ourChainKey),
        ourIteration: this.ourIteration,
        ourSigningSecret: toBase64(this.ourSigningKeyPair.secretKey),
        ourSigningPublic: toBase64(this.ourSigningKeyPair.publicKey),
        peerChains: Array.from(this.peerChains.entries()).map(([peer, chain]) => ({
          peer,
          chainKey: toBase64(chain.chainKey),
          iteration: chain.iteration,
          signingPublicKey: toBase64(chain.signingPublicKey),
        })),
      };
      secureStore.setItem(`aegis_group_session_${this.username}_${this.groupId}`, JSON.stringify(state));
    } catch (err) {
      console.warn('Failed to persist group session:', err);
    }
  }

  private loadFromStorage() {
    try {
      const raw = secureStore.getItem(`aegis_group_session_${this.username}_${this.groupId}`);
      if (!raw) return;
      const state = JSON.parse(raw);

      if (state.ourChainKey) this.ourChainKey = fromBase64(state.ourChainKey);
      if (typeof state.ourIteration === 'number') this.ourIteration = state.ourIteration;
      if (state.ourSigningSecret && state.ourSigningPublic) {
        this.ourSigningKeyPair = {
          secretKey: fromBase64(state.ourSigningSecret),
          publicKey: fromBase64(state.ourSigningPublic),
        };
      }

      if (Array.isArray(state.peerChains)) {
        for (const item of state.peerChains) {
          this.peerChains.set(item.peer, {
            chainKey: fromBase64(item.chainKey),
            iteration: item.iteration,
            signingPublicKey: fromBase64(item.signingPublicKey),
            skippedMessageKeys: new Map(),
          });
        }
      }
    } catch (err) {
      console.warn('Failed to load group session:', err);
    }
  }
}
