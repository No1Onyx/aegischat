import {
  computeDH,
  deriveKey,
  verify,
  generateDHKeyPair,
} from './primitives.js';
import type { DHKeyPair } from './primitives.js';

export interface PreKeyBundle {
  username: string;
  identityPublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  signedPreKey: {
    keyId: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
  oneTimePreKey?: {
    keyId: number;
    publicKey: Uint8Array;
  };
}

export interface X3DHInitiatorResult {
  sharedKey: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  oneTimeKeyIdUsed?: number;
}

const X3DH_SALT = new Uint8Array(32); // 32 zero bytes
const X3DH_INFO = 'AegisChat_X3DH_v1';

export class X3DH {
  /**
   * Initiator (Sender, e.g. Alice) initiates session with Recipient (Bob's PreKey bundle)
   */
  static initiate(
    senderIdentityKeyPair: DHKeyPair,
    recipientBundle: PreKeyBundle
  ): X3DHInitiatorResult {
    // 1. Verify Bob's Signed Prekey signature
    const isSignatureValid = verify(
      recipientBundle.signedPreKey.signature,
      recipientBundle.signedPreKey.publicKey,
      recipientBundle.signingPublicKey
    );

    if (!isSignatureValid) {
      throw new Error('Cryptographic verification failed: Invalid Signed PreKey signature!');
    }

    // 2. Generate Ephemeral Keypair (EK_A)
    const ephemeralKeyPair = generateDHKeyPair();

    // 3. Compute Diffie-Hellman components
    // DH1 = DH(IK_A, SPK_B)
    const dh1 = computeDH(senderIdentityKeyPair.privateKey, recipientBundle.signedPreKey.publicKey);
    // DH2 = DH(EK_A, IK_B)
    const dh2 = computeDH(ephemeralKeyPair.privateKey, recipientBundle.identityPublicKey);
    // DH3 = DH(EK_A, SPK_B)
    const dh3 = computeDH(ephemeralKeyPair.privateKey, recipientBundle.signedPreKey.publicKey);

    // DH4 = DH(EK_A, OPK_B) if one-time prekey exists
    let totalDHLength = 32 * 3;
    let dh4: Uint8Array | null = null;
    if (recipientBundle.oneTimePreKey) {
      dh4 = computeDH(ephemeralKeyPair.privateKey, recipientBundle.oneTimePreKey.publicKey);
      totalDHLength += 32;
    }

    // Concatenate DH components
    const combinedDH = new Uint8Array(totalDHLength);
    combinedDH.set(dh1, 0);
    combinedDH.set(dh2, 32);
    combinedDH.set(dh3, 64);
    if (dh4) {
      combinedDH.set(dh4, 96);
    }

    // 4. Derive Master Shared Key via HKDF
    const sharedKey = deriveKey(combinedDH, X3DH_SALT, X3DH_INFO, 32);

    return {
      sharedKey,
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      oneTimeKeyIdUsed: recipientBundle.oneTimePreKey?.keyId,
    };
  }

  /**
   * Responder (Receiver, e.g. Bob) computes shared key from Alice's headers
   */
  static respond(
    recipientIdentityKeyPair: DHKeyPair,
    signedPreKeyPrivateKey: Uint8Array,
    oneTimePreKeyPrivateKey: Uint8Array | null,
    senderIdentityPublicKey: Uint8Array,
    senderEphemeralPublicKey: Uint8Array
  ): Uint8Array {
    // DH1 = DH(SPK_B, IK_A)
    const dh1 = computeDH(signedPreKeyPrivateKey, senderIdentityPublicKey);
    // DH2 = DH(IK_B, EK_A)
    const dh2 = computeDH(recipientIdentityKeyPair.privateKey, senderEphemeralPublicKey);
    // DH3 = DH(SPK_B, EK_A)
    const dh3 = computeDH(signedPreKeyPrivateKey, senderEphemeralPublicKey);

    let totalDHLength = 32 * 3;
    let dh4: Uint8Array | null = null;
    if (oneTimePreKeyPrivateKey) {
      dh4 = computeDH(oneTimePreKeyPrivateKey, senderEphemeralPublicKey);
      totalDHLength += 32;
    }

    const combinedDH = new Uint8Array(totalDHLength);
    combinedDH.set(dh1, 0);
    combinedDH.set(dh2, 32);
    combinedDH.set(dh3, 64);
    if (dh4) {
      combinedDH.set(dh4, 96);
    }

    return deriveKey(combinedDH, X3DH_SALT, X3DH_INFO, 32);
  }
}
