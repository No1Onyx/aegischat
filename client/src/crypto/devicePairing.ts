import {
  generateDHKeyPair,
  computeDH,
  deriveKey,
  encryptAEAD,
  decryptAEAD,
  toBase64,
  fromBase64,
  toHex,
} from './primitives';
import type { DHKeyPair } from './primitives';

export interface LinkedDevice {
  id: string;
  name: string;
  platform: 'windows' | 'android' | 'ios' | 'macos' | 'linux' | 'web';
  linkedAt: number;
  lastActive: number;
  isCurrent: boolean;
}

export interface PairingSessionData {
  sessionId: string;
  pairingKeyPair: DHKeyPair;
  token: string;
  qrPayload: string;
  createdAt: number;
}

export interface ProvisioningBundle {
  mnemonic: string;
  username: string;
  verifiedContacts: string[];
  createdAt: number;
}

const STORAGE_LINKED_DEVICES = 'aegis_linked_devices';

export class DevicePairingManager {
  /**
   * Generates an ephemeral pairing session and returns QR code payload
   */
  static createPairingSession(username: string): PairingSessionData {
    const pairingKeyPair = generateDHKeyPair();
    const tokenBytes = crypto.getRandomValues(new Uint8Array(16));
    const token = toHex(tokenBytes);
    const sessionId = 'pair_' + Math.random().toString(36).substring(2, 10);

    const pkB64 = toBase64(pairingKeyPair.publicKey);
    const qrPayload = `aegis-pair://v1?id=${sessionId}&user=${encodeURIComponent(
      username
    )}&pk=${encodeURIComponent(pkB64)}&tok=${token}`;

    return {
      sessionId,
      pairingKeyPair,
      token,
      qrPayload,
      createdAt: Date.now(),
    };
  }

  /**
   * Secondary device processes the scanned QR code payload
   */
  static processScannedQR(
    qrString: string,
    secondaryDeviceName: string,
    platform: LinkedDevice['platform'] = 'android'
  ): {
    sessionId: string;
    targetUser: string;
    pairingKey: Uint8Array;
    encryptedRequest: { ciphertext: string; nonce: string; secondaryPubKey: string };
  } {
    if (!qrString.startsWith('aegis-pair://v1?')) {
      throw new Error('Invalid AegisChat pairing QR code');
    }

    const params = new URLSearchParams(qrString.replace('aegis-pair://v1?', ''));
    const sessionId = params.get('id');
    const targetUser = params.get('user');
    const primaryPkB64 = params.get('pk');
    const token = params.get('tok');

    if (!sessionId || !targetUser || !primaryPkB64 || !token) {
      throw new Error('Malformed pairing QR parameters');
    }

    const primaryPubKey = fromBase64(primaryPkB64);
    const secondaryKeyPair = generateDHKeyPair();

    // Compute Diffie-Hellman shared secret
    const sharedSecret = computeDH(secondaryKeyPair.privateKey, primaryPubKey);
    const salt = new TextEncoder().encode(token);
    const pairingKey = deriveKey(sharedSecret, salt, 'aegis-device-pairing-v1', 32);

    // Prepare pairing request payload
    const requestPayload = JSON.stringify({
      deviceName: secondaryDeviceName,
      platform,
      token,
      timestamp: Date.now(),
    });

    const { ciphertext, nonce } = encryptAEAD(pairingKey, requestPayload);

    return {
      sessionId,
      targetUser,
      pairingKey,
      encryptedRequest: {
        ciphertext: toBase64(ciphertext),
        nonce: toBase64(nonce),
        secondaryPubKey: toBase64(secondaryKeyPair.publicKey),
      },
    };
  }

  /**
   * Primary device decrypts the secondary device request
   */
  static decryptPairingRequest(
    primaryKeyPair: DHKeyPair,
    token: string,
    encryptedRequest: { ciphertext: string; nonce: string; secondaryPubKey: string }
  ): {
    pairingKey: Uint8Array;
    requestData: { deviceName: string; platform: LinkedDevice['platform']; token: string };
  } {
    const secondaryPubKey = fromBase64(encryptedRequest.secondaryPubKey);
    const sharedSecret = computeDH(primaryKeyPair.privateKey, secondaryPubKey);
    const salt = new TextEncoder().encode(token);
    const pairingKey = deriveKey(sharedSecret, salt, 'aegis-device-pairing-v1', 32);

    const ciphertext = fromBase64(encryptedRequest.ciphertext);
    const nonce = fromBase64(encryptedRequest.nonce);
    const decryptedJson = decryptAEAD(pairingKey, nonce, ciphertext);
    const requestData = JSON.parse(decryptedJson);

    if (requestData.token !== token) {
      throw new Error('Pairing token mismatch! Possible replay or MITM attack.');
    }

    return { pairingKey, requestData };
  }

  /**
   * Primary device encrypts the identity bundle to provision secondary device
   */
  static encryptProvisioningBundle(
    pairingKey: Uint8Array,
    bundle: ProvisioningBundle
  ): { ciphertext: string; nonce: string } {
    const json = JSON.stringify(bundle);
    const { ciphertext, nonce } = encryptAEAD(pairingKey, json);
    return {
      ciphertext: toBase64(ciphertext),
      nonce: toBase64(nonce),
    };
  }

  /**
   * Secondary device decrypts the provisioning bundle to activate its local vault
   */
  static decryptProvisioningBundle(
    pairingKey: Uint8Array,
    encryptedBundle: { ciphertext: string; nonce: string }
  ): ProvisioningBundle {
    const ciphertext = fromBase64(encryptedBundle.ciphertext);
    const nonce = fromBase64(encryptedBundle.nonce);
    const json = decryptAEAD(pairingKey, nonce, ciphertext);
    return JSON.parse(json);
  }

  /**
   * Manage persistent linked device registry
   */
  static getLinkedDevices(): LinkedDevice[] {
    try {
      const stored = localStorage.getItem(STORAGE_LINKED_DEVICES);
      if (stored) return JSON.parse(stored);
    } catch {
      // ignore
    }

    // Default current device
    const defaultList: LinkedDevice[] = [
      {
        id: 'dev_primary',
        name: 'This Device (Primary)',
        platform: 'windows',
        linkedAt: Date.now() - 3600000,
        lastActive: Date.now(),
        isCurrent: true,
      },
    ];
    this.saveLinkedDevices(defaultList);
    return defaultList;
  }

  static saveLinkedDevices(devices: LinkedDevice[]): void {
    try {
      localStorage.setItem(STORAGE_LINKED_DEVICES, JSON.stringify(devices));
    } catch {
      // ignore
    }
  }

  static addLinkedDevice(device: Omit<LinkedDevice, 'id' | 'linkedAt' | 'lastActive'>): LinkedDevice {
    const currentList = this.getLinkedDevices();
    const newDevice: LinkedDevice = {
      ...device,
      id: 'dev_' + Math.random().toString(36).substring(2, 10),
      linkedAt: Date.now(),
      lastActive: Date.now(),
    };
    const updated = [...currentList, newDevice];
    this.saveLinkedDevices(updated);
    return newDevice;
  }

  static removeLinkedDevice(deviceId: string): void {
    const currentList = this.getLinkedDevices();
    const filtered = currentList.filter((d) => d.id !== deviceId || d.isCurrent);
    this.saveLinkedDevices(filtered);
  }
}
