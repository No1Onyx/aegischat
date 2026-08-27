import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { toBase64, fromBase64 } from './primitives.js';
import { RELAY_URL } from '../config.js';

export interface EncryptedAttachmentDescriptor {
  attachmentId: string;
  key: string;       // Base64 32-byte ChaCha20 key
  nonce: string;     // Base64 12-byte Nonce
  fileName: string;
  fileType: string;
  fileSize: number;
  isVoiceNote?: boolean;
  durationSec?: number;
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// In-memory cache for decrypted blob URLs
const decryptedBlobCache = new Map<string, string>();

export class AttachmentCrypto {
  /**
   * Encrypts a file or voice recording in memory with ChaCha20-Poly1305,
   * uploads the pure ciphertext to the blind relay, and returns the descriptor.
   */
  static async encryptAndUpload(
    fileOrBlob: Blob | File,
    fileName: string = 'attachment.bin',
    isVoiceNote: boolean = false,
    durationSec?: number,
    serverUrl: string = RELAY_URL
  ): Promise<EncryptedAttachmentDescriptor> {
    const arrayBuffer = await fileOrBlob.arrayBuffer();
    const rawBytes = new Uint8Array(arrayBuffer);

    // 1. Generate ephemeral 256-bit media key and 12-byte nonce
    const mediaKey = randomBytes(32);
    const nonce = randomBytes(12);

    // 2. Encrypt with ChaCha20-Poly1305
    const cipher = chacha20poly1305(mediaKey, nonce);
    const ciphertext = cipher.encrypt(rawBytes);

    // 3. Upload opaque encrypted bytes to blind relay
    const res = await fetch(`${serverUrl}/api/attachments/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: ciphertext as unknown as BodyInit,
    });

    if (!res.ok) {
      throw new Error(`Failed to upload encrypted attachment: ${res.statusText}`);
    }

    const { attachmentId } = await res.json();

    const descriptor: EncryptedAttachmentDescriptor = {
      attachmentId,
      key: toBase64(mediaKey),
      nonce: toBase64(nonce),
      fileName,
      fileType: fileOrBlob.type || 'application/octet-stream',
      fileSize: rawBytes.length,
      isVoiceNote,
      durationSec,
    };

    // Cache our own decrypted version for instant local preview
    const localUrl = URL.createObjectURL(fileOrBlob);
    decryptedBlobCache.set(attachmentId, localUrl);

    return descriptor;
  }

  /**
   * Fetches opaque ciphertext from relay, decrypts using media key,
   * and returns a safe local object URL.
   */
  static async fetchAndDecrypt(
    descriptor: EncryptedAttachmentDescriptor,
    serverUrl: string = RELAY_URL
  ): Promise<string> {
    if (decryptedBlobCache.has(descriptor.attachmentId)) {
      return decryptedBlobCache.get(descriptor.attachmentId)!;
    }

    // 1. Fetch opaque encrypted bytes from relay
    const res = await fetch(`${serverUrl}/api/attachments/${descriptor.attachmentId}`);
    if (!res.ok) {
      throw new Error(`Attachment unavailable: ${res.statusText}`);
    }

    const encryptedBuffer = await res.arrayBuffer();
    const ciphertext = new Uint8Array(encryptedBuffer);

    // 2. Decrypt with ChaCha20-Poly1305
    const mediaKey = fromBase64(descriptor.key);
    const nonce = fromBase64(descriptor.nonce);
    const cipher = chacha20poly1305(mediaKey, nonce);

    const decryptedBytes = cipher.decrypt(ciphertext);

    // 3. Create blob URL
    const blob = new Blob([decryptedBytes.buffer as ArrayBuffer], { type: descriptor.fileType });
    const objectUrl = URL.createObjectURL(blob);

    decryptedBlobCache.set(descriptor.attachmentId, objectUrl);
    return objectUrl;
  }
}
