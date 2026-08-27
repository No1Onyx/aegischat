import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Transparent encryption-at-rest for the sensitive localStorage entries
 * (identity keys, ratchet sessions, group keys, identity pins, message history,
 * the seed phrase).
 *
 * The storage key is derived from the Argon2id master output produced when the
 * passphrase is entered, and lives in memory only. While the vault is locked the
 * store cannot read protected values. Values written before the store is ever
 * unlocked (e.g. very first paint) are stored in the clear and migrated to
 * ciphertext on the next unlock.
 *
 * Layout of an encrypted value:  "AEGENC1:" + base64( nonce[12] || ChaCha20Poly1305_ct )
 * The localStorage key name is bound in as associated data.
 */

const ENC_MARKER = 'AEGENC1:';
const STORAGE_KEY_INFO = new TextEncoder().encode('aegis-storage-key-v1');

// Which localStorage keys this store is responsible for encrypting.
const PROTECTED_PREFIXES = [
  'aegis_vault_',
  'aegis_sessions_',
  'aegis_group_session_',
  'aegis_pins_',
];
const PROTECTED_EXACT = new Set([
  'aegis_chat_messages',
  'aegis_secure_vault',
]);

export function isProtectedKey(name: string): boolean {
  if (PROTECTED_EXACT.has(name)) return true;
  return PROTECTED_PREFIXES.some((p) => name.startsWith(p));
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function hasLocalStorage(): boolean {
  return typeof window !== 'undefined' && !!window.localStorage;
}

class SecureStore {
  private key: Uint8Array | null = null;

  isUnlocked(): boolean {
    return this.key !== null;
  }

  /** Derive the storage key from the Argon2id master output (32 bytes). */
  unlockWithMaster(masterBytes: Uint8Array, saltB64: string): void {
    this.key = hkdf(sha256, masterBytes, fromBase64(saltB64), STORAGE_KEY_INFO, 32);
    this.migratePlaintext();
  }

  lock(): void {
    if (this.key) this.key.fill(0);
    this.key = null;
  }

  getItem(name: string): string | null {
    if (!hasLocalStorage()) return null;
    const raw = window.localStorage.getItem(name);
    if (raw === null) return null;
    if (!raw.startsWith(ENC_MARKER)) return raw; // legacy plaintext
    if (!this.key) return null;                  // locked
    try {
      const buf = fromBase64(raw.slice(ENC_MARKER.length));
      const nonce = buf.slice(0, 12);
      const ct = buf.slice(12);
      const aad = new TextEncoder().encode(name);
      const pt = chacha20poly1305(this.key, nonce, aad).decrypt(ct);
      return new TextDecoder().decode(pt);
    } catch {
      return null;
    }
  }

  setItem(name: string, value: string): void {
    if (!hasLocalStorage()) return;
    if (!this.key || !isProtectedKey(name)) {
      window.localStorage.setItem(name, value);
      return;
    }
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(name);
    const ct = chacha20poly1305(this.key, nonce, aad).encrypt(new TextEncoder().encode(value));
    const packed = new Uint8Array(12 + ct.length);
    packed.set(nonce, 0);
    packed.set(ct, 12);
    window.localStorage.setItem(name, ENC_MARKER + toBase64(packed));
  }

  removeItem(name: string): void {
    if (hasLocalStorage()) window.localStorage.removeItem(name);
  }

  /** Re-encrypt any protected values still sitting in plaintext. */
  private migratePlaintext(): void {
    if (!hasLocalStorage() || !this.key) return;
    const names: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      if (k && isProtectedKey(k)) names.push(k);
    }
    for (const k of names) {
      const raw = window.localStorage.getItem(k);
      if (raw !== null && !raw.startsWith(ENC_MARKER)) {
        this.setItem(k, raw);
      }
    }
  }
}

export const secureStore = new SecureStore();
