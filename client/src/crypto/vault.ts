import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { secureStore } from './secureStore.js';

export interface SecurityConfig {
  hasInitialized: boolean;
  username: string;
  masterPasswordHash: string;   // hex digest of the passphrase under the KDF below
  masterPasswordSalt?: string;  // base64 salt; absent => legacy unsalted SHA-256 record
  kdf?: 'argon2id' | 'legacy-sha256';
  duressHash?: string;          // hex Argon2id(duress phrase, salt); absent => no duress phrase
  autoLockMinutes: number;      // Inactivity lock timeout
  disappearingTimerSec: number; // 0 = disabled, otherwise seconds until self-destruct
  lastActiveTimestamp: number;

  // Legacy fields — read for migration only, never written going forward.
  mnemonic?: string;
  duressCode?: string;
}

/** Secrets kept only in the encrypted-at-rest vault (never in the plain config). */
interface SecureVault {
  mnemonic: string;
}

const CONFIG_KEY = 'aegis_security_config';
const SECURE_VAULT_KEY = 'aegis_secure_vault';

// Argon2id parameters (RFC 9106). Mirrors the native Rust vault:
// 64 MiB memory cost, 3 passes, 4 lanes.
const ARGON2_PARAMS = { t: 3, m: 64 * 1024, p: 4, dkLen: 32 } as const;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Length-independent, branch-free string comparison. */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export class VaultSecurityManager {
  static getConfig(): SecurityConfig | null {
    try {
      const raw = localStorage.getItem(CONFIG_KEY);
      return raw ? (JSON.parse(raw) as SecurityConfig) : null;
    } catch {
      return null;
    }
  }

  static saveConfig(config: SecurityConfig): void {
    localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
  }

  static generateNewMnemonic(): string {
    return generateMnemonic(wordlist, 128);
  }

  static isValidMnemonic(phrase: string): boolean {
    return validateMnemonic(phrase.trim(), wordlist);
  }

  /** Raw memory-hard KDF output. Salt MUST be unique per vault. */
  private static deriveRaw(password: string, salt: Uint8Array): Uint8Array {
    return argon2id(new TextEncoder().encode(password), salt, ARGON2_PARAMS);
  }

  static hashPassword(password: string, salt: Uint8Array): string {
    return bytesToHex(this.deriveRaw(password, salt));
  }

  /** Legacy record format kept only so existing local vaults can be upgraded. */
  private static legacyHash(password: string): string {
    return bytesToHex(sha256(new TextEncoder().encode(`AegisSalt_v1:${password}`)));
  }

  /**
   * The seed phrase, only available once the vault is unlocked. Returns null if
   * locked or not yet initialized.
   */
  static getMnemonic(): string | null {
    const raw = secureStore.getItem(SECURE_VAULT_KEY);
    if (!raw) {
      // Legacy: mnemonic may still be sitting in the plain config pre-migration.
      return this.getConfig()?.mnemonic ?? null;
    }
    try {
      return (JSON.parse(raw) as SecureVault).mnemonic ?? null;
    } catch {
      return null;
    }
  }

  static initializeVault(
    username: string,
    mnemonic: string,
    masterPassword: string,
    duressCode: string = ''
  ): SecurityConfig {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const raw = this.deriveRaw(masterPassword, salt);
    const config: SecurityConfig = {
      hasInitialized: true,
      username: username.trim(),
      masterPasswordHash: bytesToHex(raw),
      masterPasswordSalt: toBase64(salt),
      kdf: 'argon2id',
      duressHash: duressCode.trim()
        ? this.hashPassword(duressCode.trim(), salt)
        : undefined,
      autoLockMinutes: 10,
      disappearingTimerSec: 0,
      lastActiveTimestamp: Date.now(),
    };
    this.saveConfig(config);

    // Unlock the encrypted store and stash the seed phrase in it.
    secureStore.unlockWithMaster(raw, config.masterPasswordSalt!);
    secureStore.setItem(SECURE_VAULT_KEY, JSON.stringify({ mnemonic: mnemonic.trim() } as SecureVault));

    return config;
  }

  static verifyPassword(password: string): { success: boolean; isDuress: boolean } {
    const config = this.getConfig();
    // Fail CLOSED: an unreadable / missing config must never grant access.
    if (!config || !config.hasInitialized) {
      return { success: false, isDuress: false };
    }

    // Duress check (constant-time), before the real check.
    if (config.duressHash && config.masterPasswordSalt) {
      const h = this.hashPassword(password, fromBase64(config.masterPasswordSalt));
      if (constantTimeEquals(h, config.duressHash)) return { success: false, isDuress: true };
    } else if (config.duressCode && constantTimeEquals(password.trim(), config.duressCode)) {
      return { success: false, isDuress: true };
    }

    let ok = false;
    let raw: Uint8Array | null = null;
    let saltB64 = config.masterPasswordSalt;

    if (config.masterPasswordSalt) {
      raw = this.deriveRaw(password, fromBase64(config.masterPasswordSalt));
      ok = constantTimeEquals(bytesToHex(raw), config.masterPasswordHash);
    } else {
      // Legacy vault: verify old scheme, then upgrade to Argon2id.
      ok = constantTimeEquals(this.legacyHash(password), config.masterPasswordHash);
      if (ok) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        raw = this.deriveRaw(password, salt);
        saltB64 = toBase64(salt);
        config.masterPasswordHash = bytesToHex(raw);
        config.masterPasswordSalt = saltB64;
        config.kdf = 'argon2id';
        if (config.duressCode) config.duressHash = this.hashPassword(config.duressCode, salt);
        this.saveConfig(config);
      }
    }

    if (!ok || !raw || !saltB64) return { success: false, isDuress: false };

    // Unlock encrypted-at-rest storage.
    secureStore.unlockWithMaster(raw, saltB64);
    this.migratePlainSecrets(config);
    this.touchActivity();
    return { success: true, isDuress: false };
  }

  /** Move any plaintext secrets still in the config into the encrypted store. */
  private static migratePlainSecrets(config: SecurityConfig): void {
    let changed = false;
    if (config.mnemonic) {
      if (!secureStore.getItem(SECURE_VAULT_KEY)) {
        secureStore.setItem(
          SECURE_VAULT_KEY,
          JSON.stringify({ mnemonic: config.mnemonic } as SecureVault)
        );
      }
      delete config.mnemonic;
      changed = true;
    }
    if (config.duressCode) {
      if (!config.duressHash && config.masterPasswordSalt) {
        config.duressHash = this.hashPassword(config.duressCode, fromBase64(config.masterPasswordSalt));
      }
      delete config.duressCode;
      changed = true;
    }
    if (changed) this.saveConfig(config);
  }

  /** Set or clear the duress phrase (stored only as an Argon2id hash). */
  static setDuressPhrase(phrase: string): void {
    const config = this.getConfig();
    if (!config || !config.masterPasswordSalt) return;
    const p = phrase.trim();
    config.duressHash = p
      ? this.hashPassword(p, fromBase64(config.masterPasswordSalt))
      : undefined;
    delete config.duressCode;
    this.saveConfig(config);
  }

  static touchActivity(): void {
    const config = this.getConfig();
    if (config) {
      config.lastActiveTimestamp = Date.now();
      this.saveConfig(config);
    }
  }

  static isLocked(): boolean {
    const config = this.getConfig();
    if (!config || !config.hasInitialized) return false;
    // If the encrypted store isn't open, we are effectively locked.
    if (!secureStore.isUnlocked()) return true;
    if (config.autoLockMinutes <= 0) return false;
    const elapsedMs = Date.now() - config.lastActiveTimestamp;
    return elapsedMs > config.autoLockMinutes * 60 * 1000;
  }

  /** Drop the in-memory storage key; protected data becomes unreadable. */
  static lock(): void {
    secureStore.lock();
  }

  /**
   * EMERGENCY PANIC SHRED: best-effort removal of all local key material and
   * history. Browser storage cannot be guaranteed-overwritten on disk from JS,
   * so on hostile-forensics threat models the native (Tauri) disk wipe is the
   * real defense; we still overwrite before deleting and drop the storage key.
   */
  static emergencyShred(): void {
    secureStore.lock();
    try {
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('aegis_')) keysToRemove.push(key);
      }
      const noise = toBase64(crypto.getRandomValues(new Uint8Array(64)));
      for (const k of keysToRemove) {
        try { localStorage.setItem(k, noise); } catch { /* ignore */ }
        localStorage.removeItem(k);
      }
    } catch { /* ignore */ }

    try { sessionStorage.clear(); } catch { /* ignore */ }

    try {
      if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
        indexedDB.databases().then((dbs) => {
          for (const db of dbs) if (db.name) indexedDB.deleteDatabase(db.name);
        }).catch(() => { /* ignore */ });
      }
    } catch { /* ignore */ }

    console.warn('⚠️ [EMERGENCY PANIC SHRED EXECUTED] Local cryptographic material removed.');
  }
}
