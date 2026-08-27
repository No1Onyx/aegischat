# AegisChat - Zero-Knowledge End-to-End Encrypted Messaging Platform
## Designed for Absolute Privacy, Anti-Forensics & Freedom of Speech

AegisChat is an uncrackable, cryptographically hardened messaging system built on the **Signal Protocol specification** (Extended Triple Diffie-Hellman + Double Ratchet Algorithm), a **Zero-Knowledge Blind Relay Server**, and a **Memory-Safe Rust Engine with Anti-Forensics Database Protection**.

Target Platforms: **Windows, macOS, Linux (PC), iOS, Android**.

---

## 🛡️ The 5 Unbreakable Security Pillars

Unlike standard cloud chats where servers hold decryption keys, phone numbers link identities, and unencrypted databases sit on devices, AegisChat enforces strict mathematical and architectural guarantees:

1. **Zero-Anchor Identity (No Phone, No Email, No SMS)**:
   * Identity is derived deterministically from a **12-word BIP-39 mnemonic seed phrase**.
   * Eliminates telecom SIM-swapping, SS7 network interception, and government carrier subpoenas.
   * Derives Ed25519 signing keys and X25519 Diffie-Hellman keys on the device.

2. **Sealed Sender (Metadata & Traffic Analysis Stripping)**:
   * The sender's identity is encrypted *inside* the payload and signed with Ed25519.
   * The outer envelope visible to the relay server contains only an ephemeral **Blind Delivery Token**.
   * **The server cannot see who sent the message**, preventing social communication graph tracking.

3. **Memory-Hard Encrypted Storage at Rest (Argon2id + ChaCha20-Poly1305)**:
   * Local database files are encrypted with keys derived via **Argon2id (RFC 9106)** with 64 MB memory cost.
   * Immune to GPU/ASIC brute-force password cracking clusters.
   * **Panic Button / Duress Passphrase**: Entering a configured duress phrase triggers an **instant cryptographic shred** (overwriting the database on disk with cryptographic noise before deleting it).
   * **Self-Destructing Messages**: Disappearing messages with expiration timestamps are automatically scrubbed upon load.

4. **Signal Double Ratchet + RAM Zeroization (`ZeroizeOnDrop`)**:
   * **Forward Secrecy**: Every single message derives a brand-new symmetric key.
   * **Break-in Recovery**: Every turn alternation generates a new ephemeral Diffie-Hellman keypair, rotating the root key.
   * All private keys and intermediate secrets are automatically overwritten with zeros in RAM on drop.

5. **Untrusted Zero-Knowledge Blind Relay**:
   * The backend operates strictly as an untrusted router. It never handles private keys, never stores message history, and purges envelopes from ephemeral RAM the microsecond receipt is acknowledged.

---

## 📁 Monorepo Structure

```
D:\newapp
├── core-crypto/                # Memory-Safe Rust Cryptographic Core
│   ├── src/
│   │   ├── identity.rs         # BIP-39 Zero-Anchor identity vault
│   │   ├── aead.rs             # ChaCha20-Poly1305 authenticated encryption
│   │   ├── kdf.rs              # HKDF-SHA256 key derivation
│   │   ├── double_ratchet.rs   # Pure Rust Double Ratchet algorithm
│   │   ├── sealed_sender.rs    # Metadata-stripping Sealed Sender protocol
│   │   ├── safety_number.rs    # 60-digit MITM fingerprint generator
│   │   ├── storage.rs          # Argon2id encrypted database & duress wipe
│   │   └── ffi.rs              # C-FFI exports for iOS, Android, and PC
│   ├── aegis_core_crypto.h     # C header for native cross-platform linking
│   └── Cargo.toml
├── client/                     # Telegram-Styled Client & Tauri v2 Shell
│   ├── src/                    # React + TypeScript + Tailwind UI
│   │   ├── crypto/             # Client-side cryptographic session manager
│   │   ├── components/         # Live crypto inspector, safety numbers, logs
│   │   └── App.tsx             # Interactive messaging interface
│   └── src-tauri/              # Native Tauri v2 Desktop/Mobile Rust Shell
│       ├── src/lib.rs          # Native desktop/mobile bridge to core-crypto
│       └── tauri.conf.json     # Windows, Android, and iOS window configuration
├── server/                     # Zero-Knowledge Blind Relay Server
│   ├── src/
│   │   ├── keyDirectory.ts     # Public prekey bundle storage
│   │   ├── relay.ts            # Ephemeral message router & audit logger
│   │   └── index.ts            # Express & WebSocket server (port 4000)
└── package.json                # Monorepo orchestration scripts
```

---

## 🧪 Comprehensive Verification Commands

### 1. Test the Rust Cryptographic & Storage Engine (7 Tests)
Verifies BIP-39 mnemonic recovery, Double Ratchet rotation, Sealed Sender, Argon2id encrypted database, tamper detection, and duress emergency wipe:
```bash
npm run test:rust
```

### 2. Test the Web Cryptographic Suite (8 Tests)
Verifies client-side X3DH, ChaCha20-Poly1305 AEAD, Double Ratchet, and Safety Numbers:
```bash
npm run test:crypto
```

### 3. Test Live End-to-End Relay Over WebSockets (9 Tests)
Launches simulated independent clients over live network WebSockets, transmits real encrypted envelopes, and verifies zero-knowledge audit logs:
```bash
npm run test:e2e
```

---

## 🚀 How to Run the Application

### Option A: Web Browser Mode
Start the Blind Relay Server and the Web Client simultaneously:
```bash
npm run dev
```
* **Client App**: [http://localhost:5173](http://localhost:5173)
* **Relay Server**: `http://localhost:4000` (WebSocket at `ws://localhost:4000/ws`)

### Option B: Native Desktop Application (Windows PC)
Run the native desktop shell linking directly to the Rust core:
```bash
npm run desktop:dev
```

To compile a standalone, optimized Windows installer/executable (`.exe`):
```bash
npm run desktop:build
```

### Option C: Mobile Builds (Android / iOS)
* **Android**: `npm run mobile:android` (requires Android Studio / NDK)
* **iOS**: `npm run mobile:ios` (requires macOS with Xcode)
