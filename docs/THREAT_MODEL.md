# AegisChat — Threat Model

Status: **pre-audit.** This document describes what the current implementation
is *designed* to protect, what it explicitly does not, and the assumptions the
guarantees rest on. It is the starting point for an independent review, not a
claim that the design has been verified.

---

## 1. What the system is

A messaging system in three parts:

| Part | Language | Role |
|---|---|---|
| `client/` | TypeScript + React (web) / Tauri (desktop, mobile) | All key material and all encryption/decryption. |
| `server/` (relay) | TypeScript / Node | Untrusted store-and-forward router + public-prekey directory. |
| `core-crypto/` | Rust | Reference/native crypto engine. **Not on the live path yet** — the shipping client uses its own TS implementation. Interop for identity derivation and blind tokens is locked with test vectors. |

Protocols: X3DH for session setup, Double Ratchet for 1:1 messages, Signal-style
Sender Keys for groups, a sealed-sender envelope so the relay does not see who is
talking to whom.

---

## 2. Assets to protect

1. **Message content** (text, attachments, voice notes, call media) — 1:1 and group.
2. **Long-term identity private keys** — derived from a 12-word BIP-39 phrase.
3. **The seed phrase itself** — at rest on the device.
4. **Communication metadata** — who talks to whom, when, group membership.
5. **Local message history** — at rest on the device.
6. **Contact authenticity** — that "Bob" is the Bob you verified.

---

## 3. Adversaries considered

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | **The relay operator** (or anyone who has compromised it) | Sees and can modify/drop/replay everything on the wire; runs arbitrary server code; keeps logs. |
| A2 | **Network observer** (ISP, national firewall, Wi-Fi operator) | Passive capture; active injection/tampering; can block. |
| A3 | **Malicious peer** | A valid participant who sends hostile payloads to a contact or a group they are in. |
| A4 | **Key-directory poisoner** | Can register/overwrite prekey bundles for arbitrary usernames (the directory has no account auth). |
| A5 | **Device thief / forensic examiner** | Has the locked device, images the disk, but does **not** have the passphrase and cannot coerce it. |
| A6 | **Coercer** | Physically compels the user to unlock the device. |

Out of scope adversaries: a global passive adversary doing traffic-correlation
across the whole internet; an attacker with a live implant on the unlocked
device (screen capture, keylogger, RAM scraping while unlocked); malicious
dependencies / compromised build pipeline; the browser or OS itself.

---

## 4. Intended guarantees

| Against | Guarantee | Mechanism |
|---|---|---|
| A1, A2 | Cannot read message content. | E2E AEAD (ChaCha20-Poly1305); keys never leave the client. |
| A1, A2 | Cannot forge or undetectably tamper with a message. | AEAD tag; ratchet header bound as AAD; sealed-sender inner payload Ed25519-signed. |
| A1, A2 | **Forward secrecy** — a key compromised today does not open past messages. | Double Ratchet symmetric + DH ratchet; fresh message key per message. |
| A1, A2 | **Post-compromise security** — after a compromise, security self-heals once both sides ratchet. | DH ratchet step rotates the root key each turn. |
| A1 | Does not learn **who sent** a 1:1 or group message, nor **group membership** while routing. | Sealed sender: outer envelope carries only a blind delivery token; group messages fan out as per-recipient sealed envelopes. |
| A1, A2 | Cannot **replay** an old message into a session. | Per-session seen-id set (persisted) + signed-timestamp window; ratchet commits state only after the AEAD tag verifies. |
| A1, A3 | Cannot cause **unbounded work** with a crafted header. | `MAX_SKIP` bound on ratchet + sender-key catch-up; server collections all bounded. |
| A3 | A single malformed/forged packet cannot **permanently desync** a session. | Decrypt derives against locals; `self` mutated only after verification. |
| A4 | Cannot **silently** man-in-the-middle an established contact. | Trust-on-first-use: identity + signing key pinned on first contact; any later change hard-fails the send and forces re-verification. First contact is authenticated out-of-band via the 60-digit safety number (UI requires it before the first message). |
| A5 | Cannot read keys, seed phrase, or history from the disk image. | Everything sensitive in local storage is ChaCha20-Poly1305-encrypted under a key derived from the passphrase with Argon2id (64 MiB, t=3, p=4); the storage key is held only in memory and dropped on lock. |
| A5 | Cannot brute-force the passphrase quickly offline. | Argon2id, random per-vault salt. (Strength still bounded by passphrase entropy.) |
| A6 | Can present a decoy that destroys data instead of revealing it. | Duress phrase (stored only as an Argon2id hash) triggers an emergency shred. |

---

## 5. Non-guarantees (known and accepted, this version)

- **Group *creation*** currently registers the roster with the relay over REST
  (`POST /api/groups/create`). Message *routing* is blind, but the relay learns
  the member list at group-setup time. A blind group-setup handshake is designed
  but not implemented.
- **Traffic analysis.** Message size is bucketed (256-byte padding) but timing,
  frequency, online/offline transitions, and total volume are observable to
  A1/A2. `dummyKeepAliveTraffic` is a config flag with no implementation.
- **Tor / SOCKS5 / domain fronting** are not enforceable from a web page. They
  require Tor Browser, a system proxy, or the native build. The client exposes a
  relay-URL override (mirror / onion service / reverse proxy) and a fronting
  header, and is explicit about the rest.
- **WebRTC calls** reveal the caller's IP to STUN servers and, without a TURN
  server, to the peer. `relay-only` mode exists but needs a user-supplied TURN
  server.
- **Anti-forensic disk wipe** in the web build is best-effort (`localStorage`
  cannot be securely overwritten from JS). The native (Tauri) build's Rust disk
  wipe is the real mechanism and is **not yet wired into the app**.
- **Multi-device.** Ratchet/session state is per-device; the pairing flow exists
  but full multi-device sync is not implemented. Restoring the seed phrase
  reproduces the *identity* but not message history.
- **RAM hygiene.** The web client cannot zero key bytes reliably (JS/GC). The
  Rust core does (`ZeroizeOnDrop`) but is not on the live path.
- **Metadata in the audit log.** The relay keeps a bounded in-RAM audit log,
  served unauthenticated at `/api/audit`. Post-sealed-sender it no longer records
  1:1 sender/recipient, but group *creation* entries name the creator and members.
- **Registration.** The key directory has no account authentication (A4 is
  mitigated only by pinning + user verification, not prevented).
- **The Rust `core-crypto` engine is not exercised by the running product.**
  Its tests pass; it is reference code plus locked interop vectors.

---

## 6. Assumptions the guarantees depend on

1. The user's device is not already compromised while unlocked.
2. The user actually compares the safety number out-of-band before trusting a
   new contact, and re-verifies when warned of a key change.
3. The passphrase has enough entropy that Argon2id-bounded offline guessing is
   infeasible.
4. `@noble/*`, `@scure/*`, and the RustCrypto crates on disk are the audited
   upstream source (no supply-chain compromise).
5. `crypto.getRandomValues` / `OsRng` are sound on the platform.
6. TLS terminates at a relay the operator controls; the relay is still treated
   as fully untrusted for confidentiality and metadata, but availability and
   transport integrity assume TLS.
7. The build and delivery of the client binary/page is trusted (out of scope
   here; see deployment guidance).

---

## 7. Residual risks worth an auditor's focus

- Correctness of the Double Ratchet rewrite (commit-after-verify, skipped-key
  handling, DH-ratchet edge cases, state serialization round-trip).
- Sealed-sender construction: AAD binding, signature coverage, key-reuse across
  the ephemeral DH, canonical-JSON signing (key-order fragility).
- TOFU pinning: race conditions between first inbound and first outbound;
  partial pins (inbound-only, no signing key); the "accept new key" path.
- `secureStore`: values written before first unlock; migration of legacy
  plaintext; AAD = key name; behaviour when `localStorage` throws / is evicted.
- Group rekey: is redistribution reliable? what happens to in-flight messages
  during rotation? can a removed member replay a pre-rotation message?
- Server resource bounds: are all growth paths actually capped? unauthenticated
  endpoints (`/api/audit`, `/api/users`, group creation).
- Randomness, nonce uniqueness under state rollback, integer handling in the
  skip loops.
