# AegisChat

An end-to-end encrypted messenger built on the Signal protocol family (X3DH +
Double Ratchet), a metadata-minimising **untrusted relay**, and a memory-safe
Rust crypto core. Targets: Windows / macOS / Linux desktop, Android, iOS, and
the web.

> **Status: pre-audit.** This is not a finished product and has **not** been
> independently reviewed. Do not use it as the only protection for
> communications where disclosure could get someone hurt. Read
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
> [`SECURITY.md`](SECURITY.md) first.

---

## What it actually does today

| Property | How |
|---|---|
| **Confidential 1:1 messages** | X3DH session setup → Double Ratchet. ChaCha20-Poly1305 AEAD. Keys never leave the client. |
| **Forward secrecy + post-compromise security** | Per-message symmetric ratchet; per-turn DH ratchet rotating the root key. |
| **Group messages** | Signal-style Sender Keys (Ed25519-signed), re-keyed when a member is removed. |
| **The relay doesn't see who talks to whom** | Sealed sender: the outer envelope carries only a blind delivery token; group messages fan out as per-recipient sealed envelopes. |
| **Identity you can verify** | 12-word BIP-39 seed → deterministic identity keys (restore on any device). Trust-on-first-use pinning; the app requires an out-of-band 60-digit safety-number check before the first message and hard-fails if a contact's key later changes. |
| **Encrypted at rest** | Every key/seed/session/message blob in local storage is ChaCha20-Poly1305-encrypted under an Argon2id-derived key (64 MiB, t=3, p=4) that lives only in RAM and is dropped on lock. |
| **Duress phrase** | A decoy passphrase (stored only as a hash) triggers an emergency shred. |
| **Replay / DoS resistance** | Per-session seen-id set + signed-timestamp window; `MAX_SKIP` bounds on ratchet catch-up; all server collections bounded. |

## What it does **not** do (yet)

- Group **creation** still tells the relay the member list (message routing is blind; setup isn't).
- Tor / SOCKS5 / domain-fronting are not enforceable from a web page — they need Tor Browser, a system proxy, or the native build. A relay-URL override and a fronting header are provided.
- Traffic-analysis resistance is limited to 256-byte size bucketing. Timing/volume/online-status are visible to the relay.
- WebRTC calls leak your IP to STUN (and, without a TURN server, to the peer). `relay-only` mode exists but needs your own TURN server.
- The native disk-wipe and RAM-zeroization in `core-crypto/` are **not wired into the app**. The Rust core is reference code with locked interop vectors; the shipping client uses its own TypeScript crypto.
- Multi-device sync, message-history backup, RAM hygiene in the web build.

Full detail: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) ·
[`docs/SECURITY_REVIEW_CHECKLIST.md`](docs/SECURITY_REVIEW_CHECKLIST.md)

---

## Layout

```
core-crypto/   Rust crypto engine (reference + FFI + interop vectors; not on the live path)
  src/identity.rs        BIP-39 → identity keys
  src/double_ratchet.rs  Double Ratchet
  src/sealed_sender.rs   sealed-sender primitives
  src/storage.rs         Argon2id encrypted database + duress wipe
  fuzz/                   cargo-fuzz targets
  tests/adversarial.rs   malformed-input regression tests

client/        React + TypeScript app; Tauri v2 shell for desktop/mobile
  src/crypto/           the crypto actually used at runtime
    primitives.ts         AEAD, HKDF, seed→identity, sealed-sender, blind token
    x3dh.ts / doubleRatchet.ts / senderKeys.ts
    sessionManager.ts     sessions, pinning, replay defence, sealed transport
    vault.ts / secureStore.ts   passphrase KDF + encryption at rest
    webrtcManager.ts      E2EE calls
  src/App.tsx           UI

server/        Untrusted blind relay + prekey directory (Node/Express/ws)
  src/relay.ts           sealed + legacy routing, bounded queues
  src/keyDirectory.ts    public prekey bundles
  src/test-*.ts          integration test harnesses
```

---

## Run it

Requires Node 20+ and a stable Rust toolchain. Copy `.env.example` to `.env`
first (defaults are fine for local dev).

```bash
npm install && npm --prefix client install && npm --prefix server install

npm run dev            # relay on :4000, web client on :5173
```

- Web client: <http://localhost:5173>
- Two identities in one browser: `?user=Alice` and `?user=Bob` in separate tabs.

Native desktop:

```bash
npm run desktop:dev            # dev window
npm run desktop:build          # installer
```

Mobile: see [`docs/MOBILE_PACKAGING_GUIDE.md`](docs/MOBILE_PACKAGING_GUIDE.md).
Deployment (TLS, relay hosting): [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Test

```bash
npm run typecheck        # client + server tsc
npm run test:unit        # cargo test + crypto vectors + security regressions
npm run test:live        # integration suites (starts nothing — run `npm run dev:server` first,
                         #   or let CI start the relay)
cargo test --manifest-path core-crypto/Cargo.toml --test adversarial
```

CI (`.github/workflows/ci.yml`) runs all of the above plus `npm audit` /
`cargo audit`. A nightly workflow runs the `cargo-fuzz` targets.

---

## Contributing / reviewing

Security reports: **private**, see [`SECURITY.md`](SECURITY.md). If you want to
review the cryptography, [`docs/SECURITY_REVIEW_CHECKLIST.md`](docs/SECURITY_REVIEW_CHECKLIST.md)
is the map.

## License

Apache-2.0.
