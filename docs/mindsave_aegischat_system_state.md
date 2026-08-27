# AegisChat — System State Snapshot

Accurate as of the current commit. Supersedes earlier aspirational versions of
this file. For intended guarantees and their limits, read
[`THREAT_MODEL.md`](THREAT_MODEL.md); for a reviewer's map,
[`SECURITY_REVIEW_CHECKLIST.md`](SECURITY_REVIEW_CHECKLIST.md).

**Overall status: pre-audit. Not verified. Do not ship to at-risk users yet.**

---

## 1. Components and whether they are on the live path

| Component | On the runtime path? | Notes |
|---|---|---|
| `client/src/crypto/*.ts` | **Yes** — this is the crypto the app runs. | X3DH, Double Ratchet, Sender Keys, sealed sender, vault/at-rest. |
| `server/src/*` (relay) | **Yes** | Untrusted router + prekey directory. |
| `core-crypto/` (Rust) | **No** | Reference engine + FFI. Tauri exposes only `generate_identity`, `restore_identity`, `compute_safety_number`, `emergency_wipe_database`. Identity derivation and blind-token are interop-locked with test vectors; the rest is not wired in. |
| `client/src/crypto/meshNetwork.ts` | **No** | Simulated (a `window` CustomEvent bus). |
| `transport.ts` Tor/SOCKS5/fronting | **Partly** | Relay-URL override + fronting header work from JS; SOCKS5/Tor need Tor Browser / system proxy / native build. |

---

## 2. What works, end to end (covered by automated tests)

- **1:1 messaging**: X3DH → Double Ratchet, forward secrecy, DH-ratchet
  post-compromise recovery. `MAX_SKIP` bound; state committed only after the
  AEAD tag verifies; skipped keys reused and persisted for out-of-order
  delivery. (`test:crypto`, `test:e2e`, `test:security`)
- **Sealed sender (1:1 and groups)**: the relay routes by blind delivery token
  only; its audit log carries no sender/recipient for messages.
  (`test:e2e` #10, `test:security`)
- **Groups**: Sender Keys, Ed25519-signed, `MAX_SENDER_SKIP` bound,
  commit-after-verify. Removing a member rotates our sender key and
  redistributes to the rest; the removed member cannot decrypt new messages.
  (`test:groups`, `test:security`)
- **Identity from seed phrase**: deterministic X25519/Ed25519 keys, byte-identical
  to the Rust core (test vectors). Restore reproduces the identity on any device.
- **Trust-on-first-use**: identity + signing key pinned on first contact; a later
  change hard-fails `sendMessage` and forces re-verification. The UI blocks the
  first message until the safety number is confirmed.
- **Encryption at rest**: all `aegis_*` key/seed/session/message blobs are
  ChaCha20-Poly1305 under an Argon2id-derived (64 MiB, t=3, p=4) key held only
  in RAM. Passphrase KDF is Argon2id + random salt, async (no UI freeze),
  fails closed. Duress phrase stored only as a hash; triggers a shred.
  (`test:security`)
- **Replay defence**: per-session seen-id LRU (persisted) + signed-timestamp
  window.
- **Server resource bounds**: queues, attachments (+TTL), groups, body/frame
  sizes all capped. CORS allowlisted. Crypto-secure IDs.
- **Attachments / voice notes / E2EE WebRTC calls / device pairing**: pass their
  integration suites. Calls support a `relay-only` privacy mode (needs a TURN
  server).

Test matrix: `npm run test:unit` (rust + crypto vectors + 23 security
regressions), `npm run test:live` (7 integration suites),
`cargo test --test adversarial` (malformed-input), `core-crypto/fuzz/`
(cargo-fuzz, nightly CI).

---

## 3. Known gaps (see THREAT_MODEL §5 for the full list)

1. **Traffic analysis**: only 256-byte size bucketing. Timing / volume /
   online-status visible to the relay. No decoy traffic.
2. **Tor / SOCKS5 / domain-fronting**: not enforceable from a web page.
3. **WebRTC**: IP visible to STUN and (no TURN) to the peer.
4. **Native disk wipe / RAM zeroization** (`core-crypto/`) not wired into the app.
5. **Multi-device sync** and message-history backup: not implemented.
6. **Key directory**: no account auth (A4 mitigated by pinning + verification,
   not prevented). `/api/audit`, `/api/users` unauthenticated.
7. **No independent audit.**

---

## 4. Roadmap

1. Manual browser QA of the full onboarding → lock → chat → group flow.
2. Wire the Rust core (identity, ratchet, storage, disk wipe) onto the live path,
   or formally deprecate it.
3. Deployment hardening: rate limiting, log scrubbing, reproducible client build.
4. Independent security review → community bug bounty.
