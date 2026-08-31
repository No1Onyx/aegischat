# AegisChat — System State Snapshot (Mindsave)

**Date:** 2026-08-31 · **Branch:** `master` · **HEAD:** `b7d37f8` · 11 commits,
clean tree, not pushed.

This file is the resumable brain-dump: where the project is, what's proven, what
isn't, and what a human still has to do. For the intended guarantees and their
limits read [`THREAT_MODEL.md`](THREAT_MODEL.md); for a reviewer's map,
[`SECURITY_REVIEW_CHECKLIST.md`](SECURITY_REVIEW_CHECKLIST.md).

> **Overall status: pre-audit. Not independently verified. Do not ship to
> at-risk users yet.**

---

## 0. One-paragraph summary

AegisChat is an X3DH + Double Ratchet messenger with Signal-style Sender Keys for
groups, sealed sender so an untrusted relay never learns who talks to whom (or
that a group exists), trust-on-first-use identity pinning with forced
safety-number verification, seed-phrase-derived identity keys, and Argon2id-keyed
encryption of everything at rest. The shipping crypto is TypeScript
(`client/src/crypto/`); the Rust `core-crypto/` engine is reference code + locked
interop vectors and is **not on the live path**. ~80 automated checks pass; no
independent security review has happened.

---

## 1. Components — what is actually on the runtime path

| Component | Live? | Notes |
|---|---|---|
| `client/src/crypto/*.ts` | **Yes** | The crypto the app runs. |
| `server/src/*` (relay) | **Yes** | Untrusted router + prekey directory. In-RAM only, no DB. |
| `core-crypto/` (Rust) | **No** | Reference engine + FFI. Tauri exposes only `generate_identity`, `restore_identity`, `compute_safety_number`, `emergency_wipe_database`. Identity derivation + blind-token are byte-interop with TS (test vectors); nothing else is wired in. |
| `meshNetwork.ts` | **No** | Simulated (`window` CustomEvent bus). |
| `transport.ts` Tor/SOCKS5/fronting | **Partial** | Relay-URL override + fronting header work from JS; SOCKS5/Tor need Tor Browser / system proxy / native build. |

---

## 2. Security work applied (commit-by-commit)

| Commit | Content |
|---|---|
| `2b89980` | **P0/P1**: Double Ratchet `MAX_SKIP` + commit-after-verify + skipped-key reuse/persistence (TS+Rust); Argon2id passphrase KDF + salt + fail-closed + constant-time; encryption at rest (`secureStore`, ChaCha20-Poly1305); seed-phrase-derived identity (TS↔Rust vectors); TOFU identity pinning + forced safety-number verification; sealed sender for 1:1; server resource bounds, CSP, crypto-secure IDs, CORS allowlist. |
| `59d60a7` | Sealed sender extended to **group messages** (per-recipient sealed fan-out); group sender-key rotation on member removal. |
| `51b23af` | Session-layer **replay defence**: persisted seen-id LRU + signed-timestamp window. |
| `02a9a53` | WebRTC call-privacy modes (`standard`/`relay-only`/`no-stun` + TURN); `transport.ts` made honest about what a browser can enforce. |
| `dccb73d` | Argon2id unlock moved **off the main thread** (`argon2idAsync`); LockScreen/Onboarding/Settings await it. |
| `2915e9b` | Group **member-removal UI** (Members panel); Rust `sealed_transport_key` parity vector. |
| `3e3e467` | Relay URL / port / CORS configurable via env (`VITE_RELAY_URL`, `AEGIS_RELAY_URL`, `PORT`, `AEGIS_ALLOWED_ORIGINS`) + `.env.example`. |
| `929cede` | `test:security` (headless regression suite), aggregate npm scripts, **CI** (`.github/workflows/ci.yml`), npm/cargo audit. |
| `c4e49e9` | **Fuzzing**: `core-crypto/fuzz/` (5 cargo-fuzz targets) + `tests/adversarial.rs` (stable, in CI) + nightly `fuzz.yml`. |
| `823bf05` | `SECURITY.md`, `THREAT_MODEL.md`, `SECURITY_REVIEW_CHECKLIST.md`, `DEPLOYMENT.md` + `deploy/` (compose/Dockerfile/Caddyfile); README rewritten; "uncrackable" removed from UI + docs. |
| `b7d37f8` | **Blind groups**: no server-side group registration at all. `createGroup` is local; definition + sender key travel as sealed 1:1 `_aegisGroupInvite`. Removed all `/api/groups/*` endpoints. |

---

## 3. What works end to end (automated)

Run: `npm run typecheck && npm run test:unit && npm run test:live`
(+ `cargo test --manifest-path core-crypto/Cargo.toml`).

| Suite | Checks | Covers |
|---|---|---|
| `test:crypto` | 9 | AEAD, X3DH, Double Ratchet FS/PCS, safety number, tamper, **seed→identity + blind-token Rust-interop vectors** |
| `test:security` | 23 | MAX_SKIP bound, commit-after-verify (session survives a forged packet), out-of-order + skipped-key persistence, sealed-sender round-trip + wrong-key rejection, group sender-key rotation locks out a removed member, full vault lifecycle (Argon2id / at-rest ciphertext / duress-as-hash / lock) |
| `test:e2e` | 10 | live relay: X3DH handshake, FS, DH ratchet, zero-knowledge audit, safety number, **#10 = blind client-side group: sealed invite delivered + relay audit has zero group record** |
| `test:groups` | 5 | Sender Keys, Ed25519 tamper rejection, forward secrecy |
| `test:calling` / `mesh` / `pairing` / `censorship` / `attachments` | 4/3/5/3/1 | their respective integration harnesses |
| `cargo test` | 10 + 5 | core-crypto unit + `adversarial.rs` (malformed-input, no-panic) |

CI also runs `npm audit` (0 vulns) and `cargo audit` (clean); nightly runs the
fuzz targets.

---

## 4. Known gaps (accepted for this version)

1. **Traffic analysis** — only 256-byte size bucketing; timing / volume /
   online-status visible to the relay. No decoy traffic.
2. **Tor / SOCKS5 / domain-fronting** — not enforceable from a web page.
3. **WebRTC** — IP visible to STUN and (no TURN) to the peer.
4. **Native disk wipe / RAM zeroization** (`core-crypto/`) not wired into the app.
5. **Multi-device sync** and message-history backup — not implemented; restoring
   the seed reproduces the identity, not history.
6. **Key directory** — no account auth; `/api/keys/register` overwrites. A4
   (directory poisoning) is *mitigated* by pinning + verification, not prevented.
   `/api/audit`, `/api/users` unauthenticated. No rate limiting (do it at the proxy).
7. **No independent audit.**
8. `GROUP_ENVELOPE` / `routeGroupEnvelope` / `offlineGroupQueues` remain in the
   relay as inert dead code (groups never populate `this.groups`).

---

## 5. Human to-do (nothing here can be done by the model alone)

1. **Manual browser QA** — `npm run dev` (kill the stale relay on :4000 first),
   `localStorage.clear()` once, then: onboard → lock → unlock → verify safety
   number → 1:1 in two tabs (`?user=Alice` / `?user=Bob`) → create group → send →
   Members panel → remove a member → duress phrase → **reload** and confirm
   history/sessions/groups return. The App lock/unlock/group wiring is the
   least-tested code.
2. **Push** the repo; enable the CI + fuzz workflows.
3. Fill placeholders: `SECURITY.md` PGP fingerprint; `deploy/Caddyfile` hostname
   + email; prod client build `VITE_RELAY_URL=…` and widen Tauri `connect-src`.
4. **Run the fuzzers** (Linux / nightly): `cd core-crypto && cargo +nightly fuzz
   run <target> -- -max_total_time=600` for each of the 5 targets.
5. **Independent review** — `SECURITY_REVIEW_CHECKLIST.md` is the map. Firm
   (Cure53 / Trail of Bits / ROS) or free (open-source + cryptography community +
   cold multi-model review + small bug bounty). Do **not** put it in front of
   at-risk users before this.
6. Decide the Rust core's fate — wire `core-crypto/` onto the live path (real
   RAM-zeroization + disk wipe) or formally mark it reference-only.

---

## 6. Roadmap (after the human to-do)

1. Blind group setup edge cases: creator-only definition updates already
   enforced — audit in-flight-message handling during sender-key rotation, and
   pre-rotation replay by a removed member (currently only `markSeen` stops it).
2. Remove `username` from the WS `AUTH` message (only `/api/users` + inert paths
   still use it) so a passive relay can't map connection ↔ username.
3. Real anti-traffic-analysis: decoy traffic, constant-rate option.
4. Wire the Rust core; delete the dead `GROUP_ENVELOPE` cluster.
5. Multi-device: finish the pairing flow into real session sync.
6. Deployment hardening: proxy rate limiting, log scrubbing, reproducible client
   build + published hash.

---

## 7. Quick reference

```
npm run dev            # relay :4000 + client :5173
npm run typecheck      # client + server (incl. tests)
npm run test:unit      # cargo test + crypto vectors + security regressions
npm run test:live      # 7 integration suites (needs a relay running)
cargo test --manifest-path core-crypto/Cargo.toml   # + --test adversarial

Key files:
  client/src/crypto/sessionManager.ts   sessions, pinning, replay, sealed transport, groups
  client/src/crypto/doubleRatchet.ts    ratchet (MAX_SKIP, commit-after-verify)
  client/src/crypto/vault.ts            passphrase KDF (Argon2id, async)
  client/src/crypto/secureStore.ts      encryption at rest
  client/src/crypto/primitives.ts       AEAD, HKDF, seed→identity, sealed sender, blind token
  server/src/relay.ts                   sealed routing, bounded queues
  core-crypto/src/                      Rust reference engine (+ fuzz/, tests/adversarial.rs)
  docs/THREAT_MODEL.md, SECURITY_REVIEW_CHECKLIST.md, DEPLOYMENT.md, SECURITY.md
```
