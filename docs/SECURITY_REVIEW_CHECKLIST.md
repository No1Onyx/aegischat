# AegisChat — Security Review Checklist

For an independent reviewer (firm or community). Pairs with `THREAT_MODEL.md`.
Ordered roughly by blast radius. "✅ intended" means the code tries to do this —
your job is to confirm it actually does, under adversarial conditions.

---

## A. Cryptographic core — 1:1 (`client/src/crypto/`)

### `primitives.ts`
- [ ] `encryptAEAD` / `decryptAEAD`: nonce is 12 random bytes per call; AAD is
      passed through unmodified; no nonce reuse across two encryptions under the
      same key even after a state rollback.
- [ ] `padPayload` / `unpadPayload`: 2-byte length field — behaviour for
      plaintext > 65535 bytes (attachments wrap descriptors, but check group
      JSON and long messages). Can a crafted "unpadded" blob starting with `0x50`
      be mis-parsed?
- [ ] `deriveIdentityFromMnemonic`: matches `core-crypto/src/identity.rs`
      (test vector `test_identity_derivation_cross_impl_vector`). HKDF salt
      handling (`undefined` ⇒ zeros) matches Rust `Hkdf::new(None, …)`.
- [ ] `blindDeliveryToken`: matches Rust `compute_blind_delivery_token`
      (vector `edpq9L4YWwMOlnEca3dJvoXRDmCTomzCS6QM/XZjYDs=`).
- [ ] `sealToRecipient` / `unsealFromSender`: ephemeral X25519 → HKDF transport
      key; AAD = blind token; is the ephemeral key authenticated (it is not
      signed — only the inner payload is)? Can the relay swap the ephemeral key
      to cause a decryption failure / downgrade?

### `x3dh.ts`
- [ ] DH ordering: `initiate` vs `respond` produce the same key (test passes) —
      confirm each of DH1–DH4 pairs correctly.
- [ ] Signed-prekey signature is verified against `signingPublicKey` **from the
      same bundle** — this is self-signed and proves nothing without TOFU.
      Confirm the TOFU layer (below) is what actually stops A4.
- [ ] Missing one-time prekey path (OPK pool exhausted): weaker but correct?
      No replenishment logic exists — is that acceptable?

### `doubleRatchet.ts` (rewritten — highest priority)
- [ ] **Commit-after-verify**: on any failure in `decrypt` (bad base64, bad
      length, AEAD tag fail, MAX_SKIP), is `this` provably unchanged? Walk the
      DH-ratchet branch specifically — it builds `rk`, `ckr`, `cks`, `dhrs`,
      `dhrr`, `ns/nr/pn` in locals then commits at the end.
- [ ] **MAX_SKIP = 1000**: `drainChain` guards `untilN - fromN`. Check both the
      previous-chain drain and the current-chain drain. Overflow / negative
      (`msgNum < nr`) handling.
- [ ] **Skipped keys**: stored on commit, looked up first on the next receive,
      deleted on use, capped at `MAX_SKIPPED_KEYS`, round-trip through
      `exportState`/`fromState`. Can an attacker exhaust the cap to evict a
      legitimate pending key?
- [ ] Late message from a *previous* DH chain (its `ratchetKey` != current
      `dhrr`): does the "try skipped first" check catch it before the code
      wrongly does a fresh DH ratchet with a stale key?
- [ ] Header JSON is `JSON.stringify(header)` used as AAD — is the byte encoding
      identical on encrypt and decrypt (key order, number formatting)?

### `sessionManager.ts`
- [ ] `handleIncomingSealedEnvelope`: order of checks is unseal → signature →
      timestamp window → `markSeen` → TOFU → dispatch. Is signature verified
      before `markSeen` burns the id? (It is — confirm an attacker can't burn
      ids without a valid signature.)
- [ ] `markSeen`: LRU eviction (5000) — replay of a very old id after eviction.
      Persistence throttle (every 16) — ids lost on a hard crash between flushes;
      is the ratchet's own rejection a sufficient backstop?
- [ ] `timestampInWindow`: −7d…+1d. Absent timestamp ⇒ skipped — exploitable?
- [ ] `checkAndPinIdentity` / `checkInboundIdentity`: partial pin (inbound-only,
      `signingKey === ''`) then a later outbound completes it — can a MITM set a
      bad partial pin from a forged inbound before the real contact is reached?
      (Inbound is signature-checked in the sealed path; the legacy `ENVELOPE`
      path is not — is it reachable?)
- [ ] `markPeerVerified(peer, acceptNewKey=true)`: re-fetches the bundle and
      pins it as verified. Is there a TOCTOU between this fetch and the next
      `sendMessage` fetch?
- [ ] `sealedSigningBytes`: signs `JSON.stringify({...inner, signature:''})`.
      Key-order must match between signer and verifier. `undefined` fields are
      dropped by `JSON.stringify` — confirm direct vs group inner objects
      round-trip identically.
- [ ] Persisted session/vault/pins/seen blobs: all go through `secureStore`
      (encrypted). Confirm nothing sensitive uses raw `localStorage`.
- [ ] `requireVerificationBeforeSend` is enforced only in the app layer
      (engine default false for test harnesses). Is that the right place?

---

## B. Groups (`senderKeys.ts`, group paths in `sessionManager.ts`)

- [ ] Groups are **client-side only** — `createGroup` never touches the relay;
      the definition + sender key go to each member as a sealed 1:1
      `_aegisGroupInvite`. Confirm the relay has no group state and `test:e2e`
      #10's audit assertion holds.
- [ ] `_aegisGroupInvite` inbound handling: the group definition is accepted
      from the sealed sender only after the outer signature verifies; **updates**
      are accepted only when `envelope.sender === existing.creator`. Can a member
      (not the creator) push a malicious roster/name update? Can the creator add
      an attacker and receive copies (yes — is that acceptable? the creator is
      trusted by group members by definition)?
- [ ] Sender-key distribution travels over the 1:1 sealed channel — so it is
      only as authenticated as that session. Confirm.
- [ ] `decrypt`: signature verified before any chain mutation; `MAX_SENDER_SKIP`
      bound; commit-after-verify (locals then commit). Skipped-key cap.
- [ ] `rotateOurSenderKey`: new chain key + new signing keypair + iteration 0.
      A removed member holding the old chain cannot derive forward. Can they
      still **replay** a pre-rotation message they captured? (Yes at the
      sender-key layer — is `markSeen` the only thing stopping it?)
- [ ] `removeGroupMember`: updates the local roster, rotates, re-invites the
      remaining members. The removed member is told nothing. In-flight messages
      during rotation — lost, or delivered under the old key?
- [ ] `sendGroupMessage`: member list from the local `groups` map; fans out one
      sealed envelope per member. Group message `id` is `grp_msg_<uuid>:<member>`
      — distinct per recipient, so `markSeen` doesn't false-positive. Confirm.
- [ ] `aegis_groups_<user>` blob goes through `secureStore` (encrypted at rest).

---

## C. At-rest storage (`secureStore.ts`, `vault.ts`)

- [ ] `secureStore` key = `HKDF(argon2id_output, salt, "aegis-storage-key-v1")`.
      AAD on each value = the localStorage key name. Nonce per write.
- [ ] Values written **before** first unlock are stored in cleartext, then
      migrated on unlock (`migratePlaintext`). Window of exposure — is anything
      sensitive written before unlock in practice? (Session engine is gated on
      unlock in `App.tsx` — verify that gate holds on every path incl. profile
      switch, reload, onboarding.)
- [ ] `vault.ts`: Argon2id params (64 MiB / 3 / 4). `verifyPassword` **fails
      closed** if config missing/unparseable. Constant-time hash compare.
      Duress check is constant-time and happens before the real check.
- [ ] Legacy migration: old unsalted-SHA-256 record → verify with legacy scheme
      → re-derive with Argon2id + salt → move mnemonic to encrypted store →
      convert `duressCode` to `duressHash`. Any way to get stuck half-migrated?
- [ ] `emergencyShred`: overwrites then removes `aegis_*`, clears
      `sessionStorage`, deletes IndexedDB, drops the storage key. Known-weak on
      the web (documented). Does React state still hold decrypted messages until
      reload? (`handlePanicShred` clears state — confirm every entry point.)
- [ ] `lock()` on: manual lock button, auto-lock timer, duress, panic. Confirm
      the storage key is dropped on **all** of them.
- [ ] `isLocked()` now also returns true when `secureStore` is not unlocked —
      confirm a returning user is always forced through the lock screen.

---

## D. Relay (`server/src/`)

- [ ] `routeSealedEnvelope`: routes only by `recipientBlindToken`; audit entry
      contains no sender/recipient. `activeSealedClients` / `offlineSealedQueues`
      keyed by token; both bounded (`MAX_QUEUE_PER_RECIPIENT`).
- [ ] `AUTH` carries `username` **and** `blindToken` — username is now only used
      for `/api/users` and the inert legacy `GROUP_ENVELOPE`/`ENVELOPE` paths.
      Should it be removed from `AUTH` entirely so a passive relay can't map
      connection ↔ username?
- [ ] `/api/groups/*` endpoints and `relay.createGroup`/`getGroup`/… were
      **removed** (groups are client-side). Confirm nothing reachable recreates
      server-side group state; `routeGroupEnvelope` is inert (empty `groups`).
- [ ] Unauthenticated endpoints: `/api/audit`, `/api/users`,
      `/api/keys/register` (**overwrites** any existing bundle!). Rate limiting:
      none. DoS surface.
- [ ] Resource caps: `offlineQueues`, `offlineSealedQueues`, `attachments`
      (+ TTL sweep), `auditLogs` — every one bounded? `express.json` 256 KB,
      upload 25 MB, WS `maxPayload` 2 MB.
- [ ] `KeyDirectory.getKeyBundle` pops a one-time prekey per fetch — an attacker
      can drain a victim's OPK pool with repeated GETs. Impact?
- [ ] `acknowledgeDelivery` only logs — it does **not** remove from the offline
      queue (queue is flushed wholesale on reconnect). Messages persist in relay
      RAM until the recipient connects, and are re-delivered (no dedup server
      side; client `markSeen` handles it). Acceptable?
- [ ] CORS allowlist via `AEGIS_ALLOWED_ORIGINS`; no `Origin` ⇒ allowed
      (non-browser callers). Fine?

---

## E. Rust `core-crypto/`

- [ ] It is **not** on the live path. Confirm nothing in `client/src-tauri`
      routes real messaging through it (only `generate_identity`,
      `restore_identity`, `compute_safety_number`, `emergency_wipe_database`).
- [ ] `identity.rs`: `generate_signed_prekey` / `generate_one_time_prekeys`
      return only public bundles and drop the secrets — the Rust vault has no
      prekey-secret persistence. So `restore_identity` yields a bundle whose
      SPK/OPK secrets are gone. Document / fix before wiring in.
- [ ] `double_ratchet.rs`: same commit-after-verify + MAX_SKIP as TS. Review the
      `let _ = c;` drained-old-chain discard.
- [ ] `storage.rs`: header AAD covers magic+salt but **not** the nonce. Argon2id
      params. `emergency_wipe` single-pass overwrite (doc claims "3-pass DoD").
- [ ] `sealed_sender.rs`: `sealed_transport_key` matches TS (vector). The older
      `seal_message`/`unseal_message` use a *pre-shared* transport key — a
      different construction from the TS wire format. Intentional gap.
- [ ] `mesh_discovery.rs`: broadcasts plaintext username over UDP; no crypto;
      receive side unimplemented. Not wired in.
- [ ] Run `cargo +nightly fuzz run <target>` for each target in `fuzz/` for a
      meaningful duration.

---

## F. Build / supply chain / deployment

- [ ] `package-lock.json` / `Cargo.lock` committed and pinned. `npm audit` /
      `cargo audit` clean (CI).
- [ ] `@noble/*` and `@scure/*` versions — confirm against upstream releases and
      that the installed tarballs match.
- [ ] Tauri CSP (`tauri.conf.json`) — `script-src 'self'`, scoped `connect-src`.
      Does `connect-src` need widening for a real deployment relay URL? (It's
      currently localhost-scoped.)
- [ ] Client is a static bundle — how is it delivered, and is that channel
      trusted? Subresource integrity? Reproducible build?
- [ ] Relay deployment: TLS config, hosting jurisdiction, log retention, what
      happens on subpoena (the design assumes the operator is untrusted — verify
      nothing leaks that would change that).

---

## G. Human factors

- [ ] Will users actually perform safety-number verification? The UI blocks the
      first message until they do — is the flow clear enough that they don't
      just click through?
- [ ] Key-change warning: is it alarming enough, and does "re-verify" actually
      require out-of-band action or can it be dismissed?
- [ ] Duress phrase: discoverable in the UI? Distinguishable from the real
      passphrase under observation? Is the shred fast and complete enough to be
      useful under the coercion scenario it's designed for?
- [ ] Seed-phrase backup UX and the consequence of loss (no recovery).
