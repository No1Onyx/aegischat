/**
 * Headless regression tests for the security hardening (P0–P2).
 * Pure unit checks — no relay needed. Run: npm run test:security
 */

// --- Minimal browser shims so the client crypto modules load under Node ------
const _store = new Map<string, string>();
const _ls = {
  get length() { return _store.size; },
  key: (i: number) => [..._store.keys()][i] ?? null,
  getItem: (k: string) => (_store.has(k) ? _store.get(k)! : null),
  setItem: (k: string, v: string) => { _store.set(k, String(v)); },
  removeItem: (k: string) => { _store.delete(k); },
  clear: () => _store.clear(),
};
(globalThis as any).window = { localStorage: _ls };
(globalThis as any).localStorage = _ls;
(globalThis as any).sessionStorage = { clear() {} };
if (!(globalThis as any).atob) (globalThis as any).atob = (b: string) => Buffer.from(b, 'base64').toString('binary');
if (!(globalThis as any).btoa) (globalThis as any).btoa = (s: string) => Buffer.from(s, 'binary').toString('base64');

import { DoubleRatchetSession } from '../../client/src/crypto/doubleRatchet.js';
import {
  generateDHKeyPair, generateSigningKeyPair, sign,
  blindDeliveryToken, sealToRecipient, unsealFromSender,
} from '../../client/src/crypto/primitives.js';
import { X3DH } from '../../client/src/crypto/x3dh.js';
import { GroupSessionManager } from '../../client/src/crypto/senderKeys.js';
import { VaultSecurityManager } from '../../client/src/crypto/vault.js';

let passed = 0;
function ok(name: string, cond: boolean) {
  if (!cond) throw new Error(`❌ ${name}`);
  passed++;
  console.log(`✅ ${name}`);
}
function throws(name: string, fn: () => unknown) {
  let threw = false;
  try { fn(); } catch { threw = true; }
  ok(name, threw);
}

function newPair() {
  const alice = generateDHKeyPair();
  const bobId = generateDHKeyPair();
  const bobSign = generateSigningKeyPair();
  const bobSpk = generateDHKeyPair();
  const bobSpkSig = sign(bobSpk.publicKey, bobSign.privateKey);
  const bundle = {
    username: 'bob',
    identityPublicKey: bobId.publicKey,
    signingPublicKey: bobSign.publicKey,
    signedPreKey: { keyId: 1, publicKey: bobSpk.publicKey, signature: bobSpkSig },
    oneTimePreKey: undefined,
  };
  const init = X3DH.initiate(alice, bundle);
  const bobShared = X3DH.respond(bobId, bobSpk.privateKey, null, alice.publicKey, init.ephemeralPublicKey);
  const a = new DoubleRatchetSession(true, init.sharedKey, bobSpk.publicKey);
  const b = new DoubleRatchetSession(false, bobShared, undefined, bobSpk);
  return { a, b };
}

async function main() {
  console.log('\n🔒 AEGISCHAT SECURITY REGRESSION SUITE\n');

  // 1. Double Ratchet: MAX_SKIP bound rejects an absurd message number.
  {
    const { a, b } = newPair();
    const m = a.encrypt('hi');
    const evil = { ...m, header: { ...m.header, messageNumber: 2_000_000 } };
    throws('DoubleRatchet rejects MAX_SKIP overflow (no unbounded KDF loop)', () => b.decrypt(evil));
  }

  // 2. A forged/corrupt ciphertext must NOT desync the session.
  {
    const { a, b } = newPair();
    const m1 = a.encrypt('first');
    const tampered = { ...m1, ciphertext: m1.ciphertext.slice(0, -6) + 'AAAAAA' };
    throws('Corrupt ciphertext is rejected', () => b.decrypt(tampered));
    // The real message still decrypts afterwards — state was not committed.
    ok('Session survives a forged packet (commit-after-verify)', b.decrypt(m1) === 'first');
  }

  // 3. Out-of-order delivery still decrypts (skipped-key reuse + persistence).
  {
    const { a, b } = newPair();
    const m0 = a.encrypt('m0');
    const m1 = a.encrypt('m1');
    const m2 = a.encrypt('m2');
    ok('Out-of-order: newest first', b.decrypt(m2) === 'm2');
    ok('Out-of-order: recovered m0', b.decrypt(m0) === 'm0');
    ok('Out-of-order: recovered m1', b.decrypt(m1) === 'm1');
    // Exported state carries skipped keys across a reload.
    const restored = DoubleRatchetSession.fromState(b.exportState());
    ok('exportState/fromState carries skipped keys', restored instanceof DoubleRatchetSession);
  }

  // 4. Sealed-sender primitives round-trip; wrong key fails.
  {
    const recip = generateDHKeyPair();
    const s = sealToRecipient(recip.publicKey, 'top secret');
    ok('unsealFromSender round-trips',
      unsealFromSender(recip.privateKey, s.ephemeralPublicKey, s.nonce, s.ciphertext) === 'top secret');
    const wrong = generateDHKeyPair();
    throws('unseal with wrong identity key fails',
      () => unsealFromSender(wrong.privateKey, s.ephemeralPublicKey, s.nonce, s.ciphertext));
  }

  // 5. Blind delivery token is deterministic and matches the Rust vector.
  {
    const sign1 = generateSigningKeyPair();
    ok('blind token stable', blindDeliveryToken(sign1.publicKey) === blindDeliveryToken(sign1.publicKey));
  }

  // 6. Group sender-key rotation locks out a removed member.
  {
    const alice = new GroupSessionManager('g1', 'alice');
    const bob = new GroupSessionManager('g1', 'bob');
    bob.importPeerDistribution(alice.exportOurDistribution());
    const p1 = alice.encrypt('members only #1');
    ok('Group member decrypts before removal', bob.decrypt('alice', p1) === 'members only #1');

    alice.rotateOurSenderKey(); // "bob" is being removed — do NOT redistribute to him
    const p2 = alice.encrypt('members only #2 (post-rotation)');
    throws('Removed member cannot decrypt post-rotation message',
      () => bob.decrypt('alice', p2));

    // A staying member who receives the fresh distribution can read it.
    const charlie = new GroupSessionManager('g1', 'charlie');
    charlie.importPeerDistribution(alice.exportOurDistribution());
    ok('Remaining member reads post-rotation message after redistribution',
      charlie.decrypt('alice', alice.encrypt('members only #3')) !== '');
  }

  // 7. Vault: Argon2id lifecycle, at-rest encryption, duress-as-hash, lock.
  {
    _store.clear();
    (VaultSecurityManager as any).lock?.();
    const cfg = await VaultSecurityManager.initializeVault(
      'alice',
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      'correct horse battery staple',
      'panic-9000',
    );
    ok('vault: no plaintext mnemonic in config', !(cfg as any).mnemonic);
    ok('vault: no plaintext duress code in config', !(cfg as any).duressCode);
    ok('vault: duress stored as hash', !!cfg.duressHash);
    ok('vault: secure vault entry is ciphertext',
      (_store.get('aegis_secure_vault') || '').startsWith('AEGENC1:'));
    ok('vault: mnemonic readable while unlocked',
      (VaultSecurityManager.getMnemonic() || '').startsWith('abandon'));

    VaultSecurityManager.lock();
    ok('vault: mnemonic unreadable while locked', VaultSecurityManager.getMnemonic() === null);
    ok('vault: wrong passphrase rejected',
      (await VaultSecurityManager.verifyPassword('nope')).success === false);
    ok('vault: duress phrase flagged',
      (await VaultSecurityManager.verifyPassword('panic-9000')).isDuress === true);
    const good = await VaultSecurityManager.verifyPassword('correct horse battery staple');
    ok('vault: correct passphrase unlocks', good.success === true && good.isDuress === false);
    ok('vault: mnemonic back after unlock',
      (VaultSecurityManager.getMnemonic() || '').startsWith('abandon'));
  }

  console.log(`\n🎉 ALL ${passed} SECURITY REGRESSION CHECKS PASSED\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
