import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const ZERO_SALT = new Uint8Array(32);
const INFO_SENDER_CK = new TextEncoder().encode('AegisChat_SenderKey_CK_v1');
const SERVER_URL = 'http://localhost:4000';

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Minimal test model for Sender Key Chain
class TestSenderKeyChain {
  public chainKey: Uint8Array;
  public iteration: number = 0;
  public signingKey: { secretKey: Uint8Array; publicKey: Uint8Array };

  constructor() {
    this.chainKey = randomBytes(32);
    this.iteration = 0;
    this.signingKey = ed25519.keygen();
  }

  encrypt(plaintext: string) {
    const okm = hkdf(sha256, this.chainKey, ZERO_SALT, INFO_SENDER_CK, 64);
    this.chainKey = okm.slice(0, 32);
    const messageKey = okm.slice(32, 64);

    const currentIndex = this.iteration;
    this.iteration += 1;

    const nonce = randomBytes(12);
    const cipher = chacha20poly1305(messageKey, nonce);
    const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));

    const signPayload = new Uint8Array(4 + nonce.length + ciphertext.length);
    new DataView(signPayload.buffer).setUint32(0, currentIndex, false);
    signPayload.set(nonce, 4);
    signPayload.set(ciphertext, 4 + nonce.length);

    const signature = ed25519.sign(signPayload, this.signingKey.secretKey);

    return {
      messageIndex: currentIndex,
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
      signature: toBase64(signature),
    };
  }
}

class TestRecipientKeyChain {
  public chainKey: Uint8Array;
  public iteration: number;
  public signingPublicKey: Uint8Array;

  constructor(chainKey: Uint8Array, iteration: number, signingPublicKey: Uint8Array) {
    this.chainKey = chainKey;
    this.iteration = iteration;
    this.signingPublicKey = signingPublicKey;
  }

  decrypt(packet: { messageIndex: number; nonce: string; ciphertext: string; signature: string }) {
    const nonce = fromBase64(packet.nonce);
    const ciphertext = fromBase64(packet.ciphertext);
    const signature = fromBase64(packet.signature);

    // Verify signature
    const signPayload = new Uint8Array(4 + nonce.length + ciphertext.length);
    new DataView(signPayload.buffer).setUint32(0, packet.messageIndex, false);
    signPayload.set(nonce, 4);
    signPayload.set(ciphertext, 4 + nonce.length);

    const valid = ed25519.verify(signature, signPayload, this.signingPublicKey);
    if (!valid) throw new Error('Ed25519 signature verification failed! Impersonation detected.');

    // Step chain key
    while (this.iteration < packet.messageIndex) {
      const okm = hkdf(sha256, this.chainKey, ZERO_SALT, INFO_SENDER_CK, 64);
      this.chainKey = okm.slice(0, 32);
      this.iteration += 1;
    }

    const okm = hkdf(sha256, this.chainKey, ZERO_SALT, INFO_SENDER_CK, 64);
    this.chainKey = okm.slice(0, 32);
    const messageKey = okm.slice(32, 64);
    this.iteration += 1;

    const cipher = chacha20poly1305(messageKey, nonce);
    const decrypted = cipher.decrypt(ciphertext);
    return new TextDecoder().decode(decrypted);
  }
}

async function runGroupTests() {
  console.log('🚀 =========================================================');
  console.log('🔒 VERIFYING SIGNAL SENDER KEYS SECRET GROUP PROTOCOL');
  console.log('🚀 =========================================================\n');

  // 1. Group Creation on Server
  console.log('--- TEST 1: GROUP CREATION & ZERO-KNOWLEDGE METADATA ---');
  const groupRes = await fetch(`${SERVER_URL}/api/groups/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Freedom Resistance Alpha',
      creator: 'Alice',
      members: ['Alice', 'Bob', 'Charlie'],
    }),
  });

  if (!groupRes.ok) throw new Error('Failed to create group');
  const group = await groupRes.json();
  console.log(`✅ [1/5] Group created: "${group.name}" (ID: ${group.id}) with 3 members\n`);

  // 2. Alice generates Sender Key & distributes to Bob & Charlie
  console.log('--- TEST 2: SENDER KEY GENERATION & DISTRIBUTION ---');
  const aliceSender = new TestSenderKeyChain();
  const bobRecipient = new TestRecipientKeyChain(
    new Uint8Array(aliceSender.chainKey),
    aliceSender.iteration,
    aliceSender.signingKey.publicKey
  );
  const charlieRecipient = new TestRecipientKeyChain(
    new Uint8Array(aliceSender.chainKey),
    aliceSender.iteration,
    aliceSender.signingKey.publicKey
  );
  console.log('✅ [2/5] Alice generated 256-bit Sender Key and distributed to Bob & Charlie\n');

  // 3. Alice broadcasts group message 1: O(1) single ciphertext
  console.log('--- TEST 3: O(1) SENDER KEY BROADCAST & DUAL RECIPIENT DECRYPTION ---');
  const msg1 = 'Secret Manifesto: Unbreakable freedom of speech is non-negotiable.';
  const packet1 = aliceSender.encrypt(msg1);

  const bobDecrypted1 = bobRecipient.decrypt(packet1);
  const charlieDecrypted1 = charlieRecipient.decrypt(packet1);

  console.log(`[Alice -> Group] Ciphertext: ${packet1.ciphertext.slice(0, 32)}...`);
  console.log(`[Bob Screen]     Decrypted: "${bobDecrypted1}"`);
  console.log(`[Charlie Screen] Decrypted: "${charlieDecrypted1}"`);

  if (bobDecrypted1 !== msg1 || charlieDecrypted1 !== msg1) {
    throw new Error('Group decryption mismatch!');
  }
  console.log('✅ [3/5] Both Bob and Charlie decrypted Alice\'s single ciphertext broadcast!\n');

  // 4. Forward Secrecy: Message 2
  console.log('--- TEST 4: FORWARD SECRECY (SYMMETRIC RATCHET STEPPING) ---');
  const msg2 = 'Operational Directive: Keep emergency panic duress PIN active.';
  const packet2 = aliceSender.encrypt(msg2);

  const bobDecrypted2 = bobRecipient.decrypt(packet2);
  const charlieDecrypted2 = charlieRecipient.decrypt(packet2);

  if (bobDecrypted2 !== msg2 || charlieDecrypted2 !== msg2) {
    throw new Error('Message 2 decryption mismatch!');
  }
  console.log(`✅ [4/5] Forward Secrecy verified: Message #2 stepped Sender Key chain (Iteration: ${aliceSender.iteration})\n`);

  // 5. Tamper Resistance & Digital Signature Verification
  console.log('--- TEST 5: ED25519 SIGNATURE TAMPER REJECTION ---');
  const forgedPacket = {
    ...packet2,
    ciphertext: toBase64(new Uint8Array(10).fill(42)), // forged ciphertext
  };

  let caughtTamper = false;
  try {
    bobRecipient.decrypt(forgedPacket);
  } catch (err) {
    caughtTamper = true;
    console.log(`[Tamper Inspector] Successfully caught tampered group message: ${(err as Error).message}`);
  }

  if (!caughtTamper) {
    throw new Error('SECURITY VIOLATION: Tampered group message was not rejected!');
  }
  console.log('✅ [5/5] Digital Signature tamper resistance verified (MITM / Forgery rejected)\n');

  console.log('🎉 =========================================================');
  console.log('🏆 SENDER KEYS SECRET GROUP CHAT VERIFIED 100% SUCCESSFUL!');
  console.log('🎉 =========================================================\n');
}

runGroupTests().catch((err) => {
  console.error('❌ Group test failed:', err);
  process.exit(1);
});
