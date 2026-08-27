import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import crypto from 'node:crypto';

function randomBytes(n: number): Uint8Array {
  return new Uint8Array(crypto.randomBytes(n));
}

const SERVER_URL = 'http://localhost:4000';

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

async function runAttachmentTest() {
  console.log('🧪 ========================================================');
  console.log('🔒 VERIFYING END-TO-END ENCRYPTED ATTACHMENTS & VOICE NOTES');
  console.log('🧪 ========================================================\n');

  // 1. Simulated file / voice note plaintext
  const originalPlaintext = 'TOP-SECRET-AUDIO: Confirmed rendezvous coordinates at safehouse Alpha.';
  const rawBytes = new TextEncoder().encode(originalPlaintext);

  console.log(`[Alice] Original Media Plaintext (${rawBytes.length} bytes): "${originalPlaintext}"`);

  // 2. Client-side ChaCha20-Poly1305 encryption
  const mediaKey = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = chacha20poly1305(mediaKey, nonce);
  const ciphertext = cipher.encrypt(rawBytes);

  console.log(`[Alice] Encrypted media into ${ciphertext.length} opaque ciphertext bytes`);
  console.log(`[Alice] Ciphertext preview: ${toBase64(ciphertext.slice(0, 24))}...`);

  // 3. Upload opaque encrypted bytes to blind relay
  const uploadRes = await fetch(`${SERVER_URL}/api/attachments/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: ciphertext as unknown as BodyInit,
  });

  if (!uploadRes.ok) {
    throw new Error(`Upload failed: ${uploadRes.statusText}`);
  }

  const { attachmentId } = await uploadRes.json();
  console.log(`[Relay] Stored encrypted media blob with ID: ${attachmentId}`);

  // 4. Bob fetches the encrypted payload from relay
  console.log(`[Bob] Fetching encrypted media blob from ${SERVER_URL}/api/attachments/${attachmentId}...`);
  const downloadRes = await fetch(`${SERVER_URL}/api/attachments/${attachmentId}`);
  if (!downloadRes.ok) {
    throw new Error(`Download failed: ${downloadRes.statusText}`);
  }

  const downloadedCiphertext = new Uint8Array(await downloadRes.arrayBuffer());

  // 5. Bob decrypts with the media key received through Double Ratchet
  const bobCipher = chacha20poly1305(mediaKey, nonce);
  const decryptedBytes = bobCipher.decrypt(downloadedCiphertext);
  const decryptedText = new TextDecoder().decode(decryptedBytes);

  console.log(`[Bob] Decrypted Media Plaintext: "${decryptedText}"`);

  if (decryptedText !== originalPlaintext) {
    throw new Error('Decrypted media does not match original!');
  }
  console.log('✅ Media encryption & decryption verified 100% identical!\n');

  // 6. Server Audit Check
  console.log('[Audit Check] Inspecting relay audit logs...');
  const auditRes = await fetch(`${SERVER_URL}/api/audit`);
  const { logs } = await auditRes.json();

  const storeLogs = logs.filter((l: any) => l.type === 'STORE_ENCRYPTED_ATTACHMENT');
  const fetchLogs = logs.filter((l: any) => l.type === 'FETCH_ENCRYPTED_ATTACHMENT');

  console.log(`[Audit Check] Found ${storeLogs.length} attachment storage audit logs.`);
  console.log(`[Audit Check] Found ${fetchLogs.length} attachment fetch audit logs.`);

  const auditString = JSON.stringify(logs);
  if (auditString.includes('TOP-SECRET-AUDIO') || auditString.includes('rendezvous coordinates')) {
    throw new Error('SECURITY VIOLATION: Plaintext leaked to server audit logs!');
  }

  console.log('✅ Server Audit Logs confirmed ZERO plaintext media leakage!');
  console.log('\n🎉 ALL ATTACHMENT & VOICE NOTE SECURITY VERIFICATIONS PASSED!\n');
}

runAttachmentTest().catch((err) => {
  console.error('❌ Attachment test failed:', err);
  process.exit(1);
});
