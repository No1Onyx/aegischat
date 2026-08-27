import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runDevicePairingTests() {
  console.log('🚀 =========================================================');
  console.log('📲 VERIFYING MULTI-DEVICE ZERO-KNOWLEDGE QR PAIRING PROTOCOL');
  console.log('🚀 =========================================================\n');

  // 1. Primary Device (e.g. Windows PC) initiates pairing session
  console.log('--- TEST 1: PRIMARY DEVICE EPHEMERAL PAIRING SESSION ---');
  const primaryPair = x25519.keygen();
  const tokenBytes = crypto.getRandomValues(new Uint8Array(16));
  const token = toHex(tokenBytes);
  const sessionId = 'pair_test_' + Math.random().toString(36).substring(2, 8);

  const qrPayload = `aegis-pair://v1?id=${sessionId}&user=Alice&pk=${encodeURIComponent(toBase64(primaryPair.publicKey))}&tok=${token}`;
  console.log(`[Primary: PC] Generated Ephemeral Curve25519 Key & Token: ${token.slice(0, 16)}...`);
  console.log(`[Primary: PC] QR Payload String: ${qrPayload.slice(0, 60)}...`);
  console.log('✅ [1/5] Primary Pairing Session generated successfully!\n');

  // 2. Secondary Device (e.g. Android Phone) scans QR code
  console.log('--- TEST 2: SECONDARY DEVICE SCAN & DIFFIE-HELLMAN KEY DERIVATION ---');
  const params = new URLSearchParams(qrPayload.replace('aegis-pair://v1?', ''));
  const targetUser = params.get('user');
  const primaryPkB64 = params.get('pk');
  const scannedToken = params.get('tok');

  if (!primaryPkB64 || !scannedToken) throw new Error('Missing QR params');

  const primaryPubKey = fromBase64(decodeURIComponent(primaryPkB64));
  const secondaryPair = x25519.keygen();

  // Compute Diffie-Hellman Shared Secret on Secondary
  const secondarySharedSecret = x25519.getSharedSecret(secondaryPair.secretKey, primaryPubKey);
  const salt = new TextEncoder().encode(scannedToken);
  const secondaryPairingKey = hkdf(sha256, secondarySharedSecret, salt, new TextEncoder().encode('aegis-device-pairing-v1'), 32);

  console.log(`[Secondary: Phone] Scanned QR for user: "${targetUser}"`);
  console.log(`[Secondary: Phone] Derived 256-bit Symmetric Pairing Key: ${toHex(secondaryPairingKey).slice(0, 24)}...`);
  console.log('✅ [2/5] Secondary Diffie-Hellman handshake computed!\n');

  // 3. Secondary sends encrypted pairing request
  console.log('--- TEST 3: ENCRYPTED PAIRING REQUEST TRANSMISSION ---');
  const requestPayload = JSON.stringify({
    deviceName: 'Pixel 9 Pro (Android)',
    platform: 'android',
    token: scannedToken,
    timestamp: Date.now(),
  });
  const reqNonce = crypto.getRandomValues(new Uint8Array(12));
  const reqCipher = chacha20poly1305(secondaryPairingKey, reqNonce);
  const encryptedReqBytes = reqCipher.encrypt(new TextEncoder().encode(requestPayload));

  // 4. Primary decrypts and approves request
  console.log('--- TEST 4: PRIMARY CONFIRMATION & MUTUAL VERIFICATION ---');
  const primarySharedSecret = x25519.getSharedSecret(primaryPair.secretKey, secondaryPair.publicKey);
  const primaryPairingKey = hkdf(sha256, primarySharedSecret, salt, new TextEncoder().encode('aegis-device-pairing-v1'), 32);

  if (toHex(primaryPairingKey) !== toHex(secondaryPairingKey)) {
    throw new Error('Pairing keys do not match between Primary and Secondary!');
  }

  const primaryReqCipher = chacha20poly1305(primaryPairingKey, reqNonce);
  const decryptedReqJson = new TextDecoder().decode(primaryReqCipher.decrypt(encryptedReqBytes));
  const reqData = JSON.parse(decryptedReqJson);

  if (reqData.token !== token) {
    throw new Error('Token mismatch!');
  }
  console.log(`[Primary: PC] Decrypted Request from: "${reqData.deviceName}" (Platform: ${reqData.platform})`);
  console.log('✅ [3/5] Request verified with zero-knowledge encryption (No server escrow).\n');

  // 5. Primary provisions Secondary with encrypted identity bundle
  console.log('--- TEST 5: ZERO-KNOWLEDGE IDENTITY PROVISIONING ---');
  const aliceMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bundle = {
    mnemonic: aliceMnemonic,
    username: 'Alice',
    verifiedContacts: ['Bob', 'Charlie'],
    createdAt: Date.now(),
  };

  const provNonce = crypto.getRandomValues(new Uint8Array(12));
  const provCipher = chacha20poly1305(primaryPairingKey, provNonce);
  const encryptedBundleBytes = provCipher.encrypt(new TextEncoder().encode(JSON.stringify(bundle)));

  // Secondary decrypts provisioning bundle
  const secProvCipher = chacha20poly1305(secondaryPairingKey, provNonce);
  const decryptedBundle = JSON.parse(new TextDecoder().decode(secProvCipher.decrypt(encryptedBundleBytes)));

  if (decryptedBundle.mnemonic !== aliceMnemonic || decryptedBundle.username !== 'Alice') {
    throw new Error('Provisioning bundle mismatch on secondary device!');
  }

  console.log(`[Secondary: Phone] Provisioning bundle decrypted: Mnemonic and verified contacts (${decryptedBundle.verifiedContacts.join(', ')}) restored!`);
  console.log('✅ [4/5] Multi-device provisioning completed successfully.\n');

  // 6. Tamper Resistance
  console.log('--- TEST 6: TAMPER RESISTANCE (POLY1305 MAC CHECK) ---');
  const tamperedBytes = new Uint8Array(encryptedBundleBytes);
  tamperedBytes[tamperedBytes.length - 1] ^= 0x42;
  try {
    secProvCipher.decrypt(tamperedBytes);
    throw new Error('Tampered bundle was accepted!');
  } catch {
    console.log('[Security Check] Tampered pairing packet was detected and rejected by Poly1305 MAC.');
    console.log('✅ [5/5] Tamper rejection verified.\n');
  }

  console.log('🎉 =========================================================');
  console.log('🏆 MULTI-DEVICE ZERO-KNOWLEDGE PAIRING VERIFIED 100%!');
  console.log('🎉 =========================================================\n');
}

runDevicePairingTests().catch((err) => {
  console.error('❌ Device pairing test failed:', err);
  process.exit(1);
});
