import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './primitives.js';

/**
 * Generates a standard 60-digit verifiable Safety Number (formatted in twelve 5-digit blocks)
 * derived deterministically from the lexicographical ordering of both Identity Keys.
 */
export function generateSafetyNumber(
  userAIdentityPublicKey: Uint8Array,
  userBIdentityPublicKey: Uint8Array
): { formatted: string[]; rawHash: string } {
  const hexA = toHex(userAIdentityPublicKey);
  const hexB = toHex(userBIdentityPublicKey);

  // Sort lexicographically so both Alice and Bob compute the exact same fingerprint
  const [first, second] = hexA < hexB ? [hexA, hexB] : [hexB, hexA];

  const combined = new TextEncoder().encode(`AegisChat_Safety_v1:${first}:${second}`);
  const hash = sha256(combined);

  // Derive 60 digits from the hash (12 blocks of 5 digits)
  const blocks: string[] = [];
  for (let i = 0; i < 12; i++) {
    // Take 2 bytes per block -> number between 0 and 65535, modulo 100,000 padded to 5 digits
    const byte1 = hash[(i * 2) % hash.length];
    const byte2 = hash[(i * 2 + 1) % hash.length];
    const num = ((byte1 << 8) | byte2) % 100000;
    blocks.push(num.toString().padStart(5, '0'));
  }

  return {
    formatted: blocks,
    rawHash: toHex(hash),
  };
}
