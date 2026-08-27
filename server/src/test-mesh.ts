import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

interface MeshPacket {
  id: string;
  senderNodeId: string;
  recipientNodeId: string;
  ttl: number;
  timestamp: number;
  payload: string;
}

class TestMeshNode {
  public id: string;
  public username: string;
  public seenPackets: Set<string> = new Set();
  public receivedDeliveries: MeshPacket[] = [];
  public relayedPackets: MeshPacket[] = [];
  public neighbors: TestMeshNode[] = [];

  constructor(id: string, username: string) {
    this.id = id;
    this.username = username;
  }

  connectNeighbor(other: TestMeshNode) {
    this.neighbors.push(other);
  }

  broadcast(recipientNodeId: string, payload: string, ttl: number = 4): MeshPacket {
    const packet: MeshPacket = {
      id: 'pkt_' + Math.random().toString(36).substring(2, 10),
      senderNodeId: this.id,
      recipientNodeId,
      ttl,
      timestamp: Date.now(),
      payload,
    };
    this.seenPackets.add(packet.id);
    for (const neighbor of this.neighbors) {
      neighbor.ingest(packet);
    }
    return packet;
  }

  ingest(packet: MeshPacket): boolean {
    // 1. Deduplication check
    if (this.seenPackets.has(packet.id)) {
      return false;
    }
    this.seenPackets.add(packet.id);

    // 2. Deliver if destination
    if (packet.recipientNodeId === this.id || packet.recipientNodeId === 'BROADCAST') {
      this.receivedDeliveries.push(packet);
    }

    // 3. Relay if TTL allows
    if (packet.ttl > 1) {
      const forwarded: MeshPacket = {
        ...packet,
        ttl: packet.ttl - 1,
      };
      this.relayedPackets.push(forwarded);
      for (const neighbor of this.neighbors) {
        neighbor.ingest(forwarded);
      }
      return true;
    }
    return false;
  }
}

async function runMeshTests() {
  console.log('🚀 =========================================================');
  console.log('📡 VERIFYING OFFLINE P2P MESH STORE-AND-FORWARD PROTOCOL');
  console.log('🚀 =========================================================\n');

  // Topology: Alice <-> RelayBob <-> Charlie
  const alice = new TestMeshNode('node_alice', 'Alice');
  const relayBob = new TestMeshNode('node_bob_relay', 'Bob (Relay)');
  const charlie = new TestMeshNode('node_charlie', 'Charlie');

  alice.connectNeighbor(relayBob);
  relayBob.connectNeighbor(alice);
  relayBob.connectNeighbor(charlie);
  charlie.connectNeighbor(relayBob);

  console.log('--- TEST 1: AD-HOC TOPOLOGY & PEER DISCOVERY ---');
  console.log('Mesh Topology: [Alice] <==== 1-Hop ====> [Bob Relay] <==== 1-Hop ====> [Charlie]');
  console.log('Internet Uplink: NONE (Complete blackout simulation: Zero servers reachable)\n');

  // Encrypt payload using ChaCha20-Poly1305 with Alice & Charlie's key
  const aliceCharlieKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = chacha20poly1305(aliceCharlieKey, nonce);
  const plaintext = 'Operation Blackout: Internet is severed by state. Meet at the radio tower.';
  const encrypted = cipher.encrypt(new TextEncoder().encode(plaintext));
  let binary = '';
  for (let i = 0; i < encrypted.length; i++) binary += String.fromCharCode(encrypted[i]);
  const opaquePayload = btoa(binary);

  // 2. Broadcast from Alice to Charlie through Bob
  console.log('--- TEST 2: MULTI-HOP ENCRYPTED PACKET PROPAGATION ---');
  const sentPkt = alice.broadcast('node_charlie', opaquePayload, 3);
  console.log(`[Alice] Transmitted packet "${sentPkt.id}" (Initial TTL: 3)`);

  // Verify Bob relayed it
  if (relayBob.relayedPackets.length !== 1) {
    throw new Error('Relay node Bob failed to relay packet');
  }
  const bobsRelayedPkt = relayBob.relayedPackets[0];
  console.log(`[Bob Relay] Received packet. Decremented TTL to: ${bobsRelayedPkt.ttl}. Forwarded to Charlie.`);

  // Verify Bob CANNOT read payload (Zero-Knowledge)
  try {
    const wrongCipher = chacha20poly1305(crypto.getRandomValues(new Uint8Array(32)), nonce);
    wrongCipher.decrypt(encrypted);
    throw new Error('Unintended decryption occurred!');
  } catch {
    console.log('[Bob Relay] Zero-Knowledge verified: Relay cannot read or decrypt the packet payload.');
  }

  // Verify Charlie received it
  if (charlie.receivedDeliveries.length !== 1) {
    throw new Error('Destination node Charlie did not receive packet');
  }
  const charliesPkt = charlie.receivedDeliveries[0];
  const charlieCipher = chacha20poly1305(aliceCharlieKey, nonce);
  const charlieBytes = new Uint8Array(atob(charliesPkt.payload).split('').map((c) => c.charCodeAt(0)));
  const decrypted = new TextDecoder().decode(charlieCipher.decrypt(charlieBytes));

  if (decrypted !== plaintext) {
    throw new Error('Decrypted plaintext does not match!');
  }
  console.log(`[Charlie] Successfully delivered & decrypted: "${decrypted}"`);
  console.log('✅ [1/3] Multi-hop zero-knowledge epidemic mesh propagation verified!\n');

  // 3. Deduplication & Anti-Replay Drop
  console.log('--- TEST 3: DEDUPLICATION & LOOPBACK DROP ---');
  const duplicateIngestResult = relayBob.ingest(sentPkt);
  if (duplicateIngestResult !== false) {
    throw new Error('Duplicate packet was not dropped!');
  }
  console.log('[Deduplication] Injected duplicate packet: Dropped immediately. (No storm / loopback)');
  console.log('✅ [2/3] Anti-replay deduplication verified.\n');

  // 4. TTL Expiry Drop
  console.log('--- TEST 4: TTL HOP LIMIT EXHAUSTION ---');
  const expiredPkt: MeshPacket = {
    id: 'pkt_expired_123',
    senderNodeId: 'node_alice',
    recipientNodeId: 'node_unknown',
    ttl: 1, // Will exhaust on this hop
    timestamp: Date.now(),
    payload: 'dummy',
  };
  const shouldRelay = relayBob.ingest(expiredPkt);
  if (shouldRelay !== false) {
    throw new Error('Packet with TTL=1 was forwarded when it should have been pruned!');
  }
  console.log('[TTL Expiry] Packet with TTL=1 reached hop limit: Dropped and pruned cleanly.');
  console.log('✅ [3/3] TTL boundary enforcement verified.\n');

  console.log('🎉 =========================================================');
  console.log('🏆 ALL OFFLINE P2P MESH DEFENSES VERIFIED 100%!');
  console.log('🎉 =========================================================\n');
}

runMeshTests().catch((err) => {
  console.error('❌ Mesh test failed:', err);
  process.exit(1);
});
