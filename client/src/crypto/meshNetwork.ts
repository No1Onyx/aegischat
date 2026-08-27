export interface MeshPacket {
  id: string;
  senderNodeId: string;
  recipientNodeId: string; // Specific node ID or 'BROADCAST'
  ttl: number;             // Time To Live (hop count)
  timestamp: number;
  payload: string;         // Opaque ciphertext
}

export interface DiscoveredPeer {
  id: string;
  username: string;
  address: string;
  lastSeen: number;
  hopCount: number;
}

export type MeshPacketHandler = (packet: MeshPacket) => void;
export type PeerDiscoveryHandler = (peers: DiscoveredPeer[]) => void;

export class MeshNetwork {
  public nodeId: string;
  public username: string;
  private isEnabled: boolean = false;
  private peers: Map<string, DiscoveredPeer> = new Map();
  private seenPacketIds: Set<string> = new Set();
  private packetHandlers: Set<MeshPacketHandler> = new Set();
  private peerHandlers: Set<PeerDiscoveryHandler> = new Set();
  private relayedPacketCount: number = 0;

  constructor(nodeId: string, username: string) {
    this.nodeId = nodeId;
    this.username = username;
  }

  public setEnabled(enabled: boolean) {
    this.isEnabled = enabled;
    if (!enabled) {
      this.peers.clear();
      this.notifyPeerHandlers();
    }
  }

  public getIsEnabled(): boolean {
    return this.isEnabled;
  }

  public getDiscoveredPeers(): DiscoveredPeer[] {
    return Array.from(this.peers.values());
  }

  public getRelayedCount(): number {
    return this.relayedPacketCount;
  }

  public onPacket(handler: MeshPacketHandler) {
    this.packetHandlers.add(handler);
    return () => this.packetHandlers.delete(handler);
  }

  public onPeersChanged(handler: PeerDiscoveryHandler) {
    this.peerHandlers.add(handler);
    handler(this.getDiscoveredPeers());
    return () => this.peerHandlers.delete(handler);
  }

  private notifyPeerHandlers() {
    const peerList = this.getDiscoveredPeers();
    this.peerHandlers.forEach((h) => h(peerList));
  }

  /**
   * Register a discovered peer on the local ad-hoc network
   */
  public addOrUpdatePeer(peer: DiscoveredPeer) {
    if (peer.id === this.nodeId) return;
    this.peers.set(peer.id, { ...peer, lastSeen: Date.now() });
    this.notifyPeerHandlers();
  }

  /**
   * Broadcast an encrypted packet across the local mesh
   */
  public broadcastMessage(recipientNodeId: string, ciphertext: string, maxHops: number = 4): MeshPacket {
    const packet: MeshPacket = {
      id: 'mesh_pkt_' + Math.random().toString(36).substring(2, 12),
      senderNodeId: this.nodeId,
      recipientNodeId,
      ttl: maxHops,
      timestamp: Date.now(),
      payload: ciphertext,
    };

    // Mark as seen to prevent loopback
    this.seenPacketIds.add(packet.id);

    // In a real local subnet, transmits to broadcast socket / WebRTC DataChannels
    this.simulateMeshHop(packet);
    return packet;
  }

  /**
   * Ingest and route a packet received from an ad-hoc neighbor
   */
  public handleIncomingPacket(packet: MeshPacket): boolean {
    if (!this.isEnabled) return false;

    // Deduplication check: drop packets we have already seen or relayed
    if (this.seenPacketIds.has(packet.id)) {
      return false;
    }
    this.seenPacketIds.add(packet.id);

    // If destination is this node or BROADCAST, deliver to local app
    if (packet.recipientNodeId === this.nodeId || packet.recipientNodeId === 'BROADCAST') {
      this.packetHandlers.forEach((h) => h(packet));
    }

    // Epidemic mesh relay: if TTL remains, forward to neighbors
    if (packet.ttl > 1) {
      const forwardedPacket: MeshPacket = {
        ...packet,
        ttl: packet.ttl - 1,
      };
      this.relayedPacketCount++;
      this.simulateMeshHop(forwardedPacket);
      return true;
    }

    return false;
  }

  private simulateMeshHop(packet: MeshPacket) {
    // Emits packet onto the local broadcast bus / WebRTC channel
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('aegis_mesh_broadcast', { detail: packet }));
    }
  }

  /**
   * Prune peers inactive for more than 45 seconds
   */
  public pruneStalePeers() {
    const now = Date.now();
    let changed = false;
    for (const [id, peer] of this.peers.entries()) {
      if (now - peer.lastSeen > 45000) {
        this.peers.delete(id);
        changed = true;
      }
    }
    if (changed) this.notifyPeerHandlers();
  }
}
