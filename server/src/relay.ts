import { randomUUID } from 'crypto';
import { WebSocket } from 'ws';
import {
  EncryptedEnvelope,
  ServerAuditLog,
  GroupMetadata,
  GroupEnvelope,
  SealedEnvelope,
} from './types.js';

// Resource ceilings. The relay holds everything in RAM, so every collection
// needs a bound or a hostile client can exhaust memory.
const MAX_QUEUE_PER_RECIPIENT = 500;   // offline envelopes retained per user
const MAX_ATTACHMENTS = 2000;          // total stored blobs
const ATTACHMENT_TTL_MS = 24 * 60 * 60 * 1000; // blobs expire after 24h
const MAX_GROUPS = 5000;

export class BlindRelay {
  private activeClients = new Map<string, WebSocket>();
  private offlineQueues = new Map<string, EncryptedEnvelope[]>();
  private offlineGroupQueues = new Map<string, GroupEnvelope[]>();
  // Sealed-sender routing: keyed by blind delivery token, never by username.
  private sealedClients = new Map<string, WebSocket>();
  private offlineSealedQueues = new Map<string, SealedEnvelope[]>();
  private attachments = new Map<string, { data: Buffer; contentType: string; createdAt: number }>();
  private groups = new Map<string, GroupMetadata>();
  private auditLogs: ServerAuditLog[] = [];
  private auditListeners = new Set<WebSocket>();

  constructor() {
    // Periodically evict expired attachments.
    setInterval(() => this.sweepAttachments(), 60 * 60 * 1000).unref?.();
  }

  private sweepAttachments() {
    const now = Date.now();
    for (const [id, att] of this.attachments.entries()) {
      if (now - att.createdAt > ATTACHMENT_TTL_MS) this.attachments.delete(id);
    }
  }

  storeAttachment(data: Buffer, contentType: string = 'application/octet-stream'): string {
    this.sweepAttachments();
    if (this.attachments.size >= MAX_ATTACHMENTS) {
      // Drop the oldest to make room.
      const oldest = this.attachments.keys().next().value;
      if (oldest !== undefined) this.attachments.delete(oldest);
    }
    const id = 'att_' + randomUUID();
    this.attachments.set(id, { data, contentType, createdAt: Date.now() });

    this.addAuditLog({
      id: randomUUID(),
      timestamp: Date.now(),
      type: 'STORE_ENCRYPTED_ATTACHMENT',
      details: `Stored opaque encrypted media blob (${data.length} bytes, ID: ${id.slice(0, 12)}...). Zero plaintext knowledge.`,
    });

    return id;
  }

  getAttachment(id: string): { data: Buffer; contentType: string } | undefined {
    const att = this.attachments.get(id);
    if (att) {
      this.addAuditLog({
        id: randomUUID(),
        timestamp: Date.now(),
        type: 'FETCH_ENCRYPTED_ATTACHMENT',
        details: `Opaque encrypted media ${id.slice(0, 12)}... fetched by authorized recipient.`,
      });
    }
    return att;
  }

  registerClient(username: string, ws: WebSocket, blindToken?: string) {
    const key = username.toLowerCase();
    this.activeClients.set(key, ws);
    console.log(`[Relay] Client connected: ${username}`);

    this.addAuditLog({
      id: randomUUID(),
      timestamp: Date.now(),
      type: 'KEY_REGISTER',
      details: `A client connected to the relay`,
    });

    // Register sealed-sender routing and flush any queued sealed envelopes.
    if (blindToken) {
      this.sealedClients.set(blindToken, ws);
      const sealedQueue = this.offlineSealedQueues.get(blindToken);
      if (sealedQueue && sealedQueue.length > 0) {
        for (const env of sealedQueue) {
          ws.send(JSON.stringify({ type: 'SEALED_ENVELOPE', payload: env }));
        }
        this.offlineSealedQueues.delete(blindToken);
      }
    }

    // Deliver any queued envelopes for this recipient
    const queue = this.offlineQueues.get(key);
    if (queue && queue.length > 0) {
      console.log(`[Relay] Delivering ${queue.length} queued messages to ${username}`);
      for (const envelope of queue) {
        ws.send(JSON.stringify({ type: 'ENVELOPE', payload: envelope }));
      }
      this.offlineQueues.delete(key);
    }

    // Deliver any queued group envelopes for this recipient
    const groupQueue = this.offlineGroupQueues.get(key);
    if (groupQueue && groupQueue.length > 0) {
      console.log(`[Relay] Delivering ${groupQueue.length} queued group messages to ${username}`);
      for (const groupEnvelope of groupQueue) {
        ws.send(JSON.stringify({ type: 'GROUP_ENVELOPE', payload: groupEnvelope }));
      }
      this.offlineGroupQueues.delete(key);
    }
  }

  unregisterClient(ws: WebSocket) {
    for (const [token, clientWs] of this.sealedClients.entries()) {
      if (clientWs === ws) this.sealedClients.delete(token);
    }
    for (const [username, clientWs] of this.activeClients.entries()) {
      if (clientWs === ws) {
        this.activeClients.delete(username);
        console.log(`[Relay] Client disconnected: ${username}`);
        break;
      }
    }
    this.auditListeners.delete(ws);
  }

  registerAuditSubscriber(ws: WebSocket) {
    this.auditListeners.add(ws);
    // Send recent history
    ws.send(JSON.stringify({
      type: 'AUDIT_LOG_BATCH',
      payload: this.auditLogs.slice(-20)
    }));
  }

  /**
   * Routes a sealed-sender envelope purely by its blind delivery token. The
   * relay has no way to know who sent it or (as an identity) who receives it.
   */
  routeSealedEnvelope(envelope: SealedEnvelope): { delivered: boolean; queued: boolean } {
    const token = envelope.recipientBlindToken;
    if (typeof token !== 'string' || token.length < 16 || token.length > 128) {
      return { delivered: false, queued: false };
    }

    this.addAuditLog({
      id: envelope.id || randomUUID(),
      timestamp: Date.now(),
      type: 'ENVELOPE_RELAYED',
      details: `Sealed envelope routed (blind token ${token.slice(0, 10)}...). Sender unknown to relay.`,
      ciphertextSample: (envelope.ciphertext || '').slice(0, 32) + '...',
    });

    const targetWs = this.sealedClients.get(token);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(JSON.stringify({ type: 'SEALED_ENVELOPE', payload: envelope }));
      return { delivered: true, queued: false };
    }

    const queue = this.offlineSealedQueues.get(token) || [];
    queue.push(envelope);
    while (queue.length > MAX_QUEUE_PER_RECIPIENT) queue.shift();
    this.offlineSealedQueues.set(token, queue);
    return { delivered: false, queued: true };
  }

  routeEnvelope(envelope: EncryptedEnvelope): { delivered: boolean; queued: boolean } {
    const recipientKey = envelope.recipient.toLowerCase();
    const targetWs = this.activeClients.get(recipientKey);

    const ciphertextPreview = envelope.ciphertext.length > 32 
      ? envelope.ciphertext.slice(0, 32) + '...' 
      : envelope.ciphertext;

    this.addAuditLog({
      id: envelope.id,
      timestamp: Date.now(),
      type: 'ENVELOPE_RELAYED',
      details: `Routed envelope from ${envelope.sender} -> ${envelope.recipient} (Ratchet key: ${envelope.ratchetKey.slice(0, 10)}...)`,
      ciphertextSample: ciphertextPreview
    });

    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(JSON.stringify({
        type: 'ENVELOPE',
        payload: envelope
      }));
      return { delivered: true, queued: false };
    } else {
      // Queue for offline delivery (bounded — drop oldest past the ceiling)
      const queue = this.offlineQueues.get(recipientKey) || [];
      queue.push(envelope);
      while (queue.length > MAX_QUEUE_PER_RECIPIENT) queue.shift();
      this.offlineQueues.set(recipientKey, queue);
      console.log(`[Relay] Recipient ${envelope.recipient} offline. Queued message.`);
      return { delivered: false, queued: true };
    }
  }

  acknowledgeDelivery(envelopeId: string) {
    this.addAuditLog({
      id: randomUUID(),
      timestamp: Date.now(),
      type: 'ACK_DELIVERED',
      details: `Delivery of ${envelopeId} confirmed by recipient.`,
    });
  }

  createGroup(id: string, name: string, creator: string, members: string[]): GroupMetadata {
    if (this.groups.size >= MAX_GROUPS && !this.groups.has(id)) {
      throw new Error('Relay group capacity reached');
    }
    const uniqueMembers = Array.from(new Set([creator, ...members]));
    const metadata: GroupMetadata = {
      id,
      name,
      creator,
      members: uniqueMembers,
      createdAt: Date.now(),
    };
    this.groups.set(id, metadata);

    this.addAuditLog({
      id: randomUUID(),
      timestamp: Date.now(),
      type: 'GROUP_CREATED',
      details: `Group "${name}" (${id}) created by ${creator} with ${uniqueMembers.length} members.`,
    });

    return metadata;
  }

  getGroupsForUser(username: string): GroupMetadata[] {
    const key = username.toLowerCase();
    const userGroups: GroupMetadata[] = [];
    for (const group of this.groups.values()) {
      if (group.members.some((m) => m.toLowerCase() === key)) {
        userGroups.push(group);
      }
    }
    return userGroups;
  }

  getGroup(id: string): GroupMetadata | undefined {
    return this.groups.get(id);
  }

  removeGroupMember(id: string, member: string): GroupMetadata | undefined {
    const group = this.groups.get(id);
    if (!group) return undefined;
    group.members = group.members.filter(
      (m) => m.toLowerCase() !== member.toLowerCase()
    );
    this.addAuditLog({
      id: randomUUID(),
      timestamp: Date.now(),
      type: 'GROUP_MEMBER_CHANGED',
      details: `Group ${group.name} (${id}) membership changed (${group.members.length} members).`,
    });
    return group;
  }

  routeGroupEnvelope(envelope: GroupEnvelope): { deliveredCount: number; queuedCount: number } {
    const group = this.groups.get(envelope.groupId);
    if (!group) {
      return { deliveredCount: 0, queuedCount: 0 };
    }

    let deliveredCount = 0;
    let queuedCount = 0;
    const senderKey = envelope.sender.toLowerCase();

    for (const member of group.members) {
      const memberKey = member.toLowerCase();
      if (memberKey === senderKey) continue;

      const targetWs = this.activeClients.get(memberKey);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
          type: 'GROUP_ENVELOPE',
          payload: envelope,
        }));
        deliveredCount++;
      } else {
        const queue = this.offlineGroupQueues.get(memberKey) || [];
        queue.push(envelope);
        while (queue.length > MAX_QUEUE_PER_RECIPIENT) queue.shift();
        this.offlineGroupQueues.set(memberKey, queue);
        queuedCount++;
      }
    }

    this.addAuditLog({
      id: envelope.id,
      timestamp: Date.now(),
      type: 'GROUP_MESSAGE_RELAYED',
      details: `Group ${group.name} (${envelope.groupId}) message from ${envelope.sender} relayed (Delivered: ${deliveredCount}, Queued: ${queuedCount}).`,
      ciphertextSample: envelope.ciphertext.slice(0, 32) + '...',
    });

    return { deliveredCount, queuedCount };
  }

  getAuditLogs(): ServerAuditLog[] {
    return this.auditLogs;
  }

  private addAuditLog(log: ServerAuditLog) {
    this.auditLogs.push(log);
    if (this.auditLogs.length > 200) {
      this.auditLogs.shift();
    }

    const payload = JSON.stringify({ type: 'AUDIT_LOG', payload: log });
    for (const ws of this.auditListeners) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      }
    }
  }
}
