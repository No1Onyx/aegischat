import {
  generateDHKeyPair,
  sign,
  verify,
  toBase64,
  fromBase64,
  deriveIdentityFromMnemonic,
  blindDeliveryToken,
  sealToRecipient,
  unsealFromSender,
} from './primitives.js';
import type { DHKeyPair, SigningKeyPair } from './primitives.js';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { secureStore } from './secureStore.js';

/**
 * Deterministic BIP-39 phrase for demo profiles that have no onboarded vault.
 * Keeps the Alice/Bob/Charlie demo reproducible across reloads and machines
 * without ever generating a random, unrecoverable identity.
 */
function demoMnemonicForUsername(username: string): string {
  const entropy = sha256(
    new TextEncoder().encode(`aegis-demo-identity:${username.toLowerCase()}`)
  ).slice(0, 16);
  return entropyToMnemonic(entropy, wordlist);
}
import { X3DH } from './x3dh.js';
import type { PreKeyBundle } from './x3dh.js';
import { DoubleRatchetSession } from './doubleRatchet.js';
import type { EncryptedMessagePayload, RatchetStateSummary, DoubleRatchetStateExport } from './doubleRatchet.js';
import { generateSafetyNumber } from './safetyNumber.js';
import type { EncryptedAttachmentDescriptor } from './attachments.js';
import { GroupSessionManager } from './senderKeys.js';
import type { CallSignal } from './webrtcManager.js';
import { TransportManager } from './transport.js';
import { RELAY_URL } from '../config.js';

export interface WireEnvelope {
  id: string;
  sender: string;
  recipient: string;
  timestamp: number;
  senderIdentityKey?: string; // Included on session initialization
  senderSigningKey?: string;  // Included via sealed sender
  ephemeralKey?: string;     // Included on session initialization (X3DH)
  oneTimeKeyIdUsed?: number;
  ratchetKey: string;
  messageNumber: number;
  previousChainLength: number;
  nonce: string;
  ciphertext: string;
}

/** Outer envelope the relay sees: routing token + opaque ciphertext only. */
export interface SealedEnvelope {
  id: string;
  recipientBlindToken: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  timestamp: number;
}

/** Inner payload, readable only by the recipient. */
interface SealedInner {
  kind?: 'direct' | 'group'; // absent => 'direct'
  sender: string;
  senderIdentityKey: string;
  senderSigningKey: string;

  // --- direct (X3DH + Double Ratchet) ---
  ephemeralKey?: string;
  oneTimeKeyIdUsed?: number;
  ratchetKey?: string;
  messageNumber?: number;
  previousChainLength?: number;

  // --- group (Sender Keys) ---
  groupId?: string;
  groupMessageIndex?: number;
  groupSignature?: string;   // sender-key Ed25519 signature over index+nonce+ciphertext

  // --- shared ---
  nonce: string;
  ciphertext: string;
  timestamp: number;
  signature: string; // Ed25519 over the JSON of this object with signature:""
}

export interface ChatMessage {
  id: string;
  sender: string;
  recipient: string;
  groupId?: string;
  groupName?: string;
  text: string;
  timestamp: number;
  expiresAt?: number;
  attachment?: EncryptedAttachmentDescriptor;
  isSelf: boolean;
  ratchetStep: number;
  rawCiphertextPreview: string;
  reactions?: Record<string, string[]>;
  isPinned?: boolean;
}

export interface PinnedIdentity {
  identityKey: string;   // Base64 X25519 identity public key, as first seen
  signingKey: string;    // Base64 Ed25519 signing public key, as first seen
  verified: boolean;     // user confirmed the safety number out-of-band
  firstSeen: number;
}

export type PeerTrustState =
  | 'unknown'              // never contacted
  | 'pinned-unverified'    // key pinned, safety number not yet confirmed
  | 'verified'             // key pinned and confirmed
  | 'changed';             // pinned key no longer matches the directory — DANGER

/**
 * A group as this client knows it. Groups are entirely client-side: there is no
 * server-side group registration, so the relay never learns the roster. The
 * definition and the sender key travel to each member as a sealed 1:1 invite.
 */
export interface LocalGroup {
  id: string;
  name: string;
  creator: string;
  members: string[];
  createdAt: number;
}

export class SessionManager {
  public username: string;
  public identityKeyPair!: DHKeyPair;
  public signingKeyPair!: SigningKeyPair;
  public signedPreKey!: { keyId: number; keyPair: DHKeyPair; signature: Uint8Array };
  public oneTimePreKeys: Map<number, DHKeyPair> = new Map();

  private sessions = new Map<string, {
    session: DoubleRatchetSession;
    peerIdentityPublicKey: Uint8Array;
    peerSigningPublicKey?: Uint8Array;
  }>();
  private groupSessions = new Map<string, GroupSessionManager>();

  // --- Contact identity pinning (trust-on-first-use) -------------------------
  // The key directory is untrusted: it can hand us any keys for any username.
  // We pin a contact's identity + signing key the first time we see it and
  // refuse to proceed if it later changes without the user re-verifying. The
  // safety-number check is the out-of-band authentication for first contact.
  private pins = new Map<string, PinnedIdentity>();
  // Policy: when true, sendMessage() refuses a first message to a contact whose
  // safety number the user has not confirmed. The engine default is false (so
  // headless test harnesses work); the UI turns it on.
  public requireVerificationBeforeSend = false;

  // --- Replay defence ------------------------------------------------------
  // A hostile relay can re-deliver old envelopes. We drop any envelope id we
  // have already processed, and reject envelopes whose signed timestamp is
  // outside a sane window.
  private seenIds = new Set<string>();
  private seenOrder: string[] = [];
  private seenDirty = 0;
  private static MAX_SEEN = 5000;
  private static MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;      // 1 day in the future
  private static MAX_MESSAGE_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in the past

  private seenKey() {
    return `aegis_seen_${this.username.toLowerCase()}`;
  }

  private loadSeen() {
    try {
      const raw = secureStore.getItem(this.seenKey());
      if (!raw) return;
      const arr = JSON.parse(raw) as string[];
      for (const id of arr) {
        this.seenIds.add(id);
        this.seenOrder.push(id);
      }
    } catch {
      /* ignore */
    }
  }

  private persistSeen() {
    secureStore.setItem(this.seenKey(), JSON.stringify(this.seenOrder));
  }

  /** Returns false if this id was already processed (caller must drop it). */
  private markSeen(id: string): boolean {
    if (!id || this.seenIds.has(id)) return false;
    this.seenIds.add(id);
    this.seenOrder.push(id);
    if (this.seenOrder.length > SessionManager.MAX_SEEN) {
      const evicted = this.seenOrder.shift();
      if (evicted) this.seenIds.delete(evicted);
    }
    if (++this.seenDirty >= 16) {
      this.seenDirty = 0;
      this.persistSeen();
    }
    return true;
  }

  private timestampInWindow(ts: number | undefined): boolean {
    if (typeof ts !== 'number' || !Number.isFinite(ts)) return true; // absent => skip check
    const now = Date.now();
    return ts <= now + SessionManager.MAX_CLOCK_SKEW_MS &&
           ts >= now - SessionManager.MAX_MESSAGE_AGE_MS;
  }

  getOrCreateGroupSession(groupId: string): GroupSessionManager {
    if (!this.groupSessions.has(groupId)) {
      const gs = new GroupSessionManager(groupId, this.username);
      this.groupSessions.set(groupId, gs);
    }
    return this.groupSessions.get(groupId)!;
  }

  private serverUrl: string;
  private ws: WebSocket | null = null;
  private onMessageCallback?: (msg: ChatMessage) => void;
  private onRatchetUpdateCallback?: (peer: string, summary: RatchetStateSummary) => void;
  private onConnectionChangeCallback?: (connected: boolean) => void;
  private onCallSignalCallback?: (peer: string, signal: CallSignal) => void;
  private onGroupUpdateCallback?: (groups: LocalGroup[]) => void;

  // Client-side group registry (never sent to the relay).
  private groups = new Map<string, LocalGroup>();

  // Groups whose members we've already broadcast our own Sender Key
  // distribution to. Guards the invite-reciprocation below against looping.
  private announcedToGroup = new Set<string>();

  public setOnCallSignal(cb: (peer: string, signal: CallSignal) => void) {
    this.onCallSignalCallback = cb;
  }

  public setOnGroupUpdate(cb: (groups: LocalGroup[]) => void) {
    this.onGroupUpdateCallback = cb;
  }

  private groupsKey() {
    return `aegis_groups_${this.username.toLowerCase()}`;
  }

  private loadGroups() {
    try {
      const raw = secureStore.getItem(this.groupsKey());
      if (!raw) return;
      for (const g of JSON.parse(raw) as LocalGroup[]) this.groups.set(g.id, g);
    } catch (err) {
      console.warn('Failed to load groups:', err);
    }
  }

  private persistGroups() {
    secureStore.setItem(this.groupsKey(), JSON.stringify([...this.groups.values()]));
    this.onGroupUpdateCallback?.(this.getGroups());
  }

  getGroups(): LocalGroup[] {
    return [...this.groups.values()];
  }

  getGroup(id: string): LocalGroup | undefined {
    return this.groups.get(id);
  }

  async sendCallSignal(peer: string, signal: CallSignal): Promise<void> {
    const payload = JSON.stringify({ _aegisCall: true, signal });
    await this.sendMessage(peer, payload, 0);
  }

  private identityMnemonic: string;

  constructor(
    username: string,
    serverUrl: string = RELAY_URL,
    identityMnemonic?: string
  ) {
    this.username = username;
    // Honour a censorship-circumvention relay override (mirror / hidden service).
    this.serverUrl = TransportManager.effectiveBaseUrl(serverUrl);
    // Real onboarded users pass their seed phrase; demo profiles get a
    // deterministic per-username phrase so identity is always reproducible.
    this.identityMnemonic =
      identityMnemonic && identityMnemonic.trim()
        ? identityMnemonic.trim()
        : demoMnemonicForUsername(username);

    // Load persistent vault or generate new one
    this.loadOrCreateVault();
    this.loadSessions();
    this.loadPins();
    this.loadSeen();
    this.loadGroups();
  }

  // --- Trust / pinning -----------------------------------------------------

  private pinsKey() {
    return `aegis_pins_${this.username.toLowerCase()}`;
  }

  private loadPins() {
    try {
      const raw = secureStore.getItem(this.pinsKey());
      if (!raw) return;
      const parsed = JSON.parse(raw) as Record<string, PinnedIdentity>;
      for (const [peer, rec] of Object.entries(parsed)) {
        this.pins.set(peer.toLowerCase(), rec);
      }
    } catch (err) {
      console.warn('Failed to load identity pins:', err);
    }
  }

  private persistPins() {
    const obj: Record<string, PinnedIdentity> = {};
    for (const [peer, rec] of this.pins.entries()) obj[peer] = rec;
    secureStore.setItem(this.pinsKey(), JSON.stringify(obj));
  }

  /** Current trust state for a contact. */
  getPeerTrustState(peer: string): PeerTrustState {
    const rec = this.pins.get(peer.toLowerCase());
    if (!rec) return 'unknown';
    return rec.verified ? 'verified' : 'pinned-unverified';
  }

  /**
   * Checks a freshly-fetched bundle against the pin. Pins on first sight.
   * Throws 'IDENTITY_CHANGED' if a known contact's identity key no longer
   * matches what we pinned — this is the MITM / key-substitution signal.
   */
  private checkAndPinIdentity(peer: string, identityKeyB64: string, signingKeyB64: string) {
    const key = peer.toLowerCase();
    const existing = this.pins.get(key);
    if (!existing) {
      this.pins.set(key, {
        identityKey: identityKeyB64,
        signingKey: signingKeyB64,
        verified: false,
        firstSeen: Date.now(),
      });
      this.persistPins();
      return;
    }
    if (existing.identityKey !== identityKeyB64) {
      throw new Error(
        `IDENTITY_CHANGED: the key directory returned a different identity key for ` +
        `"${peer}" than the one pinned on first contact. Refusing to send until you ` +
        `re-verify the safety number in person.`
      );
    }
    if (existing.signingKey === '') {
      // Complete a partial pin created from an inbound-only first contact.
      existing.signingKey = signingKeyB64;
      this.persistPins();
    } else if (existing.signingKey !== signingKeyB64) {
      throw new Error(
        `IDENTITY_CHANGED: the signing key for "${peer}" no longer matches the pin. ` +
        `Refusing to send until you re-verify the safety number in person.`
      );
    }
  }

  /**
   * Inbound counterpart: an incoming first message carries only the sender's
   * identity key (not their signing key). Pin it if new; throw if it conflicts
   * with an existing pin (a relay/MITM trying to open a session under a known
   * contact's name with a substituted key).
   */
  private checkInboundIdentity(peer: string, identityKeyB64: string) {
    const key = peer.toLowerCase();
    const existing = this.pins.get(key);
    if (!existing) {
      this.pins.set(key, {
        identityKey: identityKeyB64,
        signingKey: '',
        verified: false,
        firstSeen: Date.now(),
      });
      this.persistPins();
      return;
    }
    if (existing.identityKey !== identityKeyB64) {
      throw new Error(
        `IDENTITY_CHANGED: incoming message from "${peer}" uses a different identity ` +
        `key than the one pinned on first contact. Message rejected.`
      );
    }
  }

  /**
   * Records that the user confirmed a contact's safety number out-of-band.
   * If `acceptNewKey` is set, replaces a changed pin with the current directory
   * key (use only after the user has actually re-verified).
   */
  async markPeerVerified(peer: string, acceptNewKey = false): Promise<void> {
    const key = peer.toLowerCase();
    let rec = this.pins.get(key);
    if ((!rec || acceptNewKey)) {
      // Pull the current bundle so we pin exactly what we will use.
      const res = await fetch(`${this.serverUrl}/api/keys/${encodeURIComponent(key)}`);
      if (!res.ok) throw new Error(`Cannot verify "${peer}": not registered on relay`);
      const b = await res.json();
      rec = {
        identityKey: b.identityPublicKey,
        signingKey: b.signingPublicKey,
        verified: true,
        firstSeen: rec?.firstSeen ?? Date.now(),
      };
    } else {
      rec = { ...rec, verified: true };
    }
    this.pins.set(key, rec);
    this.persistPins();
  }

  /** Forget a pin entirely (e.g. contact removed). */
  clearPeerPin(peer: string) {
    if (this.pins.delete(peer.toLowerCase())) this.persistPins();
  }

  /** Our own blind delivery token — how peers address sealed envelopes to us. */
  private myBlindToken(): string {
    return blindDeliveryToken(this.signingKeyPair.publicKey);
  }

  /** Canonical bytes signed inside a sealed envelope (signature field blanked). */
  private sealedSigningBytes(inner: Omit<SealedInner, 'signature'>): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ ...inner, signature: '' }));
  }

  /**
   * Signs `innerNoSig` with our identity key, seals it to `recipientIdentityPub`
   * with an ephemeral DH, and pushes it to the relay addressed only by the
   * recipient's blind delivery token.
   */
  private sealAndSend(
    recipientIdentityPub: Uint8Array,
    recipientSigningPub: Uint8Array,
    innerNoSig: Omit<SealedInner, 'signature'>,
    envelopeId: string,
    ts: number
  ) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected to relay');
    }
    const signature = toBase64(
      sign(this.sealedSigningBytes(innerNoSig), this.signingKeyPair.privateKey)
    );
    const inner: SealedInner = { ...innerNoSig, signature };
    const recipientBlindToken = blindDeliveryToken(recipientSigningPub);
    const sealed = sealToRecipient(
      recipientIdentityPub,
      JSON.stringify(inner),
      fromBase64(recipientBlindToken)
    );
    const sealedEnvelope: SealedEnvelope = {
      id: envelopeId,
      recipientBlindToken,
      ephemeralPublicKey: toBase64(sealed.ephemeralPublicKey),
      nonce: toBase64(sealed.nonce),
      ciphertext: toBase64(sealed.ciphertext),
      timestamp: ts,
    };
    this.ws.send(JSON.stringify({ type: 'SEALED_ENVELOPE', payload: sealedEnvelope }));
  }

  /** Fetch (and briefly cache) a peer's identity + signing public keys. */
  private async peerKeys(
    peer: string
  ): Promise<{ identity: Uint8Array; signing: Uint8Array }> {
    peer = peer.toLowerCase();
    const session = this.sessions.get(peer);
    if (session?.peerIdentityPublicKey && session.peerSigningPublicKey) {
      return { identity: session.peerIdentityPublicKey, signing: session.peerSigningPublicKey };
    }
    const pin = this.pins.get(peer);
    if (pin && pin.identityKey && pin.signingKey) {
      return { identity: fromBase64(pin.identityKey), signing: fromBase64(pin.signingKey) };
    }
    const res = await fetch(`${this.serverUrl}/api/keys/${encodeURIComponent(peer)}`);
    if (!res.ok) throw new Error(`Peer '${peer}' is not registered on key relay`);
    const b = await res.json();
    this.checkAndPinIdentity(peer, b.identityPublicKey, b.signingPublicKey);
    return {
      identity: fromBase64(b.identityPublicKey),
      signing: fromBase64(b.signingPublicKey),
    };
  }

  /** Directly set the verified flag on an existing pin (UI toggle). */
  setPeerVerified(peer: string, verified: boolean) {
    const rec = this.pins.get(peer.toLowerCase());
    if (rec && rec.verified !== verified) {
      rec.verified = verified;
      this.persistPins();
    }
  }

  private loadOrCreateVault() {
    // Long-term identity + signing keys are ALWAYS derived from the seed phrase,
    // never randomly generated or trusted from storage. This is what lets a user
    // restore the same identity on a new device from the phrase alone.
    const derived = deriveIdentityFromMnemonic(this.identityMnemonic);
    this.identityKeyPair = derived.identityKeyPair;
    this.signingKeyPair = derived.signingKeyPair;

    const vaultKey = `aegis_vault_${this.username.toLowerCase()}`;
    const stored = secureStore.getItem(vaultKey);

    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        // Only the per-device prekeys are loaded from storage; identity is derived.
        this.signedPreKey = {
          keyId: parsed.signedPreKey.keyId,
          keyPair: {
            publicKey: fromBase64(parsed.signedPreKey.keyPair.publicKey),
            privateKey: fromBase64(parsed.signedPreKey.keyPair.privateKey),
          },
          signature: fromBase64(parsed.signedPreKey.signature),
        };
        this.oneTimePreKeys.clear();
        for (const opk of parsed.oneTimePreKeys) {
          this.oneTimePreKeys.set(opk.keyId, {
            publicKey: fromBase64(opk.keyPair.publicKey),
            privateKey: fromBase64(opk.keyPair.privateKey),
          });
        }
        // Re-sign the stored SPK if it was created under a previous (random)
        // identity, so the bundle stays internally consistent.
        const freshSig = sign(this.signedPreKey.keyPair.publicKey, this.signingKeyPair.privateKey);
        if (toBase64(freshSig) !== toBase64(this.signedPreKey.signature)) {
          this.signedPreKey.signature = freshSig;
          this.persistVault();
        }
        return;
      } catch (err) {
        console.warn('Could not parse vault, regenerating prekeys:', err);
      }
    }

    // Fresh per-device prekeys (signed by the seed-derived identity).
    const spkKeyPair = generateDHKeyPair();
    this.signedPreKey = {
      keyId: 1,
      keyPair: spkKeyPair,
      signature: sign(spkKeyPair.publicKey, this.signingKeyPair.privateKey),
    };

    this.oneTimePreKeys.clear();
    for (let i = 1; i <= 10; i++) {
      this.oneTimePreKeys.set(i, generateDHKeyPair());
    }

    this.persistVault();
  }

  public persistVault() {
    const vaultKey = `aegis_vault_${this.username.toLowerCase()}`;

    const opks = Array.from(this.oneTimePreKeys.entries()).map(([keyId, pair]) => ({
      keyId,
      keyPair: {
        publicKey: toBase64(pair.publicKey),
        privateKey: toBase64(pair.privateKey),
      },
    }));

    const vault = {
      identityKeyPair: {
        publicKey: toBase64(this.identityKeyPair.publicKey),
        privateKey: toBase64(this.identityKeyPair.privateKey),
      },
      signingKeyPair: {
        publicKey: toBase64(this.signingKeyPair.publicKey),
        privateKey: toBase64(this.signingKeyPair.privateKey),
      },
      signedPreKey: {
        keyId: this.signedPreKey.keyId,
        keyPair: {
          publicKey: toBase64(this.signedPreKey.keyPair.publicKey),
          privateKey: toBase64(this.signedPreKey.keyPair.privateKey),
        },
        signature: toBase64(this.signedPreKey.signature),
      },
      oneTimePreKeys: opks,
    };

    secureStore.setItem(vaultKey, JSON.stringify(vault));
  }

  private persistSessions() {
    const sessionsKey = `aegis_sessions_${this.username.toLowerCase()}`;
    const exported: Record<string, {
      session: DoubleRatchetStateExport;
      peerIdentityPublicKey: string;
      peerSigningPublicKey?: string;
    }> = {};

    for (const [peer, data] of this.sessions.entries()) {
      exported[peer] = {
        session: data.session.exportState(),
        peerIdentityPublicKey: toBase64(data.peerIdentityPublicKey),
        peerSigningPublicKey: data.peerSigningPublicKey
          ? toBase64(data.peerSigningPublicKey)
          : undefined,
      };
    }

    secureStore.setItem(sessionsKey, JSON.stringify(exported));
  }

  private loadSessions() {
    const sessionsKey = `aegis_sessions_${this.username.toLowerCase()}`;
    const stored = secureStore.getItem(sessionsKey);
    if (!stored) return;

    try {
      const parsed = JSON.parse(stored);
      for (const [peer, data] of Object.entries(parsed) as [string, any][]) {
        const session = DoubleRatchetSession.fromState(data.session);
        this.sessions.set(peer, {
          session,
          peerIdentityPublicKey: fromBase64(data.peerIdentityPublicKey),
          peerSigningPublicKey: data.peerSigningPublicKey
            ? fromBase64(data.peerSigningPublicKey)
            : undefined,
        });
      }
    } catch (err) {
      console.warn('Failed to load persisted sessions:', err);
    }
  }

  /**
   * Registers public identity bundle with untrusted relay
   */
  async registerOnRelay(): Promise<void> {
    const opks = Array.from(this.oneTimePreKeys.entries()).map(([keyId, pair]) => ({
      keyId,
      publicKey: toBase64(pair.publicKey),
    }));

    const bundlePayload = {
      username: this.username,
      identityPublicKey: toBase64(this.identityKeyPair.publicKey),
      signingPublicKey: toBase64(this.signingKeyPair.publicKey),
      blindToken: this.myBlindToken(),
      signedPreKey: {
        keyId: this.signedPreKey.keyId,
        publicKey: toBase64(this.signedPreKey.keyPair.publicKey),
        signature: toBase64(this.signedPreKey.signature),
      },
      oneTimePreKeys: opks,
    };

    const res = await fetch(`${this.serverUrl}/api/keys/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bundlePayload),
    });

    if (!res.ok) {
      throw new Error(`Failed to register keys: ${res.statusText}`);
    }
  }

  /**
   * Connects to WebSocket Blind Relay
   */
  connectWebSocket(
    onMessage: (msg: ChatMessage) => void,
    onRatchetUpdate: (peer: string, summary: RatchetStateSummary) => void,
    onConnectionChange: (connected: boolean) => void
  ) {
    this.disconnect();

    this.onMessageCallback = onMessage;
    this.onRatchetUpdateCallback = onRatchetUpdate;
    this.onConnectionChangeCallback = onConnectionChange;

    const wsUrl = this.serverUrl.replace(/^http/, 'ws') + '/ws';
    const ws = new WebSocket(wsUrl);
    this.ws = ws;

    ws.onopen = () => {
      if (ws.readyState === WebSocket.OPEN) {
        console.log(`[Aegis Client] WS connected for ${this.username}`);
        ws.send(JSON.stringify({
          type: 'AUTH',
          username: this.username,
          blindToken: this.myBlindToken(),
        }));
        this.onConnectionChangeCallback?.(true);
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'SEALED_ENVELOPE') {
          this.handleIncomingSealedEnvelope(data.payload);
        } else if (data.type === 'ENVELOPE') {
          this.handleIncomingEnvelope(data.payload);
        } else if (data.type === 'GROUP_ENVELOPE') {
          this.handleIncomingGroupEnvelope(data.payload);
        }
      } catch (err) {
        console.error('[Aegis Client] Error processing message:', err);
      }
    };

    ws.onclose = () => {
      if (this.ws === ws) {
        this.onConnectionChangeCallback?.(false);
      }
    };
  }

  disconnect() {
    this.persistSeen();
    if (this.ws) {
      const ws = this.ws;
      this.ws = null;
      ws.onopen = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        try {
          ws.close();
        } catch {
          // ignore
        }
      }
    }
  }

  /**
   * Sends an end-to-end encrypted message to a recipient
   */
  async sendMessage(
    recipient: string,
    text: string,
    expiresInSec: number = 0,
    attachment?: EncryptedAttachmentDescriptor
  ): Promise<ChatMessage> {
    recipient = recipient.toLowerCase();
    let sessionData = this.sessions.get(recipient);
    let ephemeralKeyBase64: string | undefined = undefined;
    let oneTimeKeyIdUsed: number | undefined = undefined;

    // If no existing Double Ratchet session, initialize via X3DH
    if (!sessionData) {
      const res = await fetch(`${this.serverUrl}/api/keys/${encodeURIComponent(recipient)}`);
      if (!res.ok) {
        throw new Error(`Recipient '${recipient}' is not registered on key relay`);
      }
      const rawBundle = await res.json();

      // Trust-on-first-use: pin identity now, or fail hard if it changed.
      this.checkAndPinIdentity(recipient, rawBundle.identityPublicKey, rawBundle.signingPublicKey);

      // Check verification before doing any X3DH/session work: a blocked
      // attempt must not create a local session that was never actually
      // transmitted, or a later retry would skip X3DH (thinking a session
      // already exists) and send a message the recipient can't bootstrap.
      if (
        this.requireVerificationBeforeSend &&
        this.getPeerTrustState(recipient) !== 'verified'
      ) {
        throw new Error(
          `VERIFICATION_REQUIRED: confirm ${recipient}'s safety number before sending.`
        );
      }

      const peerBundle: PreKeyBundle = {
        username: rawBundle.username || recipient,
        identityPublicKey: fromBase64(rawBundle.identityPublicKey),
        signingPublicKey: fromBase64(rawBundle.signingPublicKey),
        signedPreKey: {
          keyId: rawBundle.signedPreKey.keyId,
          publicKey: fromBase64(rawBundle.signedPreKey.publicKey),
          signature: fromBase64(rawBundle.signedPreKey.signature),
        },
        oneTimePreKey: rawBundle.oneTimePreKey
          ? {
              keyId: rawBundle.oneTimePreKey.keyId,
              publicKey: fromBase64(rawBundle.oneTimePreKey.publicKey),
            }
          : undefined,
      };

      // Run X3DH Agreement
      const x3dhResult = X3DH.initiate(this.identityKeyPair, peerBundle);
      ephemeralKeyBase64 = toBase64(x3dhResult.ephemeralPublicKey);
      oneTimeKeyIdUsed = x3dhResult.oneTimeKeyIdUsed;

      // Initialize sender Double Ratchet session
      const ratchet = new DoubleRatchetSession(
        true,
        x3dhResult.sharedKey,
        peerBundle.signedPreKey.publicKey
      );

      sessionData = {
        session: ratchet,
        peerIdentityPublicKey: peerBundle.identityPublicKey,
        peerSigningPublicKey: peerBundle.signingPublicKey,
      };
      this.sessions.set(recipient, sessionData);
      this.persistSessions();
    } else if (
      this.requireVerificationBeforeSend &&
      this.getPeerTrustState(recipient) !== 'verified'
    ) {
      // Session already exists -- e.g. we received a first message from
      // this peer and are now replying. Still enforce verification before
      // any ciphertext goes out, the same as the brand-new-session path
      // above.
      throw new Error(
        `VERIFICATION_REQUIRED: confirm ${recipient}'s safety number before sending.`
      );
    }

    // Make sure we know the recipient's signing key (for their blind token).
    let peerSigning = sessionData.peerSigningPublicKey;
    if (!peerSigning) {
      const pin = this.pins.get(recipient);
      if (pin && pin.signingKey) {
        peerSigning = fromBase64(pin.signingKey);
      } else {
        const r = await fetch(`${this.serverUrl}/api/keys/${encodeURIComponent(recipient)}`);
        if (!r.ok) throw new Error(`Recipient '${recipient}' is not registered on key relay`);
        const b = await r.json();
        this.checkAndPinIdentity(recipient, b.identityPublicKey, b.signingPublicKey);
        peerSigning = fromBase64(b.signingPublicKey);
      }
      sessionData.peerSigningPublicKey = peerSigning;
      this.persistSessions();
    }

    // Prepare envelope payload
    const payloadText = (attachment || expiresInSec > 0)
      ? JSON.stringify({ _aegis: true, text, attachment, expiresInSec })
      : text;

    // Encrypt payload with Double Ratchet
    const encryptedPayload = sessionData.session.encrypt(payloadText);
    this.persistSessions();

    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected to relay');
    }

    // Build the inner payload (sender identity lives here, invisible to the relay).
    const envelopeId = crypto.randomUUID();
    const ts = Date.now();
    const innerNoSig: Omit<SealedInner, 'signature'> = {
      sender: this.username,
      senderIdentityKey: toBase64(this.identityKeyPair.publicKey),
      senderSigningKey: toBase64(this.signingKeyPair.publicKey),
      ephemeralKey: ephemeralKeyBase64,
      oneTimeKeyIdUsed,
      ratchetKey: encryptedPayload.header.ratchetKey,
      messageNumber: encryptedPayload.header.messageNumber,
      previousChainLength: encryptedPayload.header.previousChainLength,
      nonce: encryptedPayload.nonce,
      ciphertext: encryptedPayload.ciphertext,
      timestamp: ts,
    };
    this.sealAndSend(
      sessionData.peerIdentityPublicKey,
      peerSigning,
      innerNoSig,
      envelopeId,
      ts
    );

    const summary = sessionData.session.getStateSummary();
    this.onRatchetUpdateCallback?.(recipient, summary);

    const now = Date.now();
    return {
      id: envelopeId,
      sender: this.username,
      recipient,
      text,
      attachment,
      timestamp: ts,
      expiresAt: expiresInSec > 0 ? now + expiresInSec * 1000 : undefined,
      isSelf: true,
      ratchetStep: summary.ratchetStep,
      rawCiphertextPreview: encryptedPayload.ciphertext.slice(0, 32) + '...',
    };
  }

  /**
   * Opens a sealed-sender envelope: derive the transport key from our identity
   * key, decrypt the inner payload, verify the sender's signature, pin their
   * identity (TOFU), then hand the ratchet message to the normal path.
   */
  private handleIncomingSealedEnvelope(sealed: SealedEnvelope) {
    let inner: SealedInner;
    try {
      const json = unsealFromSender(
        this.identityKeyPair.privateKey,
        fromBase64(sealed.ephemeralPublicKey),
        fromBase64(sealed.nonce),
        fromBase64(sealed.ciphertext),
        fromBase64(sealed.recipientBlindToken)
      );
      inner = JSON.parse(json) as SealedInner;
    } catch (err) {
      console.error('[Aegis] Failed to unseal envelope:', err);
      return;
    }

    // Verify the inner signature against the claimed sender signing key.
    const { signature, ...innerNoSig } = inner;
    const sigOk = verify(
      fromBase64(signature),
      this.sealedSigningBytes(innerNoSig),
      fromBase64(inner.senderSigningKey)
    );
    if (!sigOk) {
      console.error('[Aegis] SECURITY: sealed envelope signature invalid — dropped.');
      return;
    }

    // Replay defence: reject stale timestamps and anything we've already seen.
    if (!this.timestampInWindow(inner.timestamp)) {
      console.warn('[Aegis] Dropped sealed envelope with out-of-window timestamp.');
      return;
    }
    if (!this.markSeen(sealed.id)) {
      console.warn('[Aegis] Dropped replayed sealed envelope', sealed.id);
      return;
    }

    // Trust-on-first-use on BOTH keys now that sealed sender gives us the
    // signing key too.
    try {
      this.checkAndPinIdentity(inner.sender, inner.senderIdentityKey, inner.senderSigningKey);
    } catch (err) {
      console.error('[Aegis] SECURITY:', (err as Error).message);
      return;
    }

    if (inner.kind === 'group') {
      this.handleIncomingGroupEnvelope(
        {
          id: sealed.id,
          groupId: inner.groupId,
          sender: inner.sender,
          timestamp: inner.timestamp || sealed.timestamp,
          messageIndex: inner.groupMessageIndex,
          nonce: inner.nonce,
          ciphertext: inner.ciphertext,
          signature: inner.groupSignature,
        },
        true // replay already checked on the sealed envelope
      );
      return;
    }

    if (
      typeof inner.ratchetKey !== 'string' ||
      typeof inner.messageNumber !== 'number' ||
      typeof inner.previousChainLength !== 'number'
    ) {
      console.error('[Aegis] Malformed direct sealed payload — dropped.');
      return;
    }

    const envelope: WireEnvelope = {
      id: sealed.id,
      sender: inner.sender,
      recipient: this.username,
      timestamp: inner.timestamp || sealed.timestamp,
      senderIdentityKey: inner.senderIdentityKey,
      senderSigningKey: inner.senderSigningKey,
      ephemeralKey: inner.ephemeralKey,
      oneTimeKeyIdUsed: inner.oneTimeKeyIdUsed,
      ratchetKey: inner.ratchetKey,
      messageNumber: inner.messageNumber,
      previousChainLength: inner.previousChainLength,
      nonce: inner.nonce,
      ciphertext: inner.ciphertext,
    };
    this.handleIncomingEnvelope(envelope, inner.senderSigningKey);
  }

  /**
   * Processes incoming encrypted wire envelope
   */
  private handleIncomingEnvelope(envelope: WireEnvelope, senderSigningKeyB64?: string) {
    const sender = envelope.sender.toLowerCase();
    let sessionData = this.sessions.get(sender);

    // If responder doesn't have an active session yet, derive key from X3DH
    if (!sessionData) {
      if (!envelope.ephemeralKey) {
        throw new Error('First incoming message must contain ephemeralKey for X3DH');
      }

      // Look up one-time prekey private key if used
      let opkPrivateKey: Uint8Array | null = null;
      if (envelope.oneTimeKeyIdUsed && this.oneTimePreKeys.has(envelope.oneTimeKeyIdUsed)) {
        opkPrivateKey = this.oneTimePreKeys.get(envelope.oneTimeKeyIdUsed)!.privateKey;
        // Purge one-time private key immediately (Forward Secrecy guarantee)
        this.oneTimePreKeys.delete(envelope.oneTimeKeyIdUsed);
        this.persistVault();
      }

      // Compute shared key via X3DH. The sender's identity key is required —
      // never silently fall back to the ratchet key, which would derive a
      // garbage session and (previously) desync on the first message.
      if (!envelope.senderIdentityKey) {
        throw new Error('First incoming message must carry senderIdentityKey for X3DH');
      }
      // Trust-on-first-use check before we derive a session under this name.
      this.checkInboundIdentity(sender, envelope.senderIdentityKey);
      const senderIdentityPublicKey = fromBase64(envelope.senderIdentityKey);
      const senderEphemeralPublicKey = fromBase64(envelope.ephemeralKey);

      const sharedKey = X3DH.respond(
        this.identityKeyPair,
        this.signedPreKey.keyPair.privateKey,
        opkPrivateKey,
        senderIdentityPublicKey,
        senderEphemeralPublicKey
      );

      const ratchet = new DoubleRatchetSession(
        false,
        sharedKey,
        undefined,
        this.signedPreKey.keyPair
      );

      sessionData = {
        session: ratchet,
        peerIdentityPublicKey: senderIdentityPublicKey,
        peerSigningPublicKey: senderSigningKeyB64
          ? fromBase64(senderSigningKeyB64)
          : undefined,
      };
      this.sessions.set(sender, sessionData);
      this.persistSessions();
    } else if (senderSigningKeyB64 && !sessionData.peerSigningPublicKey) {
      sessionData.peerSigningPublicKey = fromBase64(senderSigningKeyB64);
      this.persistSessions();
    }

    // Decrypt with Double Ratchet
    const payload: EncryptedMessagePayload = {
      header: {
        ratchetKey: envelope.ratchetKey,
        messageNumber: envelope.messageNumber,
        previousChainLength: envelope.previousChainLength,
      },
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
    };

    const plaintext = sessionData.session.decrypt(payload);
    this.persistSessions();

    let parsedText = plaintext;
    let attachment: EncryptedAttachmentDescriptor | undefined = undefined;
    let expiresAt: number | undefined = undefined;

    try {
      if (plaintext.startsWith('{"_aegisGroupInvite":true,')) {
        const parsed = JSON.parse(plaintext);
        const g = parsed.group as LocalGroup | undefined;
        const dist = parsed.distribution;
        if (g && g.id && dist) {
          // Store / update the group definition locally. Trust the definition
          // only from a peer whose sealed-sender signature already verified
          // (this path is only reached after that check) — and, for updates,
          // only from the same creator.
          const existing = this.groups.get(g.id);
          if (!existing || existing.creator.toLowerCase() === envelope.sender.toLowerCase()) {
            this.groups.set(g.id, {
              id: g.id,
              name: g.name || existing?.name || 'Group',
              creator: g.creator || envelope.sender,
              members: Array.isArray(g.members) ? g.members : existing?.members ?? [],
              createdAt: existing?.createdAt ?? g.createdAt ?? Date.now(),
            });
            this.persistGroups();
          }
          this.getOrCreateGroupSession(dist.groupId).importPeerDistribution(dist);
          console.log(`[Aegis] Joined/updated group ${g.id} via invite from ${envelope.sender}`);

          // Reciprocate: a member's Sender Key only reaches anyone else if we
          // proactively send it — importing the inviter's key above doesn't
          // do that for ours. Announce it back once per group so the group
          // works both ways; `announcedToGroup` stops this from looping when
          // the other side's own reciprocation arrives back at us.
          if (!this.announcedToGroup.has(g.id)) {
            const stored = this.groups.get(g.id);
            const membersToTell = (stored?.members ?? []).filter(
              (m) => m.toLowerCase() !== this.username.toLowerCase()
            );
            if (stored && membersToTell.length > 0) {
              this.sendGroupInvites(stored, membersToTell).catch((err) => {
                console.warn(`[Aegis] Could not announce our sender key for ${g.id}:`, err);
              });
            }
          }

          this.ws?.send(JSON.stringify({
            type: 'ACK', envelopeId: envelope.id, blindToken: this.myBlindToken(),
          }));
          return;
        }
      }

      if (plaintext.startsWith('{"_aegisCall":true,')) {
        const parsed = JSON.parse(plaintext);
        this.ws?.send(JSON.stringify({
          type: 'ACK',
          envelopeId: envelope.id,
          blindToken: this.myBlindToken(),
        }));
        this.onCallSignalCallback?.(sender, parsed.signal);
        return;
      }

      if (plaintext.startsWith('{"_aegis":true,')) {
        const parsed = JSON.parse(plaintext);
        parsedText = parsed.text || '';
        attachment = parsed.attachment;
        if (parsed.expiresInSec && parsed.expiresInSec > 0) {
          expiresAt = Date.now() + parsed.expiresInSec * 1000;
        }
      }
    } catch {
      // Raw plaintext message
    }

    // Acknowledge receipt to server so server purges it from queue
    this.ws?.send(JSON.stringify({
      type: 'ACK',
      envelopeId: envelope.id,
      blindToken: this.myBlindToken(),
    }));

    const summary = sessionData.session.getStateSummary();
    this.onRatchetUpdateCallback?.(sender, summary);

    const chatMsg: ChatMessage = {
      id: envelope.id,
      sender: envelope.sender,
      recipient: this.username,
      text: parsedText,
      attachment,
      expiresAt,
      timestamp: envelope.timestamp,
      isSelf: false,
      ratchetStep: summary.ratchetStep,
      rawCiphertextPreview: envelope.ciphertext.slice(0, 32) + '...',
    };

    this.onMessageCallback?.(chatMsg);
  }

  /**
   * Safety Number (Fingerprint) calculation for peer
   */
  getSafetyNumber(peer: string): { formatted: string[]; rawHash: string } | null {
    const key = peer.toLowerCase();
    const sessionData = this.sessions.get(key);
    if (sessionData) {
      return generateSafetyNumber(
        this.identityKeyPair.publicKey,
        sessionData.peerIdentityPublicKey
      );
    }

    // No Double Ratchet session yet (e.g. blocked by VERIFICATION_REQUIRED before
    // the first message goes out) — fall back to the pinned identity key so the
    // safety number is still computable before that first message can succeed.
    const pin = this.pins.get(key);
    if (!pin) return null;

    return generateSafetyNumber(this.identityKeyPair.publicKey, fromBase64(pin.identityKey));
  }

  getRatchetSummary(peer: string): RatchetStateSummary | null {
    const sessionData = this.sessions.get(peer.toLowerCase());
    if (!sessionData) return null;
    return sessionData.session.getStateSummary();
  }

  private handleIncomingGroupEnvelope(envelope: any, skipReplayCheck = false) {
    try {
      if (!skipReplayCheck) {
        if (!this.timestampInWindow(envelope.timestamp)) {
          console.warn('[Aegis] Dropped group envelope with out-of-window timestamp.');
          return;
        }
        if (!this.markSeen(envelope.id)) {
          console.warn('[Aegis] Dropped replayed group envelope', envelope.id);
          return;
        }
      }
      const groupSession = this.getOrCreateGroupSession(envelope.groupId);
      const plaintext = groupSession.decrypt(envelope.sender, {
        messageIndex: envelope.messageIndex,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
        signature: envelope.signature,
      });

      let parsedText = plaintext;
      let attachment: EncryptedAttachmentDescriptor | undefined = undefined;
      let expiresAt: number | undefined = undefined;

      try {
        if (plaintext.startsWith('{"_aegis":true,')) {
          const parsed = JSON.parse(plaintext);
          parsedText = parsed.text || '';
          attachment = parsed.attachment;
          if (parsed.expiresInSec && parsed.expiresInSec > 0) {
            expiresAt = Date.now() + parsed.expiresInSec * 1000;
          }
        }
      } catch {
        // Raw plaintext
      }

      const chatMsg: ChatMessage = {
        id: envelope.id,
        sender: envelope.sender,
        recipient: envelope.groupId,
        groupId: envelope.groupId,
        text: parsedText,
        attachment,
        expiresAt,
        timestamp: envelope.timestamp,
        isSelf: false,
        ratchetStep: envelope.messageIndex,
        rawCiphertextPreview: envelope.ciphertext.slice(0, 32) + '...',
      };

      this.onMessageCallback?.(chatMsg);
    } catch (err) {
      console.error('[Aegis] Error decrypting group envelope:', err);
    }
  }

  /**
   * Create a group entirely client-side. The relay is never told the group
   * exists or who is in it. The definition + our sender key are delivered to
   * each member as a sealed 1:1 invite.
   */
  async createGroup(name: string, members: string[]): Promise<LocalGroup> {
    const me = this.username;
    const roster = Array.from(new Set([me, ...members].map((m) => m)));
    const group: LocalGroup = {
      id: 'grp_' + crypto.randomUUID(),
      name: name.trim() || 'Group',
      creator: me,
      members: roster,
      createdAt: Date.now(),
    };
    this.groups.set(group.id, group);
    this.persistGroups();
    // Fresh sender key for this group.
    this.getOrCreateGroupSession(group.id);
    await this.sendGroupInvites(group, roster);
    return group;
  }

  /** Send `{ _aegisGroupInvite }` (definition + our current sender key) to members. */
  private async sendGroupInvites(group: LocalGroup, to: string[]): Promise<void> {
    this.announcedToGroup.add(group.id);
    const gs = this.getOrCreateGroupSession(group.id);
    const distribution = gs.exportOurDistribution();
    const payload = JSON.stringify({ _aegisGroupInvite: true, group, distribution });
    for (const member of to) {
      if (member.toLowerCase() === this.username.toLowerCase()) continue;
      try {
        await this.sendMessage(member, payload, 0);
      } catch (err) {
        console.warn(`[Aegis] Could not invite ${member} to ${group.name}:`, err);
      }
    }
  }

  async sendGroupMessage(
    groupId: string,
    text: string,
    expiresInSec: number = 0,
    attachment?: EncryptedAttachmentDescriptor
  ): Promise<ChatMessage> {
    const group = this.groups.get(groupId);
    if (!group) throw new Error(`Unknown group ${groupId}`);
    const groupSession = this.getOrCreateGroupSession(groupId);

    const payloadText = (attachment || expiresInSec > 0)
      ? JSON.stringify({ _aegis: true, text, attachment, expiresInSec })
      : text;

    // One O(1) sender-key encryption...
    const packet = groupSession.encrypt(payloadText);
    const envelopeId = 'grp_msg_' + crypto.randomUUID();
    const ts = Date.now();

    // ...fanned out as individual SEALED envelopes so the relay learns neither
    // the sender nor the group membership (privacy over the O(1) broadcast).
    const meLower = this.username.toLowerCase();
    for (const member of group.members) {
      if (member.toLowerCase() === meLower) continue;
      try {
        const { identity, signing } = await this.peerKeys(member);
        const innerNoSig: Omit<SealedInner, 'signature'> = {
          kind: 'group',
          sender: this.username,
          senderIdentityKey: toBase64(this.identityKeyPair.publicKey),
          senderSigningKey: toBase64(this.signingKeyPair.publicKey),
          groupId,
          groupMessageIndex: packet.messageIndex,
          groupSignature: packet.signature,
          nonce: packet.nonce,
          ciphertext: packet.ciphertext,
          timestamp: ts,
        };
        this.sealAndSend(identity, signing, innerNoSig, envelopeId + ':' + member.toLowerCase(), ts);
      } catch (err) {
        console.warn(`[Aegis] Could not deliver group message to ${member}:`, err);
      }
    }

    const now = Date.now();
    return {
      id: envelopeId,
      sender: this.username,
      recipient: groupId,
      groupId,
      text,
      attachment,
      timestamp: ts,
      expiresAt: expiresInSec > 0 ? now + expiresInSec * 1000 : undefined,
      isSelf: true,
      ratchetStep: packet.messageIndex,
      rawCiphertextPreview: packet.ciphertext.slice(0, 32) + '...',
    };
  }

  /**
   * Remove a member from a group: forget their sender chain, rotate our own
   * sender key, update the local roster, and re-invite the remaining members
   * with the fresh key + updated definition. The removed member is told nothing
   * and cannot read any further messages.
   */
  async removeGroupMember(groupId: string, memberToRemove: string): Promise<void> {
    const group = this.groups.get(groupId);
    if (!group) throw new Error(`Unknown group ${groupId}`);

    group.members = group.members.filter(
      (m) => m.toLowerCase() !== memberToRemove.toLowerCase()
    );
    this.persistGroups();

    const gs = this.getOrCreateGroupSession(groupId);
    gs.removePeer(memberToRemove);
    gs.rotateOurSenderKey();

    await this.sendGroupInvites(group, group.members);
  }

  /** Re-share our current sender key (and group definition) with the members. */
  async distributeSenderKeyToGroup(groupId: string, members?: string[]): Promise<void> {
    const group = this.groups.get(groupId);
    if (!group) throw new Error(`Unknown group ${groupId}`);
    await this.sendGroupInvites(group, members ?? group.members);
  }
}
