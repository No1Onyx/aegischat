import {
  generateDHKeyPair,
  computeDH,
  deriveTwoKeys,
  encryptAEAD,
  decryptAEAD,
  toHex,
  toBase64,
  fromBase64,
} from './primitives.js';
import type { DHKeyPair } from './primitives.js';

export interface RatchetHeader {
  ratchetKey: string;          // Base64 public key
  messageNumber: number;       // Ns
  previousChainLength: number; // PN
}

export interface EncryptedMessagePayload {
  header: RatchetHeader;
  nonce: string;              // Base64
  ciphertext: string;         // Base64
}

export interface RatchetStateSummary {
  ratchetStep: number;
  ourRatchetPublicKey: string;
  theirRatchetPublicKey: string;
  rootKeyPreview: string;
  sendChainLength: number;
  recvChainLength: number;
}

export interface DoubleRatchetStateExport {
  dhrs: { publicKey: string; privateKey: string };
  dhrr: string | null;
  rk: string;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  ratchetStepCount: number;
  skippedKeys?: Array<[string, string]>; // [keyId, base64 messageKey]
}

const INFO_RK = 'AegisChat_Ratchet_RK_v1';
const INFO_CK = 'AegisChat_Ratchet_CK_v1';
const ZERO_SALT = new Uint8Array(32);

// Upper bound on how many message keys we will derive to catch a chain up to an
// incoming message number. A header that asks us to skip more than this is
// treated as a denial-of-service attempt and rejected before doing the work.
// (Signal's Double Ratchet spec mandates such a bound.)
const MAX_SKIP = 1000;
// Cap on retained out-of-order message keys; oldest are evicted first.
const MAX_SKIPPED_KEYS = 2000;

export class DoubleRatchetSession {
  private dhrs: DHKeyPair;               // Our DH Ratchet keypair
  private dhrr: Uint8Array | null = null; // Their DH Ratchet public key
  private rk: Uint8Array;                // Root key
  private cks: Uint8Array | null = null; // Chain key send
  private ckr: Uint8Array | null = null; // Chain key receive
  private ns: number = 0;                // Send message index
  private nr: number = 0;                // Receive message index
  private pn: number = 0;                // Previous chain length
  private skippedKeys = new Map<string, Uint8Array>(); // (pubKeyHex + ':' + msgNum) -> mk
  public ratchetStepCount: number = 0;

  constructor(
    isInitiator: boolean,
    sharedKey: Uint8Array,
    theirRatchetPublicKey?: Uint8Array,
    ourInitialKeyPair?: DHKeyPair
  ) {
    this.rk = sharedKey;
    this.dhrs = ourInitialKeyPair || generateDHKeyPair();

    if (isInitiator) {
      // Alice (initiator) knows Bob's ratchet key from bundle (SPK or initial DHR)
      if (!theirRatchetPublicKey) {
        throw new Error('Initiator requires theirRatchetPublicKey to start Double Ratchet');
      }
      this.dhrr = theirRatchetPublicKey;
      // Perform initial DH ratchet step to derive sending chain
      const dh = computeDH(this.dhrs.privateKey, this.dhrr);
      const [newRk, newCks] = deriveTwoKeys(dh, this.rk, INFO_RK);
      this.rk = newRk;
      this.cks = newCks;
      this.ratchetStepCount = 1;
    } else {
      // Bob (responder) waits for Alice's first message with Alice's ratchet key
      this.dhrr = null;
      this.cks = null;
      this.ckr = null;
    }
  }

  /**
   * Encrypts an outgoing message and ratchets the sending symmetric chain forward
   */
  encrypt(plaintext: string): EncryptedMessagePayload {
    if (!this.cks) {
      throw new Error('Sending chain key not initialized');
    }

    // Advance sending chain key: [CKs_next, MK] = KDF_CK(CKs)
    const [nextCks, messageKey] = deriveTwoKeys(this.cks, ZERO_SALT, INFO_CK);
    this.cks = nextCks;

    const header: RatchetHeader = {
      ratchetKey: toBase64(this.dhrs.publicKey),
      messageNumber: this.ns,
      previousChainLength: this.pn,
    };

    // Encrypt payload with derived ephemeral message key
    const headerBytes = new TextEncoder().encode(JSON.stringify(header));
    const { ciphertext, nonce } = encryptAEAD(messageKey, plaintext, headerBytes);

    this.ns++;

    return {
      header,
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
    };
  }

  /**
   * Decrypts an incoming message, performing a DH ratchet step if the remote
   * key rotated.
   *
   * Security properties enforced here:
   *  - All key derivation happens against local copies; `this` is mutated ONLY
   *    after the AEAD tag verifies. A forged or corrupted packet therefore
   *    cannot desynchronize (and thereby permanently break) the session.
   *  - The number of message keys derived to catch up a chain is bounded by
   *    MAX_SKIP, so an attacker cannot force an unbounded KDF loop.
   *  - Message keys skipped by out-of-order delivery are retained and reused,
   *    so genuinely reordered / duplicated messages still decrypt.
   */
  decrypt(payload: EncryptedMessagePayload): string {
    const remoteRatchetKey = fromBase64(payload.header.ratchetKey);
    const headerBytes = new TextEncoder().encode(JSON.stringify(payload.header));
    const nonce = fromBase64(payload.nonce);
    const ciphertext = fromBase64(payload.ciphertext);
    const remoteHex = toHex(remoteRatchetKey);
    const msgNum = payload.header.messageNumber;
    const prevChainLen = payload.header.previousChainLength;

    if (
      !Number.isInteger(msgNum) || msgNum < 0 ||
      !Number.isInteger(prevChainLen) || prevChainLen < 0
    ) {
      throw new Error('Malformed ratchet header');
    }

    // 1. A message key we already skipped past — handles out-of-order and
    //    duplicate delivery without disturbing live ratchet state.
    const directId = `${remoteHex}:${msgNum}`;
    const preSkipped = this.skippedKeys.get(directId);
    if (preSkipped) {
      // Throws on a bad tag before any state change.
      const pt = decryptAEAD(preSkipped, nonce, ciphertext, headerBytes);
      this.skippedKeys.delete(directId);
      return pt;
    }

    const isNewRemoteKey = !this.dhrr || remoteHex !== toHex(this.dhrr);

    // 2. Derive everything against locals.
    let rk = this.rk;
    let ckr = this.ckr;
    let cks = this.cks;
    let dhrsPriv = this.dhrs.privateKey;
    let dhrsPub = this.dhrs.publicKey;
    let dhrr = this.dhrr;
    let ns = this.ns;
    let nr = this.nr;
    let pn = this.pn;
    let ratchetStepCount = this.ratchetStepCount;
    const newlySkipped: Array<[string, Uint8Array]> = [];

    const drainChain = (
      fromN: number,
      untilN: number,
      chainKey: Uint8Array,
      chainHex: string
    ): Uint8Array => {
      if (untilN - fromN > MAX_SKIP) {
        throw new Error(
          `Refusing to skip ${untilN - fromN} messages (max ${MAX_SKIP}) — possible DoS`
        );
      }
      let ck = chainKey;
      for (let n = fromN; n < untilN; n++) {
        const [nextCk, mk] = deriveTwoKeys(ck, ZERO_SALT, INFO_CK);
        ck = nextCk;
        newlySkipped.push([`${chainHex}:${n}`, mk]);
      }
      return ck;
    };

    if (isNewRemoteKey) {
      // Finish the current receiving chain up to the count the sender reports.
      if (ckr && dhrr) {
        ckr = drainChain(nr, prevChainLen, ckr, toHex(dhrr));
      }

      pn = ns;
      ns = 0;
      nr = 0;
      dhrr = remoteRatchetKey;

      // DH Ratchet Step 1: derive receiving chain
      const [rk1, ckr1] = deriveTwoKeys(computeDH(dhrsPriv, remoteRatchetKey), rk, INFO_RK);
      rk = rk1;
      ckr = ckr1;

      // DH Ratchet Step 2: fresh keypair, derive sending chain
      const fresh = generateDHKeyPair();
      dhrsPriv = fresh.privateKey;
      dhrsPub = fresh.publicKey;
      const [rk2, cks2] = deriveTwoKeys(computeDH(dhrsPriv, remoteRatchetKey), rk, INFO_RK);
      rk = rk2;
      cks = cks2;

      ratchetStepCount++;
    }

    if (!ckr) {
      throw new Error('Receive chain key not initialized');
    }

    // Catch up within the (possibly new) receiving chain.
    ckr = drainChain(nr, msgNum, ckr, remoteHex);
    nr = msgNum;

    const [ckrAfter, messageKey] = deriveTwoKeys(ckr, ZERO_SALT, INFO_CK);

    // 3. Verify + decrypt BEFORE committing anything.
    const plaintext = decryptAEAD(messageKey, nonce, ciphertext, headerBytes);

    // 4. Commit.
    this.rk = rk;
    this.ckr = ckrAfter;
    this.cks = cks;
    this.dhrs = { privateKey: dhrsPriv, publicKey: dhrsPub };
    this.dhrr = dhrr;
    this.ns = ns;
    this.nr = nr + 1;
    this.pn = pn;
    this.ratchetStepCount = ratchetStepCount;
    for (const [id, mk] of newlySkipped) {
      this.storeSkippedKey(id, mk);
    }

    return plaintext;
  }

  private storeSkippedKey(id: string, mk: Uint8Array) {
    this.skippedKeys.set(id, mk);
    while (this.skippedKeys.size > MAX_SKIPPED_KEYS) {
      const oldest = this.skippedKeys.keys().next().value;
      if (oldest === undefined) break;
      this.skippedKeys.delete(oldest);
    }
  }

  /**
   * Serializes current ratchet state for persistent storage
   */
  exportState(): DoubleRatchetStateExport {
    return {
      dhrs: {
        publicKey: toBase64(this.dhrs.publicKey),
        privateKey: toBase64(this.dhrs.privateKey),
      },
      dhrr: this.dhrr ? toBase64(this.dhrr) : null,
      rk: toBase64(this.rk),
      cks: this.cks ? toBase64(this.cks) : null,
      ckr: this.ckr ? toBase64(this.ckr) : null,
      ns: this.ns,
      nr: this.nr,
      pn: this.pn,
      ratchetStepCount: this.ratchetStepCount,
      skippedKeys: Array.from(this.skippedKeys.entries()).map(
        ([k, v]) => [k, toBase64(v)] as [string, string]
      ),
    };
  }

  /**
   * Restores ratchet state from serialized export
   */
  static fromState(state: DoubleRatchetStateExport): DoubleRatchetSession {
    const session = new DoubleRatchetSession(false, fromBase64(state.rk));
    session.dhrs = {
      publicKey: fromBase64(state.dhrs.publicKey),
      privateKey: fromBase64(state.dhrs.privateKey),
    };
    session.dhrr = state.dhrr ? fromBase64(state.dhrr) : null;
    session.cks = state.cks ? fromBase64(state.cks) : null;
    session.ckr = state.ckr ? fromBase64(state.ckr) : null;
    session.ns = state.ns;
    session.nr = state.nr;
    session.pn = state.pn;
    session.ratchetStepCount = state.ratchetStepCount;
    if (Array.isArray(state.skippedKeys)) {
      for (const [k, v] of state.skippedKeys) {
        session.skippedKeys.set(k, fromBase64(v));
      }
    }
    return session;
  }

  /**
   * Inspection metadata for live UI verification
   */
  getStateSummary(): RatchetStateSummary {
    return {
      ratchetStep: this.ratchetStepCount,
      ourRatchetPublicKey: toHex(this.dhrs.publicKey).slice(0, 16) + '...',
      theirRatchetPublicKey: this.dhrr ? toHex(this.dhrr).slice(0, 16) + '...' : 'Pending First Turn',
      rootKeyPreview: toHex(this.rk).slice(0, 16) + '...',
      sendChainLength: this.ns,
      recvChainLength: this.nr,
    };
  }
}
