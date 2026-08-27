import { PreKeyBundle } from './types.js';

interface StoredUserKeys {
  username: string;
  identityPublicKey: string;
  signingPublicKey: string;
  signedPreKey: {
    keyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKeys: Map<number, string>; // keyId -> Base64 publicKey
}

export class KeyDirectory {
  private users = new Map<string, StoredUserKeys>();

  registerUser(
    username: string,
    identityPublicKey: string,
    signingPublicKey: string,
    signedPreKey: { keyId: number; publicKey: string; signature: string },
    oneTimePreKeys: Array<{ keyId: number; publicKey: string }>
  ): boolean {
    const opkMap = new Map<number, string>();
    for (const opk of oneTimePreKeys) {
      opkMap.set(opk.keyId, opk.publicKey);
    }

    this.users.set(username.toLowerCase(), {
      username,
      identityPublicKey,
      signingPublicKey,
      signedPreKey,
      oneTimePreKeys: opkMap,
    });

    console.log(`[KeyDirectory] Registered keys for ${username} with ${opkMap.size} one-time prekeys`);
    return true;
  }

  hasUser(username: string): boolean {
    return this.users.has(username.toLowerCase());
  }

  getAllUsers(): string[] {
    return Array.from(this.users.values()).map(u => u.username);
  }

  getKeyBundle(username: string): PreKeyBundle | null {
    const user = this.users.get(username.toLowerCase());
    if (!user) return null;

    let oneTimePreKey: { keyId: number; publicKey: string } | undefined = undefined;

    // Pop one one-time prekey if available (ephemeral guarantee)
    const opkKeys = Array.from(user.oneTimePreKeys.keys());
    if (opkKeys.length > 0) {
      const selectedKeyId = opkKeys[0];
      const pubKey = user.oneTimePreKeys.get(selectedKeyId)!;
      user.oneTimePreKeys.delete(selectedKeyId);
      oneTimePreKey = {
        keyId: selectedKeyId,
        publicKey: pubKey,
      };
      console.log(`[KeyDirectory] Consumed one-time prekey #${selectedKeyId} for ${username} (${user.oneTimePreKeys.size} remaining)`);
    }

    return {
      username: user.username,
      identityPublicKey: user.identityPublicKey,
      signingPublicKey: user.signingPublicKey,
      signedPreKey: user.signedPreKey,
      oneTimePreKey,
    };
  }
}
