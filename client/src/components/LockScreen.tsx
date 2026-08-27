import React, { useState } from 'react';
import { Lock, AlertTriangle, ArrowRight } from 'lucide-react';
import { VaultSecurityManager } from '../crypto/vault';

interface LockScreenProps {
  username: string;
  onUnlock: () => void;
  onDuressShred: () => void;
}

export function LockScreen({ username, onUnlock, onDuressShred }: LockScreenProps) {
  const [password, setPassword] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [isShredding, setIsShredding] = useState<boolean>(false);
  const [isUnlocking, setIsUnlocking] = useState<boolean>(false);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (isUnlocking) return;
    setIsUnlocking(true);

    try {
      const result = await VaultSecurityManager.verifyPassword(password);

      if (result.isDuress) {
        // DURESS TRIGGERED: Instant Emergency Cryptographic Shred!
        setIsShredding(true);
        setTimeout(() => {
          VaultSecurityManager.emergencyShred();
          onDuressShred();
        }, 600);
        return;
      }

      if (result.success) {
        onUnlock();
      } else {
        setError('Incorrect Passphrase.');
        setPassword('');
      }
    } finally {
      setIsUnlocking(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950 flex flex-col items-center justify-center p-4 select-none">
      {/* Ambient background glow */}
      <div className="absolute w-96 h-96 bg-sky-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl text-center space-y-6 relative z-10">
        {/* Shield Icon */}
        <div className="w-16 h-16 mx-auto rounded-2xl bg-sky-500/20 text-sky-400 border border-sky-500/30 flex items-center justify-center shadow-lg shadow-sky-950">
          {isShredding ? (
            <AlertTriangle className="w-8 h-8 text-rose-400 animate-pulse" />
          ) : (
            <Lock className="w-8 h-8 text-sky-400" />
          )}
        </div>

        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            {isShredding ? 'Executing Duress Shred...' : 'AegisChat Locked'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            {isShredding
              ? 'Wiping all private keys and encrypted messages from disk.'
              : `Identity: ${username}`}
          </p>
        </div>

        {error && (
          <div className="p-2.5 rounded-xl bg-rose-950/70 border border-rose-800 text-rose-300 text-xs flex items-center justify-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {!isShredding && (
          <form onSubmit={handleUnlock} className="space-y-4">
            <div className="relative flex items-center">
              <input
                type="password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter master passphrase..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-center text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-all font-mono shadow-inner"
              />
            </div>

            <button
              type="submit"
              disabled={!password || isUnlocking}
              className={`w-full py-3 rounded-xl font-semibold text-xs flex items-center justify-center gap-2 transition-all ${
                password && !isUnlocking
                  ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-950 hover:scale-[1.02]'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed'
              }`}
            >
              <span>{isUnlocking ? 'Deriving key (Argon2id)…' : 'Unlock Vault'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        )}

        <p className="text-[10px] text-slate-400 leading-relaxed max-w-xs mx-auto">
          Argon2id Memory-Hard Key Derivation · Anti-Tamper Verification
        </p>
      </div>
    </div>
  );
}
