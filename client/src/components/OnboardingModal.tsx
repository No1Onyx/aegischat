import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Copy,
  Check,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  UserCheck,
} from 'lucide-react';
import { VaultSecurityManager } from '../crypto/vault';

interface OnboardingModalProps {
  onComplete: (username: string) => void;
}

export function OnboardingModal({ onComplete }: OnboardingModalProps) {
  const [step, setStep] = useState<number>(1);
  const [isRestoring, setIsRestoring] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [mnemonic, setMnemonic] = useState<string>('');
  const [restoreInput, setRestoreInput] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [duressCode, setDuressCode] = useState<string>('');
  const [hasBackedUp, setHasBackedUp] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    // Generate fresh 12-word phrase
    setMnemonic(VaultSecurityManager.generateNewMnemonic());
  }, []);

  const handleCopyMnemonic = () => {
    navigator.clipboard.writeText(mnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRegenerateMnemonic = () => {
    setMnemonic(VaultSecurityManager.generateNewMnemonic());
    setHasBackedUp(false);
  };

  const [isBusy, setIsBusy] = useState<boolean>(false);

  const handleFinishOnboarding = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (isBusy) return;

    if (!username.trim()) {
      setError('Please choose a username/handle.');
      return;
    }

    if (password.length < 6) {
      setError('Master Passphrase must be at least 6 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (duressCode.trim() && duressCode.trim() === password.trim()) {
      setError('Duress PIN cannot be the same as your Master Password!');
      return;
    }

    const finalMnemonic = isRestoring ? restoreInput.trim() : mnemonic;

    if (!VaultSecurityManager.isValidMnemonic(finalMnemonic)) {
      setError('Invalid 12-word recovery phrase. Please verify the words.');
      return;
    }

    setIsBusy(true);
    try {
      await VaultSecurityManager.initializeVault(
        username.trim(),
        finalMnemonic,
        password,
        duressCode.trim()
      );
      onComplete(username.trim());
    } catch (err) {
      setError('Could not create the vault: ' + (err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const words = mnemonic.split(' ');

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-lg w-full p-6 sm:p-8 shadow-2xl space-y-6 relative overflow-hidden">
        {/* Ambient Glow */}
        <div className="absolute -top-24 -left-24 w-60 h-60 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -right-24 w-60 h-60 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-3 bg-sky-500/20 text-sky-400 border border-sky-500/30 rounded-2xl">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              AegisChat Setup
              <span className="text-[10px] bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800/60 font-mono">
                Zero-Anchor
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              No Phone · No Email · Mathematical Freedom of Speech
            </p>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* STEP 1: Secret Recovery Phrase (or Restore) */}
        {step === 1 && !isRestoring && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-200">
                1. Your 12-Word Cryptographic Identity
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Because there is no central database, phone number, or email, this 12-word phrase is your entire key. Never share it with anyone.
              </p>
            </div>

            {/* 12-Word Grid */}
            <div className="grid grid-cols-3 gap-2 bg-slate-950/80 p-3.5 rounded-2xl border border-slate-800">
              {words.map((word, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-1.5 bg-slate-900/90 px-2.5 py-1.5 rounded-lg border border-slate-800/80 text-xs font-mono"
                >
                  <span className="text-slate-500 text-[10px] select-none">{idx + 1}.</span>
                  <span className="text-sky-300 font-medium">{word}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={handleCopyMnemonic}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-xl text-xs text-slate-300 font-medium flex items-center gap-1.5 transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied to Clipboard' : 'Copy Words'}</span>
              </button>

              <button
                type="button"
                onClick={handleRegenerateMnemonic}
                className="px-3 py-1.5 hover:bg-slate-800 rounded-xl text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-all"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>New Phrase</span>
              </button>
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer pt-2">
              <input
                type="checkbox"
                checked={hasBackedUp}
                onChange={(e) => setHasBackedUp(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500 focus:ring-offset-0"
              />
              <span className="text-xs text-slate-300 select-none">
                I have safely written down or backed up these 12 words offline.
              </span>
            </label>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => setIsRestoring(true)}
                className="text-xs text-sky-400 hover:underline"
              >
                Restore existing account
              </button>

              <button
                type="button"
                disabled={!hasBackedUp}
                onClick={() => {
                  setError('');
                  setStep(2);
                }}
                className={`px-5 py-2.5 rounded-xl font-semibold text-xs flex items-center gap-2 transition-all ${
                  hasBackedUp
                    ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-900/50'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                <span>Continue</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* RESTORE TAB */}
        {step === 1 && isRestoring && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-200">
                Restore from 12-Word Secret Phrase
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Paste or type your 12 recovery words separated by spaces.
              </p>
            </div>

            <textarea
              rows={3}
              value={restoreInput}
              onChange={(e) => setRestoreInput(e.target.value)}
              placeholder="e.g. magic come film anchor front deliver wasp awful you mask cloud enable"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-sky-200 focus:outline-none focus:border-sky-500 transition-all"
            />

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => setIsRestoring(false)}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Back to generate new
              </button>

              <button
                type="button"
                disabled={!restoreInput.trim()}
                onClick={() => {
                  if (!VaultSecurityManager.isValidMnemonic(restoreInput.trim())) {
                    setError('Invalid 12-word mnemonic phrase. Check spelling.');
                    return;
                  }
                  setError('');
                  setStep(2);
                }}
                className={`px-5 py-2.5 rounded-xl font-semibold text-xs flex items-center gap-2 transition-all ${
                  restoreInput.trim()
                    ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-900/50'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                <span>Verify & Continue</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* STEP 2: Passphrase & Duress Mode */}
        {step === 2 && (
          <form onSubmit={handleFinishOnboarding} className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-200">
                2. Set Local Passphrase & Duress PIN
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Your passphrase encrypts your local database with Argon2id.
              </p>
            </div>

            {/* Username */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 flex items-center gap-1">
                <UserCheck className="w-3.5 h-3.5 text-sky-400" />
                <span>Your Display Handle / Username</span>
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. Alice, CipherQueen, Anonymous"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 transition-all"
              />
            </div>

            {/* Master Password */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 flex items-center justify-between">
                <span className="flex items-center gap-1">
                  <Lock className="w-3.5 h-3.5 text-sky-400" />
                  <span>Master App Passphrase (to unlock)</span>
                </span>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-[10px] text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Choose a strong passphrase"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 transition-all"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs text-slate-400">Confirm Passphrase</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter passphrase"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 transition-all"
              />
            </div>

            {/* Duress Code (Anti-Coercion) */}
            <div className="p-3 bg-rose-950/20 border border-rose-900/40 rounded-xl space-y-1.5">
              <label className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                <span>Optional Duress PIN (Panic Button)</span>
              </label>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                If forced under duress to unlock your device, entering this PIN instead will <strong>instantly shred and permanently erase all chats</strong>.
              </p>
              <input
                type="text"
                value={duressCode}
                onChange={(e) => setDuressCode(e.target.value)}
                placeholder="e.g. 9999 or panic-word (Optional)"
                className="w-full bg-slate-950/90 border border-rose-900/50 rounded-xl px-3 py-1.5 text-xs text-rose-200 placeholder-rose-700/50 focus:outline-none focus:border-rose-500 transition-all"
              />
            </div>

            <div className="flex items-center justify-between pt-3">
              <button
                type="button"
                onClick={() => setStep(1)}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Back
              </button>

              <button
                type="submit"
                disabled={isBusy}
                className="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold text-xs shadow-lg shadow-sky-900/50 transition-all hover:scale-105"
              >
                {isBusy ? 'Deriving vault key (Argon2id)…' : 'Complete Setup & Launch'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
