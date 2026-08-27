import React, { useState } from 'react';
import {
  Shield,
  Key,
  AlertTriangle,
  Flame,
  X,
  Copy,
  Check,
  Trash2,
  Clock,
} from 'lucide-react';
import { VaultSecurityManager } from '../crypto/vault';

interface SecuritySettingsModalProps {
  onClose: () => void;
  onEmergencyShred: () => void;
}

export function SecuritySettingsModal({ onClose, onEmergencyShred }: SecuritySettingsModalProps) {
  const config = VaultSecurityManager.getConfig();
  const [seedAuthPassword, setSeedAuthPassword] = useState<string>('');
  const [seedError, setSeedError] = useState<string>('');
  const [isSeedRevealed, setIsSeedRevealed] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [confirmShred, setConfirmShred] = useState<boolean>(false);

  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(config?.autoLockMinutes || 10);
  // The duress phrase is stored only as a hash; this field sets a NEW one
  // (leave blank to keep the current phrase).
  const [duressCode, setDuressCode] = useState<string>('');
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  const handleRevealSeed = (e: React.FormEvent) => {
    e.preventDefault();
    setSeedError('');

    const res = VaultSecurityManager.verifyPassword(seedAuthPassword);
    if (res.success) {
      setIsSeedRevealed(true);
      setSeedAuthPassword('');
    } else {
      setSeedError('Incorrect password');
    }
  };

  const handleSaveSettings = () => {
    if (!config) return;
    config.autoLockMinutes = autoLockMinutes;
    VaultSecurityManager.saveConfig(config);
    if (duressCode.trim()) {
      VaultSecurityManager.setDuressPhrase(duressCode.trim());
      setDuressCode('');
    }
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2000);
  };

  const handleExecutePanicShred = () => {
    VaultSecurityManager.emergencyShred();
    onEmergencyShred();
  };

  const words = (VaultSecurityManager.getMnemonic() || '').split(' ').filter(Boolean);

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-lg w-full p-6 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-sky-500/20 text-sky-400 border border-sky-500/30 rounded-xl">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">Security & Privacy Vault</h3>
              <p className="text-xs text-slate-400">Anti-Forensic Controls</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* 1. Recovery Seed Phrase Backup */}
        <div className="bg-slate-950/80 p-4 rounded-2xl border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-sky-400" />
              <span>12-Word Recovery Seed Phrase</span>
            </span>
            <span className="text-[10px] text-emerald-400 font-mono bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800/40">
              Zero-Anchor
            </span>
          </div>

          {!isSeedRevealed ? (
            <form onSubmit={handleRevealSeed} className="space-y-2">
              <p className="text-[11px] text-slate-400">
                Enter your Master Passphrase to view your 12 recovery words.
              </p>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={seedAuthPassword}
                  onChange={(e) => setSeedAuthPassword(e.target.value)}
                  placeholder="Master Passphrase"
                  className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs rounded-xl"
                >
                  Reveal
                </button>
              </div>
              {seedError && <p className="text-[10px] text-rose-400">{seedError}</p>}
            </form>
          ) : (
            <div className="space-y-2.5">
              <div className="grid grid-cols-3 gap-1.5 bg-slate-900 p-2.5 rounded-xl border border-slate-800/80">
                {words.map((word, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-1 bg-slate-950 px-2 py-1 rounded text-[11px] font-mono text-sky-300"
                  >
                    <span className="text-slate-500 text-[9px]">{idx + 1}.</span>
                    <span>{word}</span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(VaultSecurityManager.getMnemonic() || '');
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg text-[11px] text-slate-300 flex items-center gap-1.5"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIsSeedRevealed(false)}
                  className="text-[11px] text-slate-400 hover:text-slate-200"
                >
                  Hide Words
                </button>
              </div>
            </div>
          )}
        </div>

        {/* 2. Auto-Lock Timeout */}
        <div className="bg-slate-950/80 p-4 rounded-2xl border border-slate-800 space-y-2">
          <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-sky-400" />
            <span>Auto-Lock on Inactivity</span>
          </label>
          <p className="text-[11px] text-slate-400">
            Locks the app and wipes memory keys when idle.
          </p>
          <select
            value={autoLockMinutes}
            onChange={(e) => setAutoLockMinutes(Number(e.target.value))}
            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
          >
            <option value={1}>1 Minute</option>
            <option value={5}>5 Minutes</option>
            <option value={10}>10 Minutes (Default)</option>
            <option value={30}>30 Minutes</option>
            <option value={0}>Never Auto-Lock</option>
          </select>
        </div>

        {/* 3. Duress Code Setting */}
        <div className="bg-slate-950/80 p-4 rounded-2xl border border-slate-800 space-y-2">
          <label className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Duress PIN (Panic Wipe Trigger)</span>
          </label>
          <p className="text-[11px] text-slate-400">
            Entering this PIN on the lock screen instantly shreds all chat history.
          </p>
          <input
            type="text"
            value={duressCode}
            onChange={(e) => setDuressCode(e.target.value)}
            placeholder="e.g. 9999 (Leave empty to disable)"
            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-rose-200 focus:outline-none focus:border-rose-500"
          />
        </div>

        {/* Save button */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={handleSaveSettings}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs rounded-xl shadow-md transition-all"
          >
            {saveSuccess ? 'Saved ✓' : 'Save Security Settings'}
          </button>
        </div>

        {/* 4. EMERGENCY PANIC SHRED BUTTON */}
        <div className="p-4 bg-rose-950/40 border border-rose-900/60 rounded-2xl space-y-3">
          <div className="flex items-center gap-2 text-rose-300 font-bold text-xs">
            <Flame className="w-4 h-4 text-rose-400" />
            <span>Emergency Panic Shred</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Irreversibly destroys all encryption keys, Double Ratchet sessions, and chat logs from this device.
          </p>

          {!confirmShred ? (
            <button
              type="button"
              onClick={() => setConfirmShred(true)}
              className="w-full py-2 px-3 bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs rounded-xl flex items-center justify-center gap-1.5 transition-all shadow-md shadow-rose-950"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Shred All Data Immediately</span>
            </button>
          ) : (
            <div className="space-y-2 bg-rose-950 p-3 rounded-xl border border-rose-800">
              <p className="text-xs font-bold text-white text-center">
                ARE YOU ABSOLUTELY SURE? CANNOT BE UNDONE!
              </p>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={handleExecutePanicShred}
                  className="py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-lg"
                >
                  YES, SHRED NOW
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmShred(false)}
                  className="py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
