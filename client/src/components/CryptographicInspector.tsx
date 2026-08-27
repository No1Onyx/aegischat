import React from 'react';
import { ShieldCheck, KeyRound, RefreshCw, Lock, ArrowRightLeft, Info } from 'lucide-react';
import type { RatchetStateSummary } from '../crypto/doubleRatchet';

interface CryptographicInspectorProps {
  summary: RatchetStateSummary | null;
  currentUser: string;
  peerUser: string;
  onClose: () => void;
}

export const CryptographicInspector: React.FC<CryptographicInspectorProps> = ({
  summary,
  currentUser,
  peerUser,
  onClose,
}) => {
  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-slate-900 border-l border-slate-800 shadow-2xl z-50 flex flex-col p-6 text-slate-200 overflow-y-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2 text-sky-400 font-bold text-lg">
          <ShieldCheck className="w-6 h-6 text-sky-400" />
          <span>Double Ratchet Inspector</span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white p-1 rounded-md transition-colors"
        >
          ✕
        </button>
      </div>

      {!summary ? (
        <div className="py-12 text-center text-slate-500">
          <KeyRound className="w-12 h-12 mx-auto mb-3 opacity-40 text-slate-400 animate-pulse" />
          <p>No active cryptographic session initialized with {peerUser}.</p>
          <p className="text-xs mt-2 text-slate-600">Send or receive a message to trigger X3DH & ratchet key agreement.</p>
        </div>
      ) : (
        <div className="mt-4 space-y-5">
          {/* Status Badge */}
          <div className="bg-sky-950/40 border border-sky-800/60 rounded-xl p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/20 text-sky-400">
              <RefreshCw className="w-5 h-5 animate-spin" style={{ animationDuration: '6s' }} />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                Ratchet Step #{summary.ratchetStep}
              </div>
              <div className="text-sm font-medium text-slate-300">
                Forward & Future Secrecy Active
              </div>
            </div>
          </div>

          {/* Root Key */}
          <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-amber-400" /> Current Root Key (RK)
              </span>
              <span className="text-[10px] bg-amber-950/80 text-amber-300 px-2 py-0.5 rounded-full border border-amber-800/50">
                Rotates per turn
              </span>
            </div>
            <div className="font-mono text-xs text-amber-200/90 break-all bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
              {summary.rootKeyPreview}
            </div>
          </div>

          {/* Diffie-Hellman Ratchet Keys */}
          <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 space-y-3">
            <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <ArrowRightLeft className="w-3.5 h-3.5 text-indigo-400" />
              <span>Diffie-Hellman Ratchet Keys</span>
            </div>

            <div className="space-y-2">
              <div>
                <span className="text-[11px] text-slate-500 uppercase tracking-wider">
                  {currentUser}'s Ratchet PubKey (DHRs):
                </span>
                <div className="font-mono text-xs text-indigo-300 break-all bg-slate-900/90 p-2 rounded border border-slate-800">
                  {summary.ourRatchetPublicKey}
                </div>
              </div>

              <div>
                <span className="text-[11px] text-slate-500 uppercase tracking-wider">
                  {peerUser}'s Ratchet PubKey (DHRr):
                </span>
                <div className="font-mono text-xs text-emerald-300 break-all bg-slate-900/90 p-2 rounded border border-slate-800">
                  {summary.theirRatchetPublicKey}
                </div>
              </div>
            </div>
          </div>

          {/* Chain States */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-3.5">
              <div className="text-[11px] text-slate-500 uppercase font-semibold">Send Chain</div>
              <div className="text-xl font-bold text-sky-400 mt-1">{summary.sendChainLength} msgs</div>
              <div className="text-[10px] text-slate-500 mt-0.5">KDF symmetric iterations</div>
            </div>
            <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-3.5">
              <div className="text-[11px] text-slate-500 uppercase font-semibold">Recv Chain</div>
              <div className="text-xl font-bold text-emerald-400 mt-1">{summary.recvChainLength} msgs</div>
              <div className="text-[10px] text-slate-500 mt-0.5">KDF symmetric iterations</div>
            </div>
          </div>

          {/* Educational Note */}
          <div className="bg-slate-800/40 rounded-xl p-4 text-xs text-slate-400 space-y-1.5 border border-slate-700/50">
            <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
              <Info className="w-4 h-4 text-sky-400" />
              <span>How does the encryption work?</span>
            </div>
            <p className="leading-relaxed">
              Every message is encrypted with an ephemeral one-time key derived via HKDF. Even if an attacker steals your device tomorrow, past messages remain permanently indecipherable (<strong>Forward Secrecy</strong>).
            </p>
            <p className="leading-relaxed pt-1">
              Whenever the speaking turn alternates, a new Diffie-Hellman exchange regenerates the Root Key (<strong>Break-in Recovery</strong>).
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
