import React, { useState } from 'react';
import { ShieldCheck, CheckCircle2, Copy, Check, QrCode, AlertTriangle } from 'lucide-react';

interface SafetyNumberModalProps {
  currentUser: string;
  peerUser: string;
  safetyNumber: { formatted: string[]; rawHash: string } | null;
  isVerified: boolean;
  onToggleVerify: () => void;
  onClose: () => void;
}

export const SafetyNumberModal: React.FC<SafetyNumberModalProps> = ({
  currentUser,
  peerUser,
  safetyNumber,
  isVerified,
  onToggleVerify,
  onClose,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!safetyNumber) return;
    navigator.clipboard.writeText(safetyNumber.formatted.join(' '));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative text-slate-200">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1"
        >
          ✕
        </button>

        <div className="flex items-center gap-3 pb-4 border-b border-slate-800">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-lg text-white">Verify Safety Number</h3>
            <p className="text-xs text-slate-400">Identity Fingerprint between {currentUser} and {peerUser}</p>
          </div>
        </div>

        {!safetyNumber ? (
          <div className="py-8 text-center text-slate-500">
            <AlertTriangle className="w-10 h-10 mx-auto mb-2 text-amber-500/80" />
            <p className="text-sm">No session established yet with {peerUser}.</p>
            <p className="text-xs mt-1 text-slate-600">Send an initial message to compute the mutual identity fingerprint.</p>
          </div>
        ) : (
          <div className="mt-4 space-y-4">
            <p className="text-xs text-slate-400 leading-relaxed">
              Compare this 60-digit number with the safety number on <strong>{peerUser}</strong>'s screen (e.g. over a phone call, in person, or via QR code). If they match, your connection is guaranteed to be free of Man-in-the-Middle eavesdropping.
            </p>

            {/* QR Mock / Visual Hash matrix */}
            <div className="flex items-center justify-center py-2">
              <div className="p-3 bg-white rounded-xl shadow-inner flex items-center justify-center">
                <QrCode className="w-28 h-28 text-slate-950" />
              </div>
            </div>

            {/* 12 Blocks of 5 digits */}
            <div className="grid grid-cols-3 gap-2 bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-center text-sm font-semibold tracking-wider text-emerald-300">
              {safetyNumber.formatted.map((block, idx) => (
                <div key={idx} className="bg-slate-900/80 py-1 px-2 rounded border border-slate-800/80">
                  {block}
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy fingerprint'}</span>
              </button>

              <button
                onClick={onToggleVerify}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
                  isVerified
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>{isVerified ? 'Marked as Verified' : 'Mark as Verified'}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
