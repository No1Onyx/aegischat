import { Phone, PhoneOff, Video, ShieldCheck } from 'lucide-react';
import type { CallType } from '../crypto/webrtcManager';

interface IncomingCallModalProps {
  caller: string;
  callType: CallType;
  onAccept: () => void;
  onDecline: () => void;
}

export function IncomingCallModal({
  caller,
  callType,
  onAccept,
  onDecline,
}: IncomingCallModalProps) {
  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 select-none">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-sm w-full p-6 text-center space-y-6 shadow-2xl animate-scaleUp">
        {/* Pulsing Avatar */}
        <div className="relative inline-flex items-center justify-center">
          <div className="absolute w-24 h-24 rounded-full bg-sky-500/20 animate-ping opacity-75" />
          <div className="w-20 h-20 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center text-2xl font-bold text-white shadow-xl relative z-10">
            {caller.charAt(0)}
          </div>
        </div>

        {/* Call Info */}
        <div className="space-y-1.5">
          <div className="text-xl font-bold text-white">{caller}</div>
          <div className="text-xs text-sky-400 font-semibold uppercase tracking-wider flex items-center justify-center gap-1.5">
            {callType === 'video' ? <Video className="w-3.5 h-3.5" /> : <Phone className="w-3.5 h-3.5" />}
            <span>Incoming End-to-End Encrypted {callType === 'video' ? 'Video' : 'Voice'} Call</span>
          </div>
          <div className="flex items-center justify-center gap-1 text-[11px] text-slate-400">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>P2P Direct · Key Ratchet Protected</span>
          </div>
        </div>

        {/* Actions: Decline / Accept */}
        <div className="flex items-center justify-center gap-8 pt-2">
          {/* Decline */}
          <div className="flex flex-col items-center gap-1.5">
            <button
              type="button"
              onClick={onDecline}
              className="w-14 h-14 rounded-full bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center shadow-lg shadow-rose-950/50 hover:scale-110 active:scale-95 transition-all"
            >
              <PhoneOff className="w-6 h-6" />
            </button>
            <span className="text-[11px] text-slate-400 font-medium">Decline</span>
          </div>

          {/* Accept */}
          <div className="flex flex-col items-center gap-1.5">
            <button
              type="button"
              onClick={onAccept}
              className="w-14 h-14 rounded-full bg-emerald-600 hover:bg-emerald-500 text-white flex items-center justify-center shadow-lg shadow-emerald-950/50 hover:scale-110 active:scale-95 transition-all"
            >
              <Phone className="w-6 h-6" />
            </button>
            <span className="text-[11px] text-slate-400 font-medium">Accept</span>
          </div>
        </div>
      </div>
    </div>
  );
}
