import { useState } from 'react';
import { Flame, Check } from 'lucide-react';

interface DisappearingTimerDropdownProps {
  currentTimerSec: number;
  onSelectTimer: (seconds: number) => void;
}

export const TIMER_OPTIONS = [
  { label: 'Off', seconds: 0 },
  { label: '30 Seconds', seconds: 30 },
  { label: '5 Minutes', seconds: 300 },
  { label: '1 Hour', seconds: 3600 },
  { label: '24 Hours', seconds: 86400 },
];

export function DisappearingTimerDropdown({
  currentTimerSec,
  onSelectTimer,
}: DisappearingTimerDropdownProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);

  const activeOption = TIMER_OPTIONS.find((opt) => opt.seconds === currentTimerSec) || TIMER_OPTIONS[0];

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`px-2.5 py-1.5 rounded-xl border text-xs font-medium flex items-center gap-1.5 transition-all ${
          currentTimerSec > 0
            ? 'bg-amber-950/40 border-amber-800/60 text-amber-300 shadow-sm'
            : 'bg-slate-800/80 border-slate-700/80 text-slate-400 hover:text-slate-200'
        }`}
        title="Disappearing Messages Timer"
      >
        <Flame className={`w-3.5 h-3.5 ${currentTimerSec > 0 ? 'text-amber-400 animate-pulse' : 'text-slate-400'}`} />
        <span>{currentTimerSec > 0 ? activeOption.label : 'Timer Off'}</span>
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 mt-1.5 w-44 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-1.5 z-50 space-y-0.5">
            <div className="px-2.5 py-1 text-[10px] uppercase font-bold text-slate-500 tracking-wider">
              Disappearing Messages
            </div>
            {TIMER_OPTIONS.map((opt) => (
              <button
                key={opt.seconds}
                onClick={() => {
                  onSelectTimer(opt.seconds);
                  setIsOpen(false);
                }}
                className={`w-full px-2.5 py-1.5 rounded-xl text-xs flex items-center justify-between transition-all ${
                  currentTimerSec === opt.seconds
                    ? 'bg-sky-600 text-white font-medium'
                    : 'text-slate-300 hover:bg-slate-800'
                }`}
              >
                <span>{opt.label}</span>
                {currentTimerSec === opt.seconds && <Check className="w-3.5 h-3.5 text-white" />}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
