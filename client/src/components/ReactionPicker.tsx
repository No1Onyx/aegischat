interface ReactionPickerProps {
  onSelectReaction: (emoji: string) => void;
  onClose?: () => void;
  isSender: boolean;
}

const EMOJIS = ['👍', '❤️', '🔥', '🛡️', '⚡', '🎉'];

export function ReactionPicker({ onSelectReaction, onClose, isSender }: ReactionPickerProps) {
  return (
    <div
      className={`flex items-center gap-1 bg-slate-900/95 border border-slate-700/80 rounded-full px-2 py-1 shadow-2xl backdrop-blur-md animate-fadeIn select-none z-30 ${
        isSender ? 'right-0' : 'left-0'
      }`}
      onClick={(e) => e.stopPropagation()}
    >
      {EMOJIS.map((emoji) => (
        <button
          key={emoji}
          type="button"
          onClick={() => {
            onSelectReaction(emoji);
            onClose?.();
          }}
          className="w-7 h-7 flex items-center justify-center hover:scale-130 active:scale-95 transition-transform text-sm hover:bg-white/10 rounded-full"
        >
          {emoji}
        </button>
      ))}
    </div>
  );
}
