import { Pin, X } from 'lucide-react';
import type { ChatMessage } from '../crypto/sessionManager';

interface PinnedMessageBannerProps {
  pinnedMessage: ChatMessage;
  onJumpToMessage: (msgId: string) => void;
  onUnpin: (msgId: string) => void;
}

export function PinnedMessageBanner({
  pinnedMessage,
  onJumpToMessage,
  onUnpin,
}: PinnedMessageBannerProps) {
  const preview = pinnedMessage.text || pinnedMessage.attachment?.fileName || 'Attachment';

  return (
    <div
      onClick={() => onJumpToMessage(pinnedMessage.id)}
      className="px-6 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between gap-3 text-xs cursor-pointer hover:bg-slate-800/80 transition-all z-10 backdrop-blur-md"
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="p-1 rounded-md bg-sky-500/20 text-sky-400">
          <Pin className="w-3.5 h-3.5 fill-current" />
        </div>
        <div className="min-w-0">
          <div className="text-[10px] font-bold text-sky-400 uppercase tracking-wider">
            Pinned Message ({pinnedMessage.sender})
          </div>
          <div className="text-xs text-slate-200 truncate">{preview}</div>
        </div>
      </div>

      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onUnpin(pinnedMessage.id);
        }}
        className="p-1 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
        title="Unpin message"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
