import { Search, X, ChevronUp, ChevronDown, Image, Mic } from 'lucide-react';

export type SearchFilterType = 'all' | 'media' | 'voice';

interface ChatSearchBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  filterType: SearchFilterType;
  onFilterTypeChange: (filter: SearchFilterType) => void;
  totalMatches: number;
  currentMatchIndex: number;
  onNextMatch: () => void;
  onPrevMatch: () => void;
  onClose: () => void;
}

export function ChatSearchBar({
  searchQuery,
  onSearchChange,
  filterType,
  onFilterTypeChange,
  totalMatches,
  currentMatchIndex,
  onNextMatch,
  onPrevMatch,
  onClose,
}: ChatSearchBarProps) {
  return (
    <div className="px-6 py-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between gap-3 text-xs animate-fadeIn backdrop-blur-md z-20">
      {/* Search Input */}
      <div className="flex-1 max-w-md relative flex items-center">
        <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
        <input
          type="text"
          autoFocus
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search encrypted messages & attachments..."
          className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-8 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
        />
        {searchQuery && (
          <button
            type="button"
            onClick={() => onSearchChange('')}
            className="absolute right-2.5 text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
        <button
          type="button"
          onClick={() => onFilterTypeChange('all')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
            filterType === 'all'
              ? 'bg-sky-600 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          All
        </button>
        <button
          type="button"
          onClick={() => onFilterTypeChange('media')}
          className={`px-2.5 py-1 rounded-lg font-medium flex items-center gap-1 transition-all ${
            filterType === 'media'
              ? 'bg-sky-600 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Image className="w-3 h-3" />
          <span>Media</span>
        </button>
        <button
          type="button"
          onClick={() => onFilterTypeChange('voice')}
          className={`px-2.5 py-1 rounded-lg font-medium flex items-center gap-1 transition-all ${
            filterType === 'voice'
              ? 'bg-sky-600 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Mic className="w-3 h-3" />
          <span>Voice</span>
        </button>
      </div>

      {/* Match Navigation & Close */}
      <div className="flex items-center gap-2">
        {totalMatches > 0 && (
          <span className="text-[11px] font-mono text-slate-400">
            {currentMatchIndex + 1} of {totalMatches}
          </span>
        )}

        <div className="flex items-center gap-0.5">
          <button
            type="button"
            disabled={totalMatches === 0}
            onClick={onPrevMatch}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white disabled:opacity-30"
          >
            <ChevronUp className="w-4 h-4" />
          </button>
          <button
            type="button"
            disabled={totalMatches === 0}
            onClick={onNextMatch}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white disabled:opacity-30"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-all ml-1"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
