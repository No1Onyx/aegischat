import { useState, useRef, useEffect } from 'react';
import { Palette, Check } from 'lucide-react';
import { THEMES } from '../theme/themeConfig';
import type { AppTheme } from '../theme/themeConfig';

interface ThemeSelectorProps {
  currentTheme: AppTheme;
  onSelectTheme: (theme: AppTheme) => void;
}

export function ThemeSelector({ currentTheme, onSelectTheme }: ThemeSelectorProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const dropdownRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-all flex items-center gap-1 text-xs"
        title="Switch Telegram / OLED Themes"
      >
        <Palette className="w-4 h-4" />
      </button>

      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-48 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-1.5 z-50 space-y-1 animate-fadeIn">
          <div className="px-2.5 py-1 text-[10px] uppercase font-bold text-slate-500 tracking-wider">
            Display Theme
          </div>

          {(Object.keys(THEMES) as AppTheme[]).map((themeKey) => {
            const theme = THEMES[themeKey];
            const isSelected = currentTheme === themeKey;

            return (
              <button
                key={themeKey}
                type="button"
                onClick={() => {
                  onSelectTheme(themeKey);
                  setIsOpen(false);
                }}
                className={`w-full px-2.5 py-2 rounded-xl text-xs flex items-center justify-between transition-all ${
                  isSelected
                    ? 'bg-sky-600/20 text-sky-300 font-semibold'
                    : 'text-slate-300 hover:bg-slate-800'
                }`}
              >
                <span>{theme.name}</span>
                {isSelected && <Check className="w-3.5 h-3.5 text-sky-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
