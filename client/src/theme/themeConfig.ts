export type AppTheme = 'telegram' | 'oled' | 'matrix' | 'tactical';

export interface ThemeColors {
  name: string;
  id: AppTheme;
  appBg: string;
  sidebarBg: string;
  chatBg: string;
  topBarBg: string;
  inputBg: string;
  cardBg: string;
  senderBubbleBg: string;
  recipientBubbleBg: string;
  accentText: string;
  accentBg: string;
  border: string;
  badgeBg: string;
}

export const THEMES: Record<AppTheme, ThemeColors> = {
  telegram: {
    name: 'Telegram Dark',
    id: 'telegram',
    appBg: 'bg-[#0e1621]',
    sidebarBg: 'bg-[#17212b]',
    chatBg: 'bg-[#0e1621]',
    topBarBg: 'bg-[#17212b]/95',
    inputBg: 'bg-[#17212b]',
    cardBg: 'bg-[#17212b]',
    senderBubbleBg: 'bg-[#2b5278] text-white',
    recipientBubbleBg: 'bg-[#182533] text-slate-100 border border-[#232e3c]',
    accentText: 'text-[#5288c1]',
    accentBg: 'bg-[#2481cc] hover:bg-[#1d6fa8]',
    border: 'border-[#232e3c]',
    badgeBg: 'bg-[#232e3c]',
  },
  oled: {
    name: 'OLED Midnight',
    id: 'oled',
    appBg: 'bg-[#000000]',
    sidebarBg: 'bg-[#050505]',
    chatBg: 'bg-[#000000]',
    topBarBg: 'bg-[#080808]/95',
    inputBg: 'bg-[#0c0c0c]',
    cardBg: 'bg-[#0a0a0a]',
    senderBubbleBg: 'bg-[#0052cc] text-white shadow-lg shadow-blue-950/40',
    recipientBubbleBg: 'bg-[#111111] text-slate-100 border border-neutral-800',
    accentText: 'text-[#00e5ff]',
    accentBg: 'bg-[#00e5ff] text-black hover:bg-[#00b4cc]',
    border: 'border-neutral-900',
    badgeBg: 'bg-neutral-900',
  },
  matrix: {
    name: 'Cyberpunk Matrix',
    id: 'matrix',
    appBg: 'bg-[#020b05]',
    sidebarBg: 'bg-[#04140a]',
    chatBg: 'bg-[#020b05]',
    topBarBg: 'bg-[#04140a]/95',
    inputBg: 'bg-[#061e0e]',
    cardBg: 'bg-[#05180c]',
    senderBubbleBg: 'bg-[#005f27] text-white shadow-lg shadow-emerald-950/40',
    recipientBubbleBg: 'bg-[#072411] text-emerald-100 border border-emerald-900/60',
    accentText: 'text-[#00ff66]',
    accentBg: 'bg-[#00cc52] text-black hover:bg-[#00a843]',
    border: 'border-emerald-950',
    badgeBg: 'bg-emerald-950/80',
  },
  tactical: {
    name: 'Military Slate',
    id: 'tactical',
    appBg: 'bg-slate-950',
    sidebarBg: 'bg-slate-900/90',
    chatBg: 'bg-slate-950',
    topBarBg: 'bg-slate-900/60',
    inputBg: 'bg-slate-950',
    cardBg: 'bg-slate-900',
    senderBubbleBg: 'bg-sky-600 text-white shadow-lg shadow-sky-950/40',
    recipientBubbleBg: 'bg-slate-800/90 text-slate-100 border border-slate-700/60',
    accentText: 'text-sky-400',
    accentBg: 'bg-sky-600 hover:bg-sky-500 text-white',
    border: 'border-slate-800',
    badgeBg: 'bg-slate-800',
  },
};

export class ThemeManager {
  static getTheme(): AppTheme {
    try {
      const stored = localStorage.getItem('aegis_theme');
      if (stored && stored in THEMES) return stored as AppTheme;
    } catch {
      // ignore
    }
    return 'telegram'; // Default to Telegram Dark!
  }

  static setTheme(theme: AppTheme): void {
    try {
      localStorage.setItem('aegis_theme', theme);
    } catch {
      // ignore
    }
  }
}
