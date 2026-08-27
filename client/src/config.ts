/**
 * Runtime configuration. The relay URL is the one value that must change
 * between local dev and a real deployment, so it comes from the environment:
 *
 *   - Web / Tauri build:  set VITE_RELAY_URL at build time (e.g. in .env)
 *   - Node test harness:  set AEGIS_RELAY_URL
 *
 * Falls back to the local dev relay.
 */
function readEnv(...keys: string[]): string | undefined {
  for (const key of keys) {
    try {
      const v = (import.meta as unknown as { env?: Record<string, string> }).env?.[key];
      if (typeof v === 'string' && v.trim()) return v.trim();
    } catch {
      /* not running under a bundler */
    }
    try {
      if (typeof process !== 'undefined' && process.env && process.env[key]) {
        return String(process.env[key]).trim();
      }
    } catch {
      /* no process */
    }
  }
  return undefined;
}

export const RELAY_URL =
  readEnv('VITE_RELAY_URL', 'AEGIS_RELAY_URL') || 'http://localhost:4000';
