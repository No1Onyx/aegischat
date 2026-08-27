export type TransportMode = 'direct' | 'tor_socks5' | 'domain_fronting' | 'obfuscated';

export interface TransportConfig {
  mode: TransportMode;
  socks5ProxyUrl: string;       // e.g. "socks5h://127.0.0.1:9050"
  frontingDomain: string;       // e.g. "ajax.cloudflare.com"
  hiddenHost: string;           // e.g. "relay.aegischat.local"
  trafficPadding: boolean;      // Constant-size 256/512-byte anti-DPI padding
  dummyKeepAliveTraffic: boolean; // Random decoy packets to thwart timing analysis
}

const STORAGE_KEY = 'aegis_transport_config';

const DEFAULT_CONFIG: TransportConfig = {
  mode: 'direct',
  socks5ProxyUrl: 'socks5h://127.0.0.1:9050',
  frontingDomain: 'ajax.cloudflare.com',
  hiddenHost: 'relay.aegischat.local',
  trafficPadding: true,
  dummyKeepAliveTraffic: false,
};

export class TransportManager {
  private static cachedConfig: TransportConfig | null = null;

  static getConfig(): TransportConfig {
    if (this.cachedConfig) return this.cachedConfig;

    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        this.cachedConfig = { ...DEFAULT_CONFIG, ...JSON.parse(stored) };
        return this.cachedConfig!;
      }
    } catch {
      // ignore
    }

    this.cachedConfig = { ...DEFAULT_CONFIG };
    return this.cachedConfig;
  }

  static saveConfig(config: Partial<TransportConfig>): TransportConfig {
    const current = this.getConfig();
    const updated: TransportConfig = { ...current, ...config };
    this.cachedConfig = updated;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (err) {
      console.warn('Failed to save transport config:', err);
    }
    return updated;
  }

  /**
   * Diagnostic probe to test server connection, latency, and firewall bypass
   */
  static async runDiagnosticProbe(baseServerUrl: string = 'http://localhost:4000'): Promise<{
    reachable: boolean;
    latencyMs: number;
    mode: TransportMode;
    details: string;
  }> {
    const config = this.getConfig();
    const startTime = performance.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const res = await fetch(`${baseServerUrl}/api/status`, {
        signal: controller.signal,
        headers: config.mode === 'domain_fronting' ? { 'X-Fronted-Host': config.hiddenHost } : {},
      });

      clearTimeout(timeoutId);
      const latencyMs = Math.round(performance.now() - startTime);

      if (!res.ok) {
        return {
          reachable: false,
          latencyMs,
          mode: config.mode,
          details: `HTTP ${res.status}: Server returned error status.`,
        };
      }

      const data = await res.json();
      return {
        reachable: true,
        latencyMs,
        mode: config.mode,
        details: `Connected (${data.type || 'Relay'}). Mode: ${config.mode.toUpperCase()}`,
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - startTime);
      return {
        reachable: false,
        latencyMs,
        mode: config.mode,
        details: (err as Error).message || 'Connection timed out or blocked by firewall.',
      };
    }
  }
}
