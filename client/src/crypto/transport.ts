import { RELAY_URL } from '../config.js';

export type TransportMode = 'direct' | 'tor_socks5' | 'domain_fronting' | 'obfuscated';

export interface TransportConfig {
  mode: TransportMode;
  socks5ProxyUrl: string;       // e.g. "socks5h://127.0.0.1:9050"
  frontingDomain: string;       // CDN edge the TLS SNI/Host appears to target
  hiddenHost: string;           // real relay host, sent as an inner Host header
  relayBaseUrlOverride: string; // optional: point the client at a different relay
  trafficPadding: boolean;
  dummyKeepAliveTraffic: boolean;
}

const STORAGE_KEY = 'aegis_transport_config';

const DEFAULT_CONFIG: TransportConfig = {
  mode: 'direct',
  socks5ProxyUrl: 'socks5h://127.0.0.1:9050',
  frontingDomain: 'ajax.cloudflare.com',
  hiddenHost: 'relay.aegischat.local',
  relayBaseUrlOverride: '',
  trafficPadding: true,
  dummyKeepAliveTraffic: false,
};

/**
 * IMPORTANT — what a browser can and cannot do here:
 *
 *   - A web page CANNOT open a raw SOCKS5 connection. `tor_socks5` therefore
 *     only takes effect in the native (Tauri) build, where the Rust HTTP/WS
 *     client is configured to dial through the proxy, OR when the user has set
 *     a system-wide / browser proxy to Tor. In the pure web build this mode is
 *     advisory: run the whole browser through Tor Browser or a system proxy.
 *   - `domain_fronting` IS partially actionable from JS: we can send the real
 *     relay host as an inner header while the connection's SNI/Host targets a
 *     high-reputation CDN — but only if a fronting-capable CDN actually sits in
 *     front of the relay. Without that infrastructure it is a no-op.
 *   - `relayBaseUrlOverride` lets a user point the client at a mirror / hidden
 *     service / reverse proxy without rebuilding.
 *
 * This module applies the parts that work from JS and is honest about the rest.
 */
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
      /* ignore */
    }
    this.cachedConfig = { ...DEFAULT_CONFIG };
    return this.cachedConfig;
  }

  static saveConfig(config: Partial<TransportConfig>): TransportConfig {
    const updated: TransportConfig = { ...this.getConfig(), ...config };
    this.cachedConfig = updated;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (err) {
      console.warn('Failed to save transport config:', err);
    }
    return updated;
  }

  /** Effective relay base URL, honouring any override. */
  static effectiveBaseUrl(defaultUrl: string): string {
    const cfg = this.getConfig();
    return cfg.relayBaseUrlOverride.trim() || defaultUrl;
  }

  /** Extra headers to attach to relay HTTP requests for the active mode. */
  static requestHeaders(): Record<string, string> {
    const cfg = this.getConfig();
    if (cfg.mode === 'domain_fronting' && cfg.hiddenHost.trim()) {
      // Front on the CDN, address the real host in an inner header.
      return { 'X-Fronted-Host': cfg.hiddenHost.trim() };
    }
    return {};
  }

  /** True when the active mode needs infrastructure the browser can't provide alone. */
  static needsExternalRouting(): boolean {
    const m = this.getConfig().mode;
    return m === 'tor_socks5' || m === 'obfuscated';
  }

  /**
   * Diagnostic probe: connectivity, latency, and whether the active mode is
   * actually enforceable from this runtime.
   */
  static async runDiagnosticProbe(baseServerUrl: string = RELAY_URL): Promise<{
    reachable: boolean;
    latencyMs: number;
    mode: TransportMode;
    enforceable: boolean;
    details: string;
  }> {
    const config = this.getConfig();
    const target = this.effectiveBaseUrl(baseServerUrl);
    const startTime = performance.now();
    const enforceable = !this.needsExternalRouting();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`${target}/api/status`, {
        signal: controller.signal,
        headers: this.requestHeaders(),
      });
      clearTimeout(timeoutId);
      const latencyMs = Math.round(performance.now() - startTime);

      if (!res.ok) {
        return {
          reachable: false, latencyMs, mode: config.mode, enforceable,
          details: `HTTP ${res.status}: relay returned an error status.`,
        };
      }
      const data = await res.json();
      return {
        reachable: true,
        latencyMs,
        mode: config.mode,
        enforceable,
        details: enforceable
          ? `Connected (${data.type || 'Relay'}). Mode ${config.mode.toUpperCase()} active.`
          : `Connected, but "${config.mode}" needs Tor Browser / a system proxy / the ` +
            `native build to actually route traffic — the web page cannot enforce it.`,
      };
    } catch (err) {
      return {
        reachable: false,
        latencyMs: Math.round(performance.now() - startTime),
        mode: config.mode,
        enforceable,
        details: (err as Error).message || 'Connection timed out or blocked.',
      };
    }
  }
}
