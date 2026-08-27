import React, { useState, useEffect } from 'react';
import {
  Globe,
  Radio,
  Activity,
  CheckCircle2,
  XCircle,
  X,
  RefreshCw,
  Server,
  Zap,
} from 'lucide-react';
import { TransportManager } from '../crypto/transport';
import type { TransportConfig, TransportMode } from '../crypto/transport';

interface CensorshipModalProps {
  serverUrl: string;
  onClose: () => void;
}

export function CensorshipModal({ serverUrl, onClose }: CensorshipModalProps) {
  const [config, setConfig] = useState<TransportConfig>(TransportManager.getConfig());
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [diagResult, setDiagResult] = useState<{
    reachable: boolean;
    latencyMs: number;
    mode: TransportMode;
    details: string;
  } | null>(null);

  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  useEffect(() => {
    runProbe();
  }, []);

  const runProbe = async () => {
    setIsTesting(true);
    try {
      const res = await TransportManager.runDiagnosticProbe(serverUrl);
      setDiagResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    TransportManager.saveConfig(config);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2000);
    runProbe();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-lg w-full p-6 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-xl">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">Censorship Bypass & Tor Transport</h3>
              <p className="text-xs text-slate-400">Firewall Circumvention & Anti-DPI Protection</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Live Firewall Diagnostic Card */}
        <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <span className="text-xs font-semibold text-white">Firewall Diagnostic Probe</span>
            </div>
            <button
              type="button"
              disabled={isTesting}
              onClick={runProbe}
              className="text-[11px] px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300 flex items-center gap-1.5 transition-all"
            >
              {isTesting ? <RefreshCw className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              <span>Test Route</span>
            </button>
          </div>

          {diagResult ? (
            <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs">
              <div className="flex items-center gap-2">
                {diagResult.reachable ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400" />
                )}
                <div>
                  <div className="font-medium text-slate-200">
                    {diagResult.reachable ? 'Firewall Cleared: Online' : 'Route Blocked'}
                  </div>
                  <div className="text-[10px] text-slate-500">{diagResult.details}</div>
                </div>
              </div>
              <div className="text-right font-mono">
                <span className="text-xs text-emerald-400 font-bold">{diagResult.latencyMs} ms</span>
                <div className="text-[9px] text-slate-500 uppercase">{diagResult.mode}</div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500 py-2">Probing network status...</div>
          )}
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          {/* Transport Mode Options */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300">Transport Tunnel</label>
            <div className="grid grid-cols-2 gap-2">
              {/* Option 1: Direct */}
              <div
                onClick={() => setConfig({ ...config, mode: 'direct' })}
                className={`p-3 rounded-2xl border cursor-pointer transition-all space-y-1 ${
                  config.mode === 'direct'
                    ? 'bg-sky-950/40 border-sky-500 text-white'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-bold">
                  <Server className="w-3.5 h-3.5 text-sky-400" />
                  <span>Direct Relay</span>
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Lowest latency for free regions.
                </p>
              </div>

              {/* Option 2: Tor / SOCKS5 */}
              <div
                onClick={() => setConfig({ ...config, mode: 'tor_socks5' })}
                className={`p-3 rounded-2xl border cursor-pointer transition-all space-y-1 ${
                  config.mode === 'tor_socks5'
                    ? 'bg-indigo-950/40 border-indigo-500 text-white'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-bold">
                  <Radio className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Tor SOCKS5</span>
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Onion routed. Masks your IP from ISP.
                </p>
              </div>

              {/* Option 3: Domain Fronting */}
              <div
                onClick={() => setConfig({ ...config, mode: 'domain_fronting' })}
                className={`p-3 rounded-2xl border cursor-pointer transition-all space-y-1 ${
                  config.mode === 'domain_fronting'
                    ? 'bg-emerald-950/40 border-emerald-500 text-white'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-bold">
                  <Globe className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Domain Fronting</span>
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Disguises TLS SNI as ordinary CDN.
                </p>
              </div>

              {/* Option 4: Obfuscated Traffic */}
              <div
                onClick={() => setConfig({ ...config, mode: 'obfuscated' })}
                className={`p-3 rounded-2xl border cursor-pointer transition-all space-y-1 ${
                  config.mode === 'obfuscated'
                    ? 'bg-amber-950/40 border-amber-500 text-white'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-bold">
                  <Zap className="w-3.5 h-3.5 text-amber-400" />
                  <span>Obfuscated WS</span>
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Anti-DPI protocol camouflage.
                </p>
              </div>
            </div>
          </div>

          {/* Conditional inputs */}
          {config.mode === 'tor_socks5' && (
            <div className="space-y-1.5 bg-slate-950/80 p-3 rounded-2xl border border-slate-800">
              <label className="text-xs font-semibold text-slate-300">Tor SOCKS5 Proxy Address</label>
              <input
                type="text"
                value={config.socks5ProxyUrl}
                onChange={(e) => setConfig({ ...config, socks5ProxyUrl: e.target.value })}
                placeholder="socks5h://127.0.0.1:9050"
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-indigo-500"
              />
              <p className="text-[10px] text-slate-500">
                Default: 127.0.0.1:9050 (Tor Daemon) or 127.0.0.1:9150 (Tor Browser)
              </p>
            </div>
          )}

          {config.mode === 'domain_fronting' && (
            <div className="space-y-2 bg-slate-950/80 p-3 rounded-2xl border border-slate-800">
              <div>
                <label className="text-xs font-semibold text-slate-300">Public CDN Front (SNI Mask)</label>
                <input
                  type="text"
                  value={config.frontingDomain}
                  onChange={(e) => setConfig({ ...config, frontingDomain: e.target.value })}
                  placeholder="ajax.cloudflare.com"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500 mt-1"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-300">Hidden Relay Origin Host</label>
                <input
                  type="text"
                  value={config.hiddenHost}
                  onChange={(e) => setConfig({ ...config, hiddenHost: e.target.value })}
                  placeholder="relay.aegis.onion"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500 mt-1"
                />
              </div>
            </div>
          )}

          {/* Anti-DPI Traffic Morphing Toggles */}
          <div className="space-y-2 bg-slate-950/80 p-3 rounded-2xl border border-slate-800">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-semibold text-slate-200">Constant-Size Packet Padding</div>
                <div className="text-[10px] text-slate-500">Pads all messages to fixed 256-byte blocks to prevent length analysis</div>
              </div>
              <input
                type="checkbox"
                checked={config.trafficPadding}
                onChange={(e) => setConfig({ ...config, trafficPadding: e.target.checked })}
                className="w-4 h-4 rounded text-sky-600 bg-slate-900 border-slate-700"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
              <div>
                <div className="text-xs font-semibold text-slate-200">Decoy Keep-Alive Traffic</div>
                <div className="text-[10px] text-slate-500">Transmits random encrypted noise to mask messaging timing patterns</div>
              </div>
              <input
                type="checkbox"
                checked={config.dummyKeepAliveTraffic}
                onChange={(e) => setConfig({ ...config, dummyKeepAliveTraffic: e.target.checked })}
                className="w-4 h-4 rounded text-sky-600 bg-slate-900 border-slate-700"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 hover:bg-slate-800 text-slate-400 hover:text-white rounded-xl text-xs"
            >
              Close
            </button>
            <button
              type="submit"
              className="px-5 py-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs rounded-xl shadow-md transition-all"
            >
              {savedSuccess ? 'Saved ✓' : 'Apply Transport Settings'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
