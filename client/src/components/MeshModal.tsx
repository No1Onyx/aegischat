import { useState, useEffect } from 'react';
import {
  Radio,
  WifiOff,
  CheckCircle2,
  X,
  RefreshCw,
  Zap,
} from 'lucide-react';
import type { DiscoveredPeer } from '../crypto/meshNetwork';

interface MeshModalProps {
  isEnabled: boolean;
  onToggleMesh: (enabled: boolean) => void;
  peers: DiscoveredPeer[];
  relayedCount: number;
  onClose: () => void;
}

export function MeshModal({
  isEnabled,
  onToggleMesh,
  peers,
  relayedCount,
  onClose,
}: MeshModalProps) {
  const [radarAngle, setRadarAngle] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setRadarAngle((a) => (a + 4) % 360);
    }, 30);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 select-none animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-lg w-full p-6 shadow-2xl space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-xl">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">Offline P2P Mesh Network</h3>
              <p className="text-xs text-slate-400">Zero-Internet Ad-Hoc / Wi-Fi Direct Mode</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Master Toggle Banner */}
        <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div className="space-y-0.5">
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <span>Mesh Protocol State</span>
              {isEnabled ? (
                <span className="text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-mono">
                  ACTIVE (LISTENING)
                </span>
              ) : (
                <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full font-mono">
                  STANDBY
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 leading-tight">
              Bypasses cellular and ISP shutdowns by routing packets directly across local devices.
            </p>
          </div>

          <label className="relative inline-flex items-center cursor-pointer ml-3">
            <input
              type="checkbox"
              checked={isEnabled}
              onChange={(e) => onToggleMesh(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
          </label>
        </div>

        {/* Radar & Discovered Nodes */}
        {isEnabled ? (
          <div className="space-y-3">
            <div className="relative h-40 bg-slate-950/80 rounded-2xl border border-slate-800 overflow-hidden flex items-center justify-center">
              {/* Radar Circles */}
              <div className="absolute w-32 h-32 rounded-full border border-emerald-500/20" />
              <div className="absolute w-20 h-20 rounded-full border border-emerald-500/30" />
              <div className="absolute w-8 h-8 rounded-full border border-emerald-500/40" />

              {/* Radar Sweep Needle */}
              <div
                className="absolute w-32 h-32 origin-center pointer-events-none"
                style={{
                  transform: `rotate(${radarAngle}deg)`,
                  background:
                    'conic-gradient(from 0deg, rgba(16, 185, 129, 0.25) 0deg, transparent 60deg, transparent 360deg)',
                }}
              />

              {/* Center Node */}
              <div className="z-10 flex flex-col items-center">
                <div className="w-4 h-4 rounded-full bg-emerald-400 shadow-lg shadow-emerald-500/60 ring-4 ring-emerald-500/20 animate-pulse" />
                <span className="text-[10px] font-mono text-emerald-300 mt-1">This Device</span>
              </div>
            </div>

            {/* Discovered Peers List */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-slate-400 font-semibold px-1">
                <span>Discovered Mesh Nodes ({peers.length})</span>
                <span className="text-[11px] font-mono text-emerald-400">
                  {relayedCount} Packets Relayed
                </span>
              </div>

              {peers.length === 0 ? (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center text-xs text-slate-500 space-y-1">
                  <RefreshCw className="w-4 h-4 mx-auto animate-spin text-slate-600 mb-1" />
                  <div>Broadcasting ad-hoc discovery beacons on local subnet...</div>
                  <div className="text-[10px] text-slate-600">
                    Nearby devices running AegisChat on the same Wi-Fi, hotspot, or Bluetooth will appear automatically.
                  </div>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {peers.map((peer) => (
                    <div
                      key={peer.id}
                      className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <div>
                          <div className="font-semibold text-white">{peer.username}</div>
                          <div className="text-[10px] font-mono text-slate-500">
                            {peer.address} · {peer.hopCount}-Hop Mesh Route
                          </div>
                        </div>
                      </div>
                      <div className="px-2 py-0.5 rounded-md bg-emerald-950/80 border border-emerald-800/60 text-emerald-300 text-[10px] font-mono">
                        Direct P2P
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-2xl bg-slate-950 border border-slate-800 text-center space-y-2">
            <WifiOff className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="text-sm font-semibold text-slate-300">Offline Mesh is Disabled</div>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Enable Mesh Mode when traditional mobile networks or internet providers are blocked. Devices route encrypted packets peer-to-peer across physical proximity.
            </p>
          </div>
        )}

        {/* Technical Explainer */}
        <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 space-y-1">
          <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-xs">
            <Zap className="w-3.5 h-3.5" />
            <span>Store-and-Forward Epidemic Routing</span>
          </div>
          <p className="leading-relaxed">
            All mesh packets are end-to-end encrypted with Double Ratchet keys before transmission. Intermediate nodes route packets without the ability to read or tamper with the payload.
          </p>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold rounded-xl transition-all"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
