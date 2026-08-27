import { RELAY_URL } from '../config';
import { useEffect, useState } from 'react';
import { Server, Activity, ShieldAlert, Database } from 'lucide-react';

interface AuditLog {
  id: string;
  timestamp: number;
  type: 'KEY_REGISTER' | 'KEY_FETCH' | 'ENVELOPE_RELAYED' | 'ACK_DELIVERED';
  details: string;
  ciphertextSample?: string;
}

interface RelayTransparencyDrawerProps {
  onClose: () => void;
  serverUrl?: string;
}

export const RelayTransparencyDrawer: React.FC<RelayTransparencyDrawerProps> = ({
  onClose,
  serverUrl = RELAY_URL,
}) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);

  useEffect(() => {
    const wsUrl = serverUrl.replace(/^http/, 'ws') + '/ws';
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'SUBSCRIBE_AUDIT' }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'AUDIT_LOG_BATCH') {
          setLogs(data.payload);
        } else if (data.type === 'AUDIT_LOG') {
          setLogs((prev) => [data.payload, ...prev].slice(0, 50));
        }
      } catch (err) {
        console.error('Failed to parse audit log:', err);
      }
    };

    return () => {
      ws.close();
    };
  }, [serverUrl]);

  return (
    <div className="fixed inset-y-0 left-0 w-[420px] bg-slate-900 border-r border-slate-800 shadow-2xl z-50 flex flex-col p-6 text-slate-200">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2 text-indigo-400 font-bold text-lg">
          <Server className="w-6 h-6 text-indigo-400" />
          <span>Blind Relay Transparency Log</span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white p-1 rounded-md transition-colors"
        >
          ✕
        </button>
      </div>

      <div className="mt-3 p-3 bg-indigo-950/30 border border-indigo-800/40 rounded-xl text-xs text-indigo-300 flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 shrink-0 text-indigo-400 mt-0.5" />
        <p>
          Live stream from the relay server: demonstrates that the central server operates strictly in <strong>Zero-Knowledge mode</strong>. It only routes encrypted ciphertext blocks and purges ephemeral payloads upon delivery ACK.
        </p>
      </div>

      <div className="flex-1 overflow-y-auto mt-4 space-y-2.5 pr-1">
        {logs.length === 0 ? (
          <div className="text-center py-16 text-slate-500 text-sm">
            <Activity className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
            Listening for relay traffic...
          </div>
        ) : (
          logs.map((log) => (
            <div
              key={log.id + log.timestamp}
              className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3 text-xs space-y-1.5 transition-all"
            >
              <div className="flex items-center justify-between">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                    log.type === 'ENVELOPE_RELAYED'
                      ? 'bg-sky-950 text-sky-400 border border-sky-800/50'
                      : log.type === 'ACK_DELIVERED'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {log.type.replace('_', ' ')}
                </span>
                <span className="text-[10px] text-slate-500 font-mono">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <p className="text-slate-300 font-medium">{log.details}</p>

              {log.ciphertextSample && (
                <div className="pt-1">
                  <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1 font-semibold">
                    <Database className="w-3 h-3 text-slate-500" />
                    Opaque Payload Visible to Server:
                  </div>
                  <div className="font-mono text-[11px] text-indigo-300/80 bg-slate-900 p-1.5 rounded border border-slate-800/80 break-all mt-0.5">
                    {log.ciphertextSample}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
