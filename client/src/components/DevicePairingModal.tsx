import { useState, useEffect } from 'react';
import QRCode from 'qrcode';
import {
  QrCode,
  Smartphone,
  Laptop,
  CheckCircle2,
  Trash2,
  X,
  Copy,
  Check,
  Zap,
} from 'lucide-react';
import { DevicePairingManager } from '../crypto/devicePairing';
import type { LinkedDevice, PairingSessionData } from '../crypto/devicePairing';

interface DevicePairingModalProps {
  currentUser: string;
  onClose: () => void;
}

export function DevicePairingModal({ currentUser, onClose }: DevicePairingModalProps) {
  const [activeTab, setActiveTab] = useState<'qr' | 'devices'>('qr');
  const [session, setSession] = useState<PairingSessionData | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [devices, setDevices] = useState<LinkedDevice[]>(DevicePairingManager.getLinkedDevices());
  const [simulatedSuccess, setSimulatedSuccess] = useState<boolean>(false);

  // Generate pairing session and QR code
  useEffect(() => {
    const s = DevicePairingManager.createPairingSession(currentUser);
    setSession(s);

    QRCode.toDataURL(s.qrPayload, {
      width: 240,
      margin: 2,
      color: {
        dark: '#ffffff',
        light: '#0a0a0a',
      },
    })
      .then((url: string) => setQrDataUrl(url))
      .catch((err: any) => console.error('QR generation error:', err));
  }, [currentUser]);

  const handleCopyCode = () => {
    if (!session) return;
    navigator.clipboard.writeText(session.qrPayload);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSimulatePhonePairing = () => {
    if (!session) return;

    // Simulate secondary device scanning the QR code
    const scanned = DevicePairingManager.processScannedQR(
      session.qrPayload,
      'Pixel 9 Pro (Android Phone)',
      'android'
    );

    // Primary decrypts request and confirms
    const decryptedReq = DevicePairingManager.decryptPairingRequest(
      session.pairingKeyPair,
      session.token,
      scanned.encryptedRequest
    );

    // Primary adds to linked devices
    DevicePairingManager.addLinkedDevice({
      name: decryptedReq.requestData.deviceName,
      platform: decryptedReq.requestData.platform,
      isCurrent: false,
    });

    setDevices(DevicePairingManager.getLinkedDevices());
    setSimulatedSuccess(true);
    setTimeout(() => {
      setSimulatedSuccess(false);
      setActiveTab('devices');
    }, 1500);
  };

  const handleRevokeDevice = (deviceId: string) => {
    if (confirm('Revoke access for this linked device?')) {
      DevicePairingManager.removeLinkedDevice(deviceId);
      setDevices(DevicePairingManager.getLinkedDevices());
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 select-none animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-md w-full p-6 shadow-2xl space-y-6 max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-sky-500/20 text-sky-400 border border-sky-500/30 rounded-xl">
              <QrCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">Linked Devices & Multi-Device Sync</h3>
              <p className="text-xs text-slate-400">Zero-Knowledge Encrypted QR Handshake</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Switcher */}
        <div className="grid grid-cols-2 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('qr')}
            className={`py-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'qr'
                ? 'bg-sky-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <QrCode className="w-3.5 h-3.5" />
            <span>Link New Device</span>
          </button>
          <button
            onClick={() => setActiveTab('devices')}
            className={`py-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'devices'
                ? 'bg-sky-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Smartphone className="w-3.5 h-3.5" />
            <span>Active Devices ({devices.length})</span>
          </button>
        </div>

        {/* Tab 1: QR Code Pairing */}
        {activeTab === 'qr' && (
          <div className="space-y-4 text-center">
            <div className="p-4 bg-black/40 border border-slate-800 rounded-2xl inline-block mx-auto shadow-inner">
              {qrDataUrl ? (
                <img
                  src={qrDataUrl}
                  alt="Aegis Pairing QR Code"
                  className="w-48 h-48 mx-auto rounded-xl shadow-lg"
                />
              ) : (
                <div className="w-48 h-48 flex items-center justify-center text-xs text-slate-500 font-mono">
                  Generating keypair...
                </div>
              )}
            </div>

            <div className="space-y-1">
              <div className="text-xs font-semibold text-white">Scan with AegisChat Mobile App</div>
              <p className="text-[11px] text-slate-400 max-w-xs mx-auto leading-relaxed">
                Open AegisChat on your phone &gt; Settings &gt; Linked Devices &gt; Scan QR Code.
              </p>
            </div>

            {/* Alphanumeric Copy-Paste Code */}
            <div className="flex items-center gap-2 p-2 rounded-xl bg-slate-950 border border-slate-800 text-left">
              <div className="flex-1 font-mono text-[10px] text-slate-400 truncate select-all">
                {session?.qrPayload || 'Loading...'}
              </div>
              <button
                type="button"
                onClick={handleCopyCode}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all flex items-center gap-1 text-[10px]"
                title="Copy raw pairing string"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Quick Demo Simulator */}
            <div className="pt-1">
              <button
                type="button"
                onClick={handleSimulatePhonePairing}
                className={`w-full py-2.5 px-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-md ${
                  simulatedSuccess
                    ? 'bg-emerald-600 text-white'
                    : 'bg-indigo-950/60 hover:bg-indigo-900/60 text-indigo-300 border border-indigo-800/60'
                }`}
              >
                {simulatedSuccess ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-white" />
                    <span>Pixel 9 Pro Linked Successfully!</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-indigo-400" />
                    <span>Simulate Mobile Scan Handshake</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: Linked Devices List */}
        {activeTab === 'devices' && (
          <div className="space-y-2.5">
            <div className="text-xs font-semibold text-slate-400 px-1">Authorized Devices</div>

            {devices.map((device) => (
              <div
                key={device.id}
                className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 flex items-center justify-between transition-all"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-slate-900 text-slate-300 border border-slate-800">
                    {device.platform === 'android' || device.platform === 'ios' ? (
                      <Smartphone className="w-4 h-4 text-sky-400" />
                    ) : (
                      <Laptop className="w-4 h-4 text-indigo-400" />
                    )}
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-white flex items-center gap-1.5">
                      <span>{device.name}</span>
                      {device.isCurrent && (
                        <span className="text-[9px] bg-emerald-950 text-emerald-300 border border-emerald-800/80 px-1.5 py-0.2 rounded font-mono">
                          THIS DEVICE
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      Linked: {new Date(device.linkedAt).toLocaleDateString()} · Status: Active
                    </div>
                  </div>
                </div>

                {!device.isCurrent && (
                  <button
                    type="button"
                    onClick={() => handleRevokeDevice(device.id)}
                    className="p-2 rounded-xl hover:bg-rose-950/40 text-slate-500 hover:text-rose-400 transition-colors"
                    title="Revoke device access"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Security Banner */}
        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-[10px] text-slate-400 leading-relaxed">
          <span className="text-sky-400 font-semibold">Zero-Knowledge Guarantee:</span> Pairing uses ephemeral Curve25519 key negotiation directly between devices. No private keys or unencrypted message histories are ever stored in the cloud.
        </div>
      </div>
    </div>
  );
}
