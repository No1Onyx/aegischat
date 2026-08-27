import { useState, useEffect, useRef } from 'react';
import {
  Mic,
  MicOff,
  Video,
  VideoOff,
  PhoneOff,
  ShieldCheck,
  Lock,
} from 'lucide-react';
import type { CallType, CallState } from '../crypto/webrtcManager';

interface CallModalProps {
  peer: string;
  callType: CallType;
  callState: CallState;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  onToggleMute: () => boolean;
  onToggleVideo: () => boolean;
  onEndCall: () => void;
}

export function CallModal({
  peer,
  callType,
  callState,
  localStream,
  remoteStream,
  onToggleMute,
  onToggleVideo,
  onEndCall,
}: CallModalProps) {
  const [durationSec, setDurationSec] = useState<number>(0);
  const [isMuted, setIsMuted] = useState<boolean>(false);
  const [isVideoActive, setIsVideoActive] = useState<boolean>(callType === 'video');

  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null);

  // Call timer ticker
  useEffect(() => {
    let timer: any = null;
    if (callState === 'connected') {
      timer = setInterval(() => setDurationSec((d) => d + 1), 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [callState]);

  // Bind local stream
  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream, isVideoActive]);

  // Bind remote stream
  useEffect(() => {
    if (remoteStream) {
      if (remoteVideoRef.current) {
        remoteVideoRef.current.srcObject = remoteStream;
      }
      if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = remoteStream;
      }
    }
  }, [remoteStream, callState]);

  const formatDuration = (sec: number) => {
    const mins = Math.floor(sec / 60);
    const s = sec % 60;
    return `${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const handleMuteToggle = () => {
    const muted = onToggleMute();
    setIsMuted(muted);
  };

  const handleVideoToggle = () => {
    const active = onToggleVideo();
    setIsVideoActive(active);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/95 backdrop-blur-lg flex items-center justify-center p-4 select-none">
      {/* Invisible Remote Audio Output */}
      <audio ref={remoteAudioRef} autoPlay playsInline />

      <div className="relative w-full max-w-2xl h-[520px] bg-slate-900 border border-slate-800 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
        {/* Top Bar: Peer info, Duration, Security Status */}
        <div className="p-4 bg-gradient-to-b from-black/80 to-transparent flex items-center justify-between z-20">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-md">
              {peer.charAt(0)}
            </div>
            <div>
              <div className="font-bold text-white text-base leading-tight">{peer}</div>
              <div className="text-[11px] text-sky-400 font-mono">
                {callState === 'outgoing_ringing' && 'Ringing...'}
                {callState === 'connecting' && 'Establishing P2P Tunnel...'}
                {callState === 'connected' && formatDuration(durationSec)}
                {callState === 'ended' && 'Call Ended'}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="px-3 py-1 rounded-full bg-emerald-950/80 border border-emerald-800/60 text-emerald-300 text-[10px] font-semibold flex items-center gap-1.5 shadow-sm">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>E2EE (DTLS-SRTP)</span>
            </div>
          </div>
        </div>

        {/* Center Area: Video or Voice Waveform */}
        <div className="flex-1 relative flex items-center justify-center bg-slate-950 overflow-hidden">
          {callType === 'video' && remoteStream ? (
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              className="w-full h-full object-cover"
            />
          ) : (
            /* Audio Call Waveform & Avatar Animation */
            <div className="flex flex-col items-center justify-center space-y-6">
              <div className="relative">
                <div className="absolute -inset-4 rounded-full bg-sky-500/10 animate-pulse" />
                <div className="w-28 h-28 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center text-4xl font-bold text-white shadow-2xl">
                  {peer.charAt(0)}
                </div>
              </div>

              {/* Pulsing Audio Waves */}
              <div className="flex items-center gap-1.5 h-8">
                {[40, 70, 30, 90, 60, 100, 50, 80, 45, 95, 35, 75].map((h, i) => (
                  <div
                    key={i}
                    className="w-1 bg-sky-400 rounded-full transition-all duration-300"
                    style={{
                      height: callState === 'connected' ? `${h}%` : '20%',
                      animation:
                        callState === 'connected'
                          ? `pulse 1s infinite ${i * 0.1}s`
                          : 'none',
                    }}
                  />
                ))}
              </div>

              <div className="text-xs text-slate-400 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-sky-400" />
                <span>Zero-Knowledge Direct P2P Channel</span>
              </div>
            </div>
          )}

          {/* Local PiP Video Preview (if video active) */}
          {isVideoActive && (
            <div className="absolute bottom-4 right-4 w-36 h-48 bg-slate-900 border-2 border-slate-700/80 rounded-2xl overflow-hidden shadow-2xl z-20">
              <video
                ref={localVideoRef}
                autoPlay
                playsInline
                muted
                className="w-full h-full object-cover mirror"
              />
              <div className="absolute bottom-1 left-2 text-[9px] font-mono text-white/80 bg-black/60 px-1 rounded">
                You
              </div>
            </div>
          )}
        </div>

        {/* Bottom Call Controls */}
        <div className="p-5 bg-gradient-to-t from-black/90 to-transparent flex items-center justify-center gap-5 z-20">
          {/* Mute Mic */}
          <button
            type="button"
            onClick={handleMuteToggle}
            className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${
              isMuted
                ? 'bg-rose-600 text-white shadow-lg shadow-rose-950/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
            }`}
            title={isMuted ? 'Unmute microphone' : 'Mute microphone'}
          >
            {isMuted ? <MicOff className="w-5 h-5" /> : <Mic className="w-5 h-5" />}
          </button>

          {/* Video Toggle */}
          <button
            type="button"
            onClick={handleVideoToggle}
            className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${
              !isVideoActive
                ? 'bg-slate-800 text-slate-400'
                : 'bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-950/40'
            }`}
            title={isVideoActive ? 'Turn camera off' : 'Turn camera on'}
          >
            {isVideoActive ? <Video className="w-5 h-5" /> : <VideoOff className="w-5 h-5" />}
          </button>

          {/* Hangup / End Call */}
          <button
            type="button"
            onClick={onEndCall}
            className="w-14 h-14 rounded-full bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center shadow-xl shadow-rose-950/60 hover:scale-105 active:scale-95 transition-all"
            title="End Call"
          >
            <PhoneOff className="w-6 h-6" />
          </button>
        </div>
      </div>
    </div>
  );
}
