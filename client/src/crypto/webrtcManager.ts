export type CallType = 'audio' | 'video';

export type CallSignal =
  | { type: 'CALL_INVITE'; callType: CallType; peerName: string }
  | { type: 'CALL_ACCEPT'; callType: CallType }
  | { type: 'CALL_OFFER'; sdp: RTCSessionDescriptionInit }
  | { type: 'CALL_ANSWER'; sdp: RTCSessionDescriptionInit }
  | { type: 'CALL_CANDIDATE'; candidate: RTCIceCandidateInit }
  | { type: 'CALL_DECLINE'; reason?: string }
  | { type: 'CALL_HANGUP'; reason?: string };

export type CallState =
  | 'idle'
  | 'outgoing_ringing'
  | 'incoming_ringing'
  | 'connecting'
  | 'connected'
  | 'ended';

export type CallPrivacyMode =
  | 'standard'    // STUN for NAT traversal, direct P2P where possible
  | 'relay-only'  // force TURN relay so the peer never learns your IP (needs TURN)
  | 'no-stun';    // no STUN/TURN at all — only works on the same LAN / mesh

export interface CallPrivacyConfig {
  mode: CallPrivacyMode;
  stunServers: string[];
  turnServers: { urls: string; username?: string; credential?: string }[];
}

const CALL_CONFIG_KEY = 'aegis_call_config';

const DEFAULT_CALL_CONFIG: CallPrivacyConfig = {
  mode: 'standard',
  // Cloudflare first (privacy-friendlier than Google); users can trim this list.
  stunServers: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'],
  turnServers: [],
};

export function getCallPrivacyConfig(): CallPrivacyConfig {
  try {
    const raw = localStorage.getItem(CALL_CONFIG_KEY);
    if (raw) return { ...DEFAULT_CALL_CONFIG, ...JSON.parse(raw) };
  } catch {
    /* ignore */
  }
  return { ...DEFAULT_CALL_CONFIG };
}

export function setCallPrivacyConfig(cfg: Partial<CallPrivacyConfig>): CallPrivacyConfig {
  const merged = { ...getCallPrivacyConfig(), ...cfg };
  try {
    localStorage.setItem(CALL_CONFIG_KEY, JSON.stringify(merged));
  } catch {
    /* ignore */
  }
  return merged;
}

function buildRtcConfig(): RTCConfiguration {
  const cfg = getCallPrivacyConfig();
  const iceServers: RTCIceServer[] = [];

  if (cfg.mode !== 'no-stun') {
    for (const s of cfg.stunServers) iceServers.push({ urls: s });
  }
  for (const t of cfg.turnServers) {
    iceServers.push({ urls: t.urls, username: t.username, credential: t.credential });
  }

  const rtc: RTCConfiguration = { iceServers };
  if (cfg.mode === 'relay-only') {
    // Never emit host/srflx candidates: the remote peer only ever sees the TURN
    // relay address, not the caller's real IP. Requires at least one TURN server.
    rtc.iceTransportPolicy = 'relay';
    if (cfg.turnServers.length === 0) {
      console.warn(
        '[Aegis] Call privacy is "relay-only" but no TURN server is configured — ' +
        'calls will not connect until you add one.'
      );
    }
  }
  return rtc;
}

export class WebRTCManager {
  private pc: RTCPeerConnection | null = null;
  public localStream: MediaStream | null = null;
  public remoteStream: MediaStream | null = null;
  public state: CallState = 'idle';
  public callType: CallType = 'audio';
  public currentPeer: string | null = null;

  private onStateChangeCb: ((state: CallState) => void) | null = null;
  private onRemoteStreamCb: ((stream: MediaStream) => void) | null = null;
  private sendSignalCb: ((peer: string, signal: CallSignal) => Promise<void>) | null = null;

  constructor(
    sendSignal: (peer: string, signal: CallSignal) => Promise<void>,
    onStateChange: (state: CallState) => void,
    onRemoteStream: (stream: MediaStream) => void
  ) {
    this.sendSignalCb = sendSignal;
    this.onStateChangeCb = onStateChange;
    this.onRemoteStreamCb = onRemoteStream;
  }

  private setState(newState: CallState) {
    this.state = newState;
    this.onStateChangeCb?.(newState);
  }

  async startCall(peer: string, callType: CallType) {
    this.currentPeer = peer;
    this.callType = callType;
    this.setState('outgoing_ringing');

    // 1. Acquire local media
    await this.setupLocalMedia(callType);

    // 2. Send INVITE signal
    await this.sendSignalCb?.(peer, {
      type: 'CALL_INVITE',
      callType,
      peerName: peer,
    });
  }

  async handleIncomingInvite(peer: string, callType: CallType) {
    this.currentPeer = peer;
    this.callType = callType;
    this.setState('incoming_ringing');
  }

  async acceptCall() {
    if (!this.currentPeer) return;
    this.setState('connecting');

    // 1. Acquire local media
    await this.setupLocalMedia(this.callType);

    // 2. Send ACCEPT signal
    await this.sendSignalCb?.(this.currentPeer, {
      type: 'CALL_ACCEPT',
      callType: this.callType,
    });

    // 3. Initialize RTCPeerConnection
    this.createPeerConnection();
  }

  async declineCall() {
    if (this.currentPeer) {
      await this.sendSignalCb?.(this.currentPeer, {
        type: 'CALL_DECLINE',
        reason: 'Call declined by user',
      });
    }
    this.endCall();
  }

  private async setupLocalMedia(callType: CallType) {
    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: callType === 'video',
      });
    } catch (err) {
      console.warn('Could not acquire requested media, trying audio only:', err);
      try {
        this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        this.callType = 'audio';
      } catch (audioErr) {
        console.error('Microphone unavailable or permission denied:', audioErr);
        // Create an empty fallback audio track so signaling doesn't fail
        const ctx = new AudioContext();
        const osc = ctx.createOscillator();
        const dst = ctx.createMediaStreamDestination();
        osc.connect(dst);
        osc.start();
        this.localStream = dst.stream;
      }
    }
  }

  private createPeerConnection() {
    this.pc = new RTCPeerConnection(buildRtcConfig());

    if (this.localStream) {
      this.localStream.getTracks().forEach((track) => {
        this.pc?.addTrack(track, this.localStream!);
      });
    }

    this.pc.ontrack = (event) => {
      if (event.streams && event.streams[0]) {
        this.remoteStream = event.streams[0];
        this.onRemoteStreamCb?.(this.remoteStream);
      }
    };

    this.pc.onicecandidate = (event) => {
      if (event.candidate && this.currentPeer) {
        this.sendSignalCb?.(this.currentPeer, {
          type: 'CALL_CANDIDATE',
          candidate: event.candidate.toJSON(),
        });
      }
    };

    this.pc.onconnectionstatechange = () => {
      if (this.pc?.connectionState === 'connected') {
        this.setState('connected');
      } else if (
        this.pc?.connectionState === 'disconnected' ||
        this.pc?.connectionState === 'failed' ||
        this.pc?.connectionState === 'closed'
      ) {
        this.endCall();
      }
    };
  }

  async handleSignal(peer: string, signal: CallSignal) {
    if (signal.type === 'CALL_INVITE') {
      await this.handleIncomingInvite(peer, signal.callType);
      return;
    }

    if (signal.type === 'CALL_ACCEPT') {
      this.setState('connecting');
      this.createPeerConnection();
      // Caller initiates the SDP offer
      const offer = await this.pc!.createOffer();
      await this.pc!.setLocalDescription(offer);
      await this.sendSignalCb?.(peer, {
        type: 'CALL_OFFER',
        sdp: offer,
      });
      return;
    }

    if (signal.type === 'CALL_OFFER') {
      if (!this.pc) this.createPeerConnection();
      await this.pc!.setRemoteDescription(new RTCSessionDescription(signal.sdp));
      const answer = await this.pc!.createAnswer();
      await this.pc!.setLocalDescription(answer);
      await this.sendSignalCb?.(peer, {
        type: 'CALL_ANSWER',
        sdp: answer,
      });
      return;
    }

    if (signal.type === 'CALL_ANSWER') {
      if (this.pc) {
        await this.pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));
      }
      return;
    }

    if (signal.type === 'CALL_CANDIDATE') {
      if (this.pc && signal.candidate) {
        try {
          await this.pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
        } catch (e) {
          console.warn('Error adding ICE candidate:', e);
        }
      }
      return;
    }

    if (signal.type === 'CALL_DECLINE' || signal.type === 'CALL_HANGUP') {
      this.endCall();
      return;
    }
  }

  toggleMuteAudio(): boolean {
    if (!this.localStream) return false;
    const audioTrack = this.localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      return !audioTrack.enabled; // returns isMuted
    }
    return false;
  }

  toggleVideo(): boolean {
    if (!this.localStream) return false;
    const videoTrack = this.localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      return videoTrack.enabled; // returns isVideoOn
    }
    return false;
  }

  endCall() {
    if (this.currentPeer && (this.state === 'connected' || this.state === 'outgoing_ringing')) {
      this.sendSignalCb?.(this.currentPeer, {
        type: 'CALL_HANGUP',
        reason: 'Call ended by user',
      }).catch(() => {});
    }

    if (this.localStream) {
      this.localStream.getTracks().forEach((track) => track.stop());
      this.localStream = null;
    }

    if (this.pc) {
      this.pc.close();
      this.pc = null;
    }

    this.remoteStream = null;
    this.currentPeer = null;
    this.setState('idle');
  }
}
