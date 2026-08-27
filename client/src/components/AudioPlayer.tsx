import { useState, useEffect, useRef } from 'react';
import { Play, Pause, RefreshCw, Volume2 } from 'lucide-react';
import { AttachmentCrypto } from '../crypto/attachments';
import type { EncryptedAttachmentDescriptor } from '../crypto/attachments';

interface AudioPlayerProps {
  descriptor: EncryptedAttachmentDescriptor;
  isSender: boolean;
}

export function AudioPlayer({ descriptor, isSender }: AudioPlayerProps) {
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [duration, setDuration] = useState<number>(descriptor.durationSec || 0);

  const audioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    let active = true;

    async function loadAudio() {
      setIsLoading(true);
      try {
        const url = await AttachmentCrypto.fetchAndDecrypt(descriptor);
        if (active) {
          setAudioUrl(url);
        }
      } catch (err) {
        console.error('Failed to decrypt audio note:', err);
      } finally {
        if (active) setIsLoading(false);
      }
    }

    loadAudio();

    return () => {
      active = false;
    };
  }, [descriptor]);

  const togglePlay = () => {
    if (!audioRef.current || !audioUrl) return;

    if (isPlaying) {
      audioRef.current.pause();
      setIsPlaying(false);
    } else {
      audioRef.current.play();
      setIsPlaying(true);
    }
  };

  const handleTimeUpdate = () => {
    if (!audioRef.current) return;
    const current = audioRef.current.currentTime;
    const total = audioRef.current.duration || duration || 1;
    setProgress((current / total) * 100);
  };

  const handleLoadedMetadata = () => {
    if (audioRef.current && !duration) {
      setDuration(Math.round(audioRef.current.duration));
    }
  };

  const handleEnded = () => {
    setIsPlaying(false);
    setProgress(0);
  };

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const s = Math.floor(secs % 60);
    return `${mins}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <div className="flex items-center gap-3 py-1 min-w-[200px] max-w-xs select-none">
      {audioUrl && (
        <audio
          ref={audioRef}
          src={audioUrl}
          onTimeUpdate={handleTimeUpdate}
          onLoadedMetadata={handleLoadedMetadata}
          onEnded={handleEnded}
        />
      )}

      {/* Play/Pause / Loading Button */}
      <button
        type="button"
        disabled={isLoading || !audioUrl}
        onClick={togglePlay}
        className={`w-9 h-9 rounded-full flex items-center justify-center transition-all ${
          isSender
            ? 'bg-white/20 hover:bg-white/30 text-white'
            : 'bg-sky-500/20 hover:bg-sky-500/30 text-sky-400 border border-sky-500/30'
        }`}
      >
        {isLoading ? (
          <RefreshCw className="w-4 h-4 animate-spin" />
        ) : isPlaying ? (
          <Pause className="w-4 h-4 fill-current" />
        ) : (
          <Play className="w-4 h-4 fill-current ml-0.5" />
        )}
      </button>

      {/* Waveform & Scrubber */}
      <div className="flex-1 space-y-1">
        <div className="flex items-center gap-0.5 h-6">
          {Array.from({ length: 24 }).map((_, i) => {
            const barHeight = 6 + Math.sin(i * 0.8) * 8 + (i % 3) * 4;
            const barProgress = (i / 24) * 100;
            const isFilled = barProgress <= progress;

            return (
              <div
                key={i}
                style={{ height: `${barHeight}px` }}
                className={`w-1 rounded-full transition-all ${
                  isFilled
                    ? isSender
                      ? 'bg-white'
                      : 'bg-sky-400'
                    : isSender
                    ? 'bg-white/30'
                    : 'bg-slate-700'
                }`}
              />
            );
          })}
        </div>

        <div className="flex items-center justify-between text-[10px] opacity-75 font-mono">
          <span className="flex items-center gap-1">
            <Volume2 className="w-2.5 h-2.5" />
            <span>Voice Note</span>
          </span>
          <span>{duration > 0 ? formatTime(duration) : '0:00'}</span>
        </div>
      </div>
    </div>
  );
}
