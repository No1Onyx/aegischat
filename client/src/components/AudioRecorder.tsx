import { useState, useEffect, useRef } from 'react';
import { Trash2, Send } from 'lucide-react';

interface AudioRecorderProps {
  onRecordingComplete: (blob: Blob, durationSec: number) => void;
  onCancel: () => void;
}

export function AudioRecorder({ onRecordingComplete, onCancel }: AudioRecorderProps) {
  const [seconds, setSeconds] = useState<number>(0);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;

    async function startRecording() {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const mediaRecorder = new MediaRecorder(stream);
        mediaRecorderRef.current = mediaRecorder;
        audioChunksRef.current = [];

        mediaRecorder.ondataavailable = (event) => {
          if (event.data.size > 0) {
            audioChunksRef.current.push(event.data);
          }
        };

        mediaRecorder.start();

        timerRef.current = window.setInterval(() => {
          setSeconds((prev) => prev + 1);
        }, 1000);
      } catch (err) {
        console.error('Microphone access error:', err);
        alert('Could not access microphone: ' + (err as Error).message);
        onCancel();
      }
    }

    startRecording();

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
        mediaRecorderRef.current.stop();
      }
      if (stream) {
        stream.getTracks().forEach((track) => track.stop());
      }
    };
  }, [onCancel]);

  const handleSend = () => {
    if (!mediaRecorderRef.current) return;

    mediaRecorderRef.current.onstop = () => {
      const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
      onRecordingComplete(audioBlob, seconds);
    };

    mediaRecorderRef.current.stop();
  };

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const s = Math.floor(secs % 60);
    return `${mins}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <div className="flex items-center gap-3 bg-slate-900 border border-slate-800 rounded-xl px-4 py-2 w-full animate-fadeIn">
      {/* Blinking Recording Light */}
      <div className="flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping" />
        <span className="text-xs font-mono font-bold text-rose-400">
          {formatTime(seconds)}
        </span>
      </div>

      {/* Voice Wave Animation */}
      <div className="flex-1 flex items-center justify-center gap-1 h-5">
        {Array.from({ length: 16 }).map((_, i) => (
          <div
            key={i}
            className="w-1 bg-rose-500/80 rounded-full animate-pulse"
            style={{
              height: `${4 + Math.sin(seconds * 2 + i) * 12 + 6}px`,
              animationDelay: `${i * 0.08}s`,
            }}
          />
        ))}
      </div>

      {/* Actions: Cancel or Send */}
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={onCancel}
          className="p-2 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-all"
          title="Cancel Recording"
        >
          <Trash2 className="w-4 h-4" />
        </button>

        <button
          type="button"
          onClick={handleSend}
          className="px-3 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-rose-950 transition-all"
          title="Send Encrypted Voice Note"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Send</span>
        </button>
      </div>
    </div>
  );
}
