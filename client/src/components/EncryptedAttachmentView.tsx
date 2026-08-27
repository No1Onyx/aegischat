import { useState, useEffect } from 'react';
import { FileText, Download, RefreshCw, Maximize2, X } from 'lucide-react';
import { AttachmentCrypto } from '../crypto/attachments';
import type { EncryptedAttachmentDescriptor } from '../crypto/attachments';
import { AudioPlayer } from './AudioPlayer';

interface EncryptedAttachmentViewProps {
  descriptor: EncryptedAttachmentDescriptor;
  isSender: boolean;
}

export function EncryptedAttachmentView({ descriptor, isSender }: EncryptedAttachmentViewProps) {
  const [decryptedUrl, setDecryptedUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [showLightbox, setShowLightbox] = useState<boolean>(false);

  const isImage = descriptor.fileType.startsWith('image/');
  const isVoice = descriptor.isVoiceNote || descriptor.fileType.startsWith('audio/');

  useEffect(() => {
    let active = true;

    // Pre-decrypt images for inline viewing
    if (isImage) {
      setIsLoading(true);
      AttachmentCrypto.fetchAndDecrypt(descriptor)
        .then((url) => {
          if (active) setDecryptedUrl(url);
        })
        .catch((err) => console.error('Failed to decrypt attachment image:', err))
        .finally(() => {
          if (active) setIsLoading(false);
        });
    }

    return () => {
      active = false;
    };
  }, [descriptor, isImage]);

  const handleDownload = async () => {
    try {
      setIsLoading(true);
      const url = decryptedUrl || (await AttachmentCrypto.fetchAndDecrypt(descriptor));
      setDecryptedUrl(url);

      const a = document.createElement('a');
      a.href = url;
      a.download = descriptor.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      alert('Error downloading file: ' + (err as Error).message);
    } finally {
      setIsLoading(false);
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // 1. Voice Note
  if (isVoice) {
    return <AudioPlayer descriptor={descriptor} isSender={isSender} />;
  }

  // 2. Encrypted Image Preview
  if (isImage) {
    return (
      <div className="space-y-1.5 pt-1">
        <div className="relative rounded-xl overflow-hidden bg-slate-950/80 border border-slate-700/50 max-w-[280px] max-h-[220px] flex items-center justify-center group cursor-pointer">
          {isLoading ? (
            <div className="p-8 flex flex-col items-center justify-center gap-2 text-xs text-slate-400">
              <RefreshCw className="w-5 h-5 animate-spin text-sky-400" />
              <span>Decrypting Image...</span>
            </div>
          ) : decryptedUrl ? (
            <div onClick={() => setShowLightbox(true)} className="relative w-full">
              <img
                src={decryptedUrl}
                alt={descriptor.fileName}
                className="w-full h-auto max-h-[220px] object-cover rounded-xl"
              />
              <div className="absolute inset-0 bg-black/30 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                <Maximize2 className="w-5 h-5 text-white" />
              </div>
            </div>
          ) : (
            <div className="p-4 text-xs text-rose-400">Failed to decrypt</div>
          )}
        </div>

        {/* Lightbox Modal */}
        {showLightbox && decryptedUrl && (
          <div
            className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4 backdrop-blur-md"
            onClick={() => setShowLightbox(false)}
          >
            <div className="relative max-w-4xl max-h-[90vh]">
              <button
                type="button"
                onClick={() => setShowLightbox(false)}
                className="absolute -top-10 right-0 p-2 text-white hover:text-rose-400 transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
              <img
                src={decryptedUrl}
                alt={descriptor.fileName}
                className="max-h-[85vh] max-w-full rounded-2xl shadow-2xl object-contain"
              />
            </div>
          </div>
        )}
      </div>
    );
  }

  // 3. Document / File Card
  return (
    <div className="flex items-center gap-3 p-2.5 rounded-xl bg-slate-950/60 border border-slate-700/50 max-w-xs mt-1">
      <div className="p-2.5 rounded-lg bg-sky-500/20 text-sky-400">
        <FileText className="w-5 h-5" />
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-slate-200 truncate">{descriptor.fileName}</p>
        <p className="text-[10px] text-slate-400 font-mono">{formatSize(descriptor.fileSize)}</p>
      </div>

      <button
        type="button"
        disabled={isLoading}
        onClick={handleDownload}
        className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all"
        title="Decrypt & Download"
      >
        {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
      </button>
    </div>
  );
}
