import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Upload,
  FileText,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Crosshair,
  File as FileIcon,
  X,
  CheckCircle2,
} from 'lucide-react';
import { ThreatRing } from '@/components/ThreatRing';
import { Card, SectionLabel, Badge } from '@/components/ui/Primitives';
import { useNavigate } from 'react-router-dom';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { cn } from '@/lib/utils';

// --- NEW API IMPORTS ---
import { scanEmail, getEmail } from '@/api/api';
import { mapApiEmailToUiEmail } from '@/api/emailMapper';
import { type ScannedEmail } from '@/data/mockData';

type ScannerPhase = 'idle' | 'scanning' | 'result';

const ACTIVITY_MESSAGES = [
  'Parsing email headers...',
  'Extracting sender information...',
  'Analyzing authentication...',
  'Extracting URLs...',
  'Analyzing domain indicators...',
  'Analyzing infrastructure...',
];

async function calculateSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ScannerPage() {
  const navigate = useNavigate();
  const { setLastViewed, refreshEmails } = useActiveCase();
  
  const [phase, setPhase] = useState<ScannerPhase>('idle');
  const [progress, setProgress] = useState(0);
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  
  const [hashReady, setHashReady] = useState(false);
  const [hash, setHash] = useState('');
  
  // --- LIVE DATA STATE ---
  const [analyzedEmail, setAnalyzedEmail] = useState<ScannedEmail | null>(null);
  const [isApiDone, setIsApiDone] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const confidence = analyzedEmail ? Math.min(99, Math.round(analyzedEmail.threatScore * 0.9 + 8)) : 0;

  const handleFileSelected = useCallback((file: File) => {
    setPendingFile(file);
    setHashReady(false);
    setHash('');
    setApiError(null);
    
    calculateSha256(file).then((realHash) => {
      setHash(realHash);
      setHashReady(true);
    });
  }, []);

  const clearPendingFile = () => {
    setPendingFile(null);
    setHashReady(false);
    setHash('');
    setApiError(null);
  };

  const startScan = useCallback(async () => {
    if (!pendingFile) return;
    setPhase('scanning');
    setProgress(0);
    setIsApiDone(false);
    setApiError(null);

    try {
      // 1. Post file to backend
      const scanResult = await scanEmail(pendingFile);
      
      // 2. Fetch the full mapped email details using returned ID
      const fullEmailDetails = await getEmail(scanResult.emailId);
      
      // 3. Map to UI format and store it
      setAnalyzedEmail(mapApiEmailToUiEmail(fullEmailDetails));
      
      // 4. Update the global list so the sidebar populates immediately
      await refreshEmails();
      
      setIsApiDone(true);
    } catch (err) {
      console.error(err);
      setApiError(err instanceof Error ? err.message : 'Scan failed');
      setIsApiDone(true);
    }
  }, [pendingFile, refreshEmails]);

  useEffect(() => {
    if (phase !== 'scanning') return;
    const interval = setInterval(() => {
      setProgress((p) => {
        // Stall the visual progress bar at 95% if API is still loading
        if (p >= 95 && !isApiDone) return 95;
        
        if (p >= 100) {
          clearInterval(interval);
          setTimeout(() => setPhase('result'), 400);
          return 100;
        }
        return p + 2.5;
      });
    }, 60);
    return () => clearInterval(interval);
  }, [phase, isApiDone]);

  const reset = () => {
    setPhase('idle');
    setProgress(0);
    clearPendingFile();
    setAnalyzedEmail(null);
  };

  const goToInvestigation = () => {
    if (!analyzedEmail) return;
    setLastViewed(analyzedEmail.id);
    navigate('/investigation', { state: { emailId: analyzedEmail.id } });
  };

  return (
    <div className="px-8 py-6 max-w-[1400px] mx-auto">
      <div className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-ink-50">Email Scanner</h1>
          <p className="text-xs text-ink-500 mt-1">Upload an email for live backend analysis</p>
        </div>
        {phase === 'result' && (
          <button
            onClick={reset}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[11px] font-medium text-ink-400 hover:text-ink-200 bg-base-800/60 border border-base-500/30 transition-colors uppercase tracking-wider"
          >
            <RefreshCw className="w-3 h-3" /> New Scan
          </button>
        )}
      </div>

      <div className="flex items-center gap-3 mb-6">
        <PhaseStep num="01" label="Upload" active={phase === 'idle'} done={phase !== 'idle'} />
        <PhaseConnector done={phase !== 'idle'} />
        <PhaseStep num="02" label="Analyze" active={phase === 'scanning'} done={phase === 'result'} />
        <PhaseConnector done={phase === 'result'} />
        <PhaseStep num="03" label="Result" active={phase === 'result'} done={false} />
      </div>

      {phase === 'idle' && (
        <UploadZone
          pendingFile={pendingFile}
          hash={hash}
          hashReady={hashReady}
          onFileSelected={handleFileSelected}
          onClearFile={clearPendingFile}
          onStartAnalysis={startScan}
        />
      )}

      {phase === 'scanning' && (
        <div className="space-y-4">
          <Card className="flex flex-col items-center justify-center py-16 min-h-[500px] relative overflow-hidden">
            <ThreatRing mode="scanning" progress={progress} size={360} />
            <div className="mt-8 text-center">
              <p className="text-[11px] text-ink-500 mono">
                Analyzing {pendingFile?.name}
              </p>
            </div>
          </Card>
          <ActivityFeed progress={progress} />
        </div>
      )}

      {phase === 'result' && (
        <div className="space-y-5">
          {apiError ? (
            <Card className="flex flex-col items-center justify-center py-20 border-accent-500/30 bg-accent-950/10">
              <AlertTriangle className="w-12 h-12 text-accent-500 mb-4" />
              <h3 className="text-lg font-bold text-accent-400">Analysis Failed</h3>
              <p className="text-sm text-ink-300 mt-2">{apiError}</p>
            </Card>
          ) : analyzedEmail ? (
            <>
              <div className="grid grid-cols-12 gap-5">
                <Card className="col-span-5 flex flex-col items-center justify-center py-10 min-h-[420px]">
                  <ThreatRing mode="result" score={analyzedEmail.threatScore} riskLevel={analyzedEmail.riskLevel} threatType={analyzedEmail.classification} size={320} />
                </Card>
                <div className="col-span-7 space-y-4">
                  <Card className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <SectionLabel>Scan Result</SectionLabel>
                      <div className="flex gap-2">
                        <Badge variant={analyzedEmail.threatScore >= 80 ? 'critical' : 'danger'}>{analyzedEmail.riskLevel}</Badge>
                        <Badge variant="danger">{analyzedEmail.classification}</Badge>
                        <Badge variant="neutral">Confidence {confidence}%</Badge>
                      </div>
                    </div>
                    <div className="space-y-3 text-sm">
                      <DataRow label="Subject" value={analyzedEmail.subject} />
                      <DataRow label="Sender" value={analyzedEmail.sender} mono />
                      <DataRow label="Date" value={analyzedEmail.date} mono />
                      <DataRow label="Size" value={pendingFile ? formatBytes(pendingFile.size) : 'Unknown'} mono />
                      <DataRow label="SPF" value={analyzedEmail.spf.toUpperCase()} danger={analyzedEmail.spf === 'fail'} />
                      <DataRow label="DKIM" value={analyzedEmail.dkim.toUpperCase()} danger={analyzedEmail.dkim === 'none'} />
                      <DataRow label="DMARC" value={analyzedEmail.dmarc.toUpperCase()} danger={analyzedEmail.dmarc === 'fail'} />
                    </div>
                  </Card>
                  
                  {analyzedEmail.whyFlagged.length > 0 && (
                    <Card className="p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <AlertTriangle className="w-3.5 h-3.5 text-accent-500" />
                        <SectionLabel>Primary Threats Detected</SectionLabel>
                      </div>
                      <ul className="space-y-2">
                        {analyzedEmail.whyFlagged.slice(0, 4).map((r, i) => (
                          <li key={i} className="flex items-start gap-2 text-[13px] text-ink-300">
                            <span className="mono text-[10px] text-accent-600 mt-0.5">{String(i + 1).padStart(2, '0')}</span>
                            {r}
                          </li>
                        ))}
                      </ul>
                    </Card>
                  )}
                </div>
              </div>

              <button
                onClick={goToInvestigation}
                className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl text-[13px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors"
              >
                <Crosshair className="w-4 h-4" /> Open Investigation
              </button>
            </>
          ) : null}
        </div>
      )}
    </div>
  );
}

function UploadZone({
  pendingFile,
  hash,
  hashReady,
  onFileSelected,
  onClearFile,
  onStartAnalysis,
}: {
  pendingFile: File | null;
  hash: string;
  hashReady: boolean;
  onFileSelected: (file: File) => void;
  onClearFile: () => void;
  onStartAnalysis: () => void;
}) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  
  const defaultSourceText = `From: Account Security Team <security@acc0unt-verify.net>\nTo: user@company.com\nSubject: Urgent: Account Security Verification Required\nDate: Sat, 23 Aug 2026 09:14:22 +0000\n\nClick here to verify your account immediately...`;
  const [rawSource, setRawSource] = useState(defaultSourceText);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFileSelected(file);
  };

  const handlePick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onFileSelected(file);
    e.target.value = '';
  };

  const handleUseSample = () => {
    const file = new File([defaultSourceText], "suspicious-invoice.eml", { type: "message/rfc822" });
    onFileSelected(file);
  };

  const handleAnalyzeSource = () => {
    const file = new File([rawSource], "pasted-source.eml", { type: "message/rfc822" });
    onFileSelected(file);
  };

  return (
    <div className="grid grid-cols-12 gap-5">
      <div className="col-span-8">
        <Card className="p-0">
          <input ref={inputRef} type="file" accept=".eml" className="hidden" onChange={handlePick} />

          {!pendingFile ? (
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => inputRef.current?.click()}
              role="button"
              tabIndex={0}
              className={cn(
                'w-full flex flex-col items-center justify-center py-20 border-2 border-dashed rounded-xl transition-all cursor-pointer group',
                dragOver ? 'border-accent-600/60 bg-accent-700/10' : 'border-base-400/40 hover:border-accent-700/40 hover:bg-accent-700/5'
              )}
            >
              <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-base-700 border border-base-500/40 group-hover:border-accent-700/40 group-hover:bg-accent-700/10 transition-all">
                <Upload className="w-6 h-6 text-ink-500 group-hover:text-accent-500 transition-colors" />
              </div>
              <div className="mt-5 text-center">
                <p className="text-sm font-medium text-ink-200">Drop email file here or click to browse</p>
                <p className="text-[11px] text-ink-600 mt-1">Supports .eml</p>
              </div>
            </div>
          ) : (
            <div className="p-6">
              <div className="flex items-start gap-4">
                <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-accent-700/10 border border-accent-700/25 shrink-0">
                  <FileIcon className="w-5 h-5 text-accent-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-ink-100 truncate">{pendingFile.name}</span>
                    <button
                      onClick={onClearFile}
                      className="flex items-center justify-center w-6 h-6 rounded-md text-ink-600 hover:text-ink-300 hover:bg-base-700/60 transition-colors shrink-0"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-3 mt-4">
                    <div className="panel-2 p-3">
                      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">File Size</div>
                      <div className="mono text-[12px] text-ink-200">{formatBytes(pendingFile.size)}</div>
                    </div>
                    <div className="panel-2 p-3">
                      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">SHA-256</div>
                      <div className="mono text-[11px] text-ink-300 truncate flex items-center gap-1.5">
                        {hashReady ? (
                          <>
                            <CheckCircle2 className="w-3 h-3 text-emerald-500 shrink-0" />
                            <span className="truncate">{hash}</span>
                          </>
                        ) : (
                          <span className="text-ink-600 animate-pulse">Calculating hash...</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <button
                onClick={onStartAnalysis}
                disabled={!hashReady}
                className={cn(
                  'mt-5 w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-[12px] font-bold uppercase tracking-wider transition-colors',
                  hashReady
                    ? 'text-ink-100 bg-accent-700/25 border border-accent-700/45 hover:bg-accent-700/35'
                    : 'text-ink-600 bg-base-800 border border-base-500/20 cursor-not-allowed'
                )}
              >
                Start Analysis <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <div className="flex items-center gap-4 px-5 py-3 border-t border-base-500/20">
            <button
              onClick={handleUseSample}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-bold text-ink-100 bg-accent-700/20 border border-accent-700/40 hover:bg-accent-700/30 transition-colors uppercase tracking-wider"
            >
              <FileText className="w-3.5 h-3.5 text-accent-400" />
              Use Sample Email
            </button>
            <span className="text-[10px] text-ink-600">or paste raw source in the panel →</span>
          </div>
        </Card>
      </div>

      <div className="col-span-4">
        <Card className="p-5 h-full">
          <SectionLabel className="block mb-3">Raw Email Source</SectionLabel>
          <textarea
            value={rawSource}
            onChange={(e) => setRawSource(e.target.value)}
            className="w-full h-72 bg-base-950/60 border border-base-500/20 rounded-lg p-3 text-[11px] mono text-ink-400 resize-none scrollbar-thin focus:outline-none focus:border-accent-700/30"
            placeholder="Paste raw email headers and body here..."
          />
          <button
            onClick={handleAnalyzeSource}
            className="mt-3 w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-[11px] font-bold text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors uppercase tracking-wider"
          >
            Analyze Source <ArrowRight className="w-3 h-3" />
          </button>
        </Card>
      </div>
    </div>
  );
}

function ActivityFeed({ progress }: { progress: number }) {
  const visibleCount = Math.min(
    ACTIVITY_MESSAGES.length,
    Math.max(1, Math.ceil((progress / 100) * ACTIVITY_MESSAGES.length))
  );

  return (
    <Card className="p-4">
      <SectionLabel className="block mb-2.5">Activity</SectionLabel>
      <div className="space-y-1.5">
        {ACTIVITY_MESSAGES.slice(0, visibleCount).map((msg, i) => {
          const isCurrent = i === visibleCount - 1 && progress < 100;
          return (
            <div key={msg} className="flex items-center gap-2 text-[11px] mono">
              {isCurrent ? (
                <span className="text-accent-500 animate-pulse shrink-0">▸</span>
              ) : (
                <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
              )}
              <span className={isCurrent ? 'text-ink-300' : 'text-ink-600'}>{msg}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function PhaseStep({ num, label, active, done }: { num: string; label: string; active: boolean; done: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <span
        className={cn(
          'mono text-[10px] font-bold w-6 h-6 flex items-center justify-center rounded-md border transition-all',
          done
            ? 'bg-accent-700/15 border-accent-700/30 text-accent-400'
            : active
            ? 'bg-base-700 border-base-400/40 text-ink-100'
            : 'bg-base-800 border-base-500/20 text-ink-600'
        )}
      >
        {num}
      </span>
      <span
        className={cn(
          'text-[11px] font-semibold uppercase tracking-wider transition-colors',
          done ? 'text-accent-400' : active ? 'text-ink-100' : 'text-ink-600'
        )}
      >
        {label}
      </span>
    </div>
  );
}

function PhaseConnector({ done }: { done: boolean }) {
  return (
    <div className={cn('h-px w-8 transition-colors', done ? 'bg-accent-700/40' : 'bg-base-500/30')} />
  );
}

function DataRow({ label, value, mono, danger }: { label: string; value: string; mono?: boolean; danger?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-base-500/15 last:border-0">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">{label}</span>
      <span className={cn('text-[13px]', mono && 'mono', danger ? 'text-accent-400 font-medium' : 'text-ink-200')}>
        {value}
      </span>
    </div>
  );
}