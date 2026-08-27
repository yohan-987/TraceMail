import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  FileSearch,
  User,
  Shield,
  Network,
  Copy,
  CheckCircle,
  XCircle,
  AlertCircle,
  Paperclip,
  Info,
  Flag,
  Eye,
  Sparkles,
} from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import {
  InvestigationWorkspace,
  PreviewField,
  AuthChip,
  PreviewInvestigateButton,
} from '@/components/InvestigationWorkspace';
import { cn } from '@/lib/utils';
import { getEmail as fetchEmailDetails } from '@/api/api';

// --- TYPES ---
interface BackendEmailDetail {
  emailId: string;
  caseId: string | null;
  score: number;
  level: string;
  classification: string;
  evidence?: {
    sha256?: string;
    createdAt?: string;
    fileSizeBytes?: number;
  };
  parsedEmail?: {
    subject?: string;
    from?: Array<{ email?: string; displayName?: string; localPart?: string; domain?: string }>;
    to?: Array<{ email?: string }>;
    date?: string;
    headers?: { raw?: Array<{ name: string; value: string }>; normalized?: Record<string, string> };
    attachments?: Array<{ filename?: string; contentType?: string; mimeType?: string; size?: number; sha256?: string; hash?: string }>;
  };
  headerAnalysis?: {
    anomalies?: Array<{ message: string }>;
    receivedChain?: Array<{ hop: number; fromHostname?: string; fromIp?: string; fromIpClassification?: string; byHostname?: string; timestampIso?: string; timestampRaw?: string; rawHeader?: string }>;
  };
  authentication?: {
    spf?: { result: string };
    dkim?: { result: string };
    dmarc?: { result: string };
  };
  explanations?: Array<{ message: string }>;
}

export interface MappedForensicEmail {
  id: string;
  caseId: string;
  subject: string;
  sender: string;
  senderName: string;
  senderDomain: string;
  recipient: string;
  date: string;
  size: string;
  threatScore: number;
  status: 'safe' | 'suspicious' | 'malicious' | 'inconclusive';
  classification: string;
  riskLevel: string;
  threatSummary: string;
  spf: string;
  dkim: string;
  dmarc: string;
  authenticationSummary: string;
  whyFlagged: string[];
  senderAnomalies: string[];
  headers: Array<{ name: string; value: string }> | Record<string, string>;
  receivedChain: Array<any>;
  attachments: Array<any>;
  evidenceSha256: string;
  indicators: any[];
  infraNodes: any[];
  infraEdges: any[];
  geoData: any[];
  reportSections: any[];
}

const tabs = [
  { key: 'headers', label: 'Headers', icon: FileSearch },
  { key: 'sender', label: 'Sender Identity', icon: User },
  { key: 'auth', label: 'Authentication', icon: Shield },
  { key: 'chain', label: 'Received Chain', icon: Network },
  { key: 'attachments', label: 'Attachments', icon: Paperclip },
  { key: 'flagged', label: 'Why Flagged', icon: Flag },
];

function normalizeEmailStatus(value: unknown): 'safe' | 'suspicious' | 'malicious' | 'inconclusive' {
  const status = String(value ?? '').toLowerCase();
  if (status === 'malicious' || status === 'critical' || status === 'high') return 'malicious';
  if (status === 'suspicious' || status === 'moderate') return 'suspicious';
  if (status === 'inconclusive') return 'inconclusive';
  return 'safe';
}

function getHeaderValue(headers: any, key: string): string {
  if (Array.isArray(headers)) {
    const found = headers.find((h: { name: string; value: string }) => h.name.toLowerCase() === key.toLowerCase());
    if (!found) return 'N/A';
    const regex = new RegExp(`^${key}:\\s*`, 'i');
    return found.value.replace(regex, '').trim();
  }
  return headers?.[key] || headers?.[key.toLowerCase()] || 'N/A';
}

function getAuthState(status: string) {
  switch (status.toLowerCase()) {
    case 'fail':
    case 'softfail':
      return 'fail';
    case 'pass':
      return 'pass';
    case 'none':
    case 'neutral':
    case 'unknown':
    case 'temperror':
    case 'permerror':
    default:
      return 'neutral';
  }
}

function mapDetailedApiToScannedEmail(apiData: BackendEmailDetail): MappedForensicEmail {
  const fromObj = apiData.parsedEmail?.from?.[0] || {};
  const toObj = apiData.parsedEmail?.to?.[0] || {};

  const mappedChain = (apiData.headerAnalysis?.receivedChain || []).map((hop) => ({
    hop: hop.hop,
    fromHostname: hop.fromHostname,
    fromIp: hop.fromIp,
    fromIpClassification: hop.fromIpClassification,
    byHostname: hop.byHostname,
    timestampIso: hop.timestampIso,
    timestampRaw: hop.timestampRaw,
    rawHeader: hop.rawHeader
  }));

  return {
    id: apiData.emailId || '',
    caseId: apiData.caseId ?? '',
    
    subject: apiData.parsedEmail?.subject || 'No Subject',
    sender: fromObj.email || 'Unknown Sender',
    senderName: fromObj.displayName || fromObj.localPart || 'Unknown',
    senderDomain: fromObj.domain || 'Unknown',
    recipient: toObj.email || '',
    date: apiData.parsedEmail?.date || apiData.evidence?.createdAt || '',
    size: apiData.evidence?.fileSizeBytes ? `${apiData.evidence.fileSizeBytes} B` : 'Unknown',
    
    threatScore: apiData.score ?? 0,
    status: normalizeEmailStatus(apiData.level),
    classification: apiData.classification || 'Unknown',
    riskLevel: (apiData.level || 'UNKNOWN').toUpperCase(),
    threatSummary: '',
    
    spf: (apiData.authentication?.spf?.result || 'none').toLowerCase(),
    dkim: (apiData.authentication?.dkim?.result || 'none').toLowerCase(),
    dmarc: (apiData.authentication?.dmarc?.result || 'none').toLowerCase(),
    authenticationSummary: `SPF: ${apiData.authentication?.spf?.result || 'none'}, DKIM: ${apiData.authentication?.dkim?.result || 'none'}, DMARC: ${apiData.authentication?.dmarc?.result || 'none'}`,
    
    whyFlagged: apiData.explanations?.map((e) => e.message) || [],
    senderAnomalies: apiData.headerAnalysis?.anomalies?.map((a) => a.message) || [],
    
    headers: apiData.parsedEmail?.headers?.raw || apiData.parsedEmail?.headers?.normalized || {},
    receivedChain: mappedChain,
    attachments: apiData.parsedEmail?.attachments || [],
    evidenceSha256: apiData.evidence?.sha256 || 'N/A',
    
    indicators: [],
    infraNodes: [],
    infraEdges: [],
    geoData: [],
    reportSections: []
  };
}

export function ForensicsPage() {
  const location = useLocation();
  const { setLastViewed, availableEmails } = useActiveCase();
  
  const [forensicsSelectedEmailId, setForensicsSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );
  const [activeTab, setActiveTab] = useState<string>('headers');

  const [activeEmail, setActiveEmail] = useState<MappedForensicEmail | null>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);

  useEffect(() => {
    if (!forensicsSelectedEmailId) {
      setActiveEmail(null);
      return;
    }

    let cancelled = false;
    setIsLoadingDetails(true);
    setDetailsError(null);

    fetchEmailDetails(forensicsSelectedEmailId)
      .then((data) => {
        if (!cancelled) setActiveEmail(mapDetailedApiToScannedEmail(data));
      })
      .catch((err) => {
        if (!cancelled) setDetailsError(err instanceof Error ? err.message : 'Failed to load email details');
      })
      .finally(() => {
        if (!cancelled) setIsLoadingDetails(false);
      });

    return () => {
      cancelled = true;
    };
  }, [forensicsSelectedEmailId]);

  const handleInvestigate = (email: any) => {
    setForensicsSelectedEmailId(email.id);
    setLastViewed(email.id);
  };

  return (
    <InvestigationShell
      breadcrumb="Email Forensics"
      title="Email Forensics"
      subtitle={activeEmail ? `${activeEmail.id} · ${activeEmail.sender}` : undefined}
      actions={activeEmail ? <Badge variant={activeEmail.threatScore >= 60 ? 'danger' : 'neutral'}>{activeEmail.classification}</Badge> : undefined}
      hideCaseSelector={!activeEmail}
      selectedEmail={activeEmail as any}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setForensicsSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setForensicsSelectedEmailId(null)}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'forensics' } : undefined}
    >
      {isLoadingDetails ? (
        <div className="flex items-center justify-center h-[500px] w-full text-ink-400 font-mono text-sm animate-pulse">
          Fetching forensic details...
        </div>
      ) : detailsError ? (
        <div className="flex items-center justify-center h-[500px] w-full text-accent-500 font-mono text-sm">
          Error: {detailsError}
        </div>
      ) : !activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderForensicsPreview as any} />
      ) : (
        <div key={activeEmail.id} className="animate-fade-in">
          <div className="flex items-center gap-1 mb-5 border-b border-base-500/20 overflow-x-auto">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2.5 text-[12px] font-medium transition-all border-b-2 -mb-px whitespace-nowrap',
                    activeTab === tab.key
                      ? 'text-accent-400 border-accent-600'
                      : 'text-ink-500 border-transparent hover:text-ink-300'
                  )}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {activeTab === 'headers' && <HeadersView headers={activeEmail.headers} />}
          {activeTab === 'sender' && <SenderView email={activeEmail} />}
          {activeTab === 'auth' && <AuthView email={activeEmail} />}
          {activeTab === 'chain' && <ChainView chain={activeEmail.receivedChain} />}
          {activeTab === 'attachments' && <AttachmentsView email={activeEmail} />}
          {activeTab === 'flagged' && <WhyFlaggedView email={activeEmail} />}
        </div>
      )}
    </InvestigationShell>
  );
}

function HeadersView({ headers }: { headers: any }) {
  const isArray = Array.isArray(headers);
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-base-500/20">
        <SectionLabel>Raw Headers</SectionLabel>
        <button className="flex items-center gap-1.5 text-[10px] font-medium text-ink-500 hover:text-ink-300 transition-colors uppercase tracking-wider">
          <Copy className="w-3 h-3" /> Copy
        </button>
      </div>
      <div className="divide-y divide-base-500/10">
        {isArray ? (
          headers.map((h: { name: string; value: string }, i: number) => (
            <div key={i} className="flex items-start px-5 py-3 hover:bg-base-700/30 transition-colors">
              <div className="w-44 shrink-0">
                <span className="text-[11px] font-semibold text-ink-400 mono">{h.name}</span>
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-[12px] text-ink-300 mono break-all">{h.value}</span>
              </div>
            </div>
          ))
        ) : (
          Object.entries(headers || {}).map(([key, value]) => (
            <div key={key} className="flex items-start px-5 py-3 hover:bg-base-700/30 transition-colors">
              <div className="w-44 shrink-0">
                <span className="text-[11px] font-semibold text-ink-400 mono">
                  {key.replace(/-/g, ' ')}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-[12px] text-ink-300 mono break-all">{String(value)}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function SenderView({ email }: { email: MappedForensicEmail }) {
  const replyTo = getHeaderValue(email.headers, 'Reply-To');
  const returnPath = getHeaderValue(email.headers, 'Return-Path');
  const xMailer = getHeaderValue(email.headers, 'X-Mailer');
  const messageId = getHeaderValue(email.headers, 'Message-ID');
  const mimeVersion = getHeaderValue(email.headers, 'MIME-Version');
  const contentType = getHeaderValue(email.headers, 'Content-Type');

  return (
    <div className="grid grid-cols-12 gap-5">
      <Card className="col-span-7 p-5">
        <div className="flex items-center gap-2 mb-4">
          <User className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Sender Identity Analysis</SectionLabel>
        </div>
        <div className="space-y-3">
          <Field label="Display Name" value={email.senderName} danger={email.senderAnomalies.length > 0} note={email.senderAnomalies[0]} />
          <Field label="From Address" value={email.sender} mono danger={email.senderAnomalies.length > 0} />
          <Field label="Reply-To" value={replyTo} mono danger={replyTo !== 'N/A' && replyTo !== email.sender} note={replyTo !== email.sender ? 'Differs from From address' : undefined} />
          <Field label="Return-Path" value={returnPath} mono />
          <Field label="X-Mailer" value={xMailer} mono note={xMailer.includes('PHPMailer') || xMailer.includes('RoundCube') ? 'Commonly used in phishing kits' : undefined} danger={xMailer.includes('PHPMailer')} />
        </div>
      </Card>
      <Card className="col-span-5 p-5">
        <div className="flex items-center gap-2 mb-4">
          <AlertCircle className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Identity Anomalies</SectionLabel>
        </div>
        {email.senderAnomalies.length > 0 ? (
          <div className="space-y-3">
            {email.senderAnomalies.map((anomaly: string, i: number) => (
              <Anomaly key={i} text={anomaly} />
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[12px] text-emerald-400">
            <CheckCircle className="w-3.5 h-3.5" />
            No sender identity anomalies detected
          </div>
        )}
      </Card>

      <Card className="col-span-12 p-5">
        <div className="flex items-center gap-2 mb-4">
          <Info className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Message Metadata</SectionLabel>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <Field label="Message-ID" value={messageId} mono />
          <Field label="Date" value={email.date} mono />
          <Field label="MIME Version" value={mimeVersion} mono />
          <Field label="Size" value={email.size} mono />
          <Field label="Content-Type" value={contentType} mono />
          <Field label="Subject" value={email.subject} />
          <Field label="Threat Score" value={String(email.threatScore)} valueClassName={email.threatScore >= 60 ? 'text-accent-400' : 'text-emerald-400'} />
          <Field label="Case ID" value={email.caseId || 'No Case Assigned'} mono />
        </div>
      </Card>
    </div>
  );
}

function AuthView({ email }: { email: MappedForensicEmail }) {
  return (
    <div>
      <div className="grid grid-cols-3 gap-5">
        <AuthCard label="SPF" status={email.spf} description="Sender Policy Framework — verifies sending IP is authorized for the domain" />
        <AuthCard label="DKIM" status={email.dkim} description="DomainKeys Identified Mail — cryptographic signature verification" />
        <AuthCard label="DMARC" status={email.dmarc} description="Domain-based Message Authentication — alignment of SPF/DKIM with From domain" />
      </div>
      <Card className="mt-5 p-5">
        <SectionLabel className="block mb-2">Authentication Summary</SectionLabel>
        <p className="text-[13px] text-ink-400 leading-relaxed">{email.authenticationSummary}</p>
      </Card>
    </div>
  );
}

function ChainView({ chain }: { chain: any[] }) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <Network className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Received Chain</SectionLabel>
        </div>
        <div className="flex items-center gap-3 text-[9px] uppercase tracking-wider text-ink-600">
          <span className="flex items-center gap-1"><Eye className="w-2.5 h-2.5 text-ink-500" /> Observed (from headers)</span>
        </div>
      </div>
      {chain && chain.length > 0 ? (
        <div className="space-y-0">
          {chain.map((hop, i) => (
            <div key={i} className="flex gap-4">
              <div className="flex flex-col items-center">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent-700/10 border border-accent-700/20">
                  <span className="mono text-[11px] font-bold text-accent-400">{hop.hop}</span>
                </div>
                {i < chain.length - 1 && <div className="w-px h-16 bg-base-500/30 my-1" />}
              </div>
              <div className="flex-1 pb-6">
                <div className="panel-2 p-4">
                  <div className="grid grid-cols-2 gap-4">
                    <ChainField label="From Host" value={hop.fromHostname || 'Unknown'} mono />
                    <ChainField label="From IP" value={hop.fromIp || 'Unknown'} mono />
                    <ChainField label="By Host" value={hop.byHostname || 'Unknown'} mono />
                    <ChainField label="Timestamp" value={hop.timestampIso || hop.timestampRaw || 'Unknown'} mono />
                  </div>
                  {hop.fromIpClassification && (
                    <div className="mt-3 pt-3 border-t border-base-500/15 flex items-center gap-3">
                      <span className="section-label">IP Classification</span>
                      <Badge variant="neutral">{hop.fromIpClassification}</Badge>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-[12px] text-ink-600 text-center py-8">No received chain data available</div>
      )}
    </Card>
  );
}

function AttachmentsView({ email }: { email: MappedForensicEmail }) {
  const attachments = email.attachments || [];
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <Paperclip className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Attachments</SectionLabel>
        </div>
        <Badge variant="neutral">{attachments.length} found</Badge>
      </div>
      {attachments.length > 0 ? (
        <div className="space-y-3">
          {attachments.map((att: any, i: number) => (
            <div key={i} className="panel-2 p-4">
              <div className="flex items-start gap-3">
                <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/10 border border-accent-700/25 shrink-0">
                  <Paperclip className="w-4 h-4 text-accent-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold text-ink-100 mono">{att.filename || `attachment-${i + 1}`}</div>
                  <div className="grid grid-cols-3 gap-3 mt-3">
                    <ChainField label="MIME Type" value={att.contentType || att.mimeType || 'application/octet-stream'} mono />
                    <ChainField label="Size" value={att.size ? `${att.size} B` : 'Unknown'} />
                    <ChainField label="SHA-256" value={att.sha256 || att.hash || 'N/A'} mono />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center gap-2 text-[12px] text-emerald-400">
          <CheckCircle className="w-3.5 h-3.5" /> No attachments detected on this email
        </div>
      )}
    </Card>
  );
}

function WhyFlaggedView({ email }: { email: MappedForensicEmail }) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Flag className="w-3.5 h-3.5 text-accent-500" />
        <SectionLabel>Why Flagged</SectionLabel>
      </div>
      {email.whyFlagged.length > 0 ? (
        <ul className="space-y-3">
          {email.whyFlagged.map((reason: string, i: number) => (
            <li key={i} className="flex items-start gap-3 text-[13px] text-ink-300 leading-relaxed">
              <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">
                {String(i + 1).padStart(2, '0')}
              </span>
              <span>{reason}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="flex items-center gap-2 text-[12px] text-emerald-400">
          <CheckCircle className="w-3.5 h-3.5" /> No flags raised for this email
        </div>
      )}
    </Card>
  );
}

function AuthCard({ label, status, description }: { label: string; status: string; description: string }) {
  const state = getAuthState(status);
  
  return (
    <Card className={cn('p-5', state === 'fail' && 'border-accent-700/20')}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-bold text-ink-200">{label}</span>
        {state === 'fail' && <XCircle className="w-5 h-5 text-accent-500" />}
        {state === 'pass' && <CheckCircle className="w-5 h-5 text-emerald-500" />}
        {state === 'neutral' && <Info className="w-5 h-5 text-ink-500" />}
      </div>
      <div className={cn(
        'mono text-2xl font-bold uppercase mb-3', 
        state === 'fail' ? 'text-accent-400' : state === 'pass' ? 'text-emerald-400' : 'text-ink-400'
      )}>
        {status}
      </div>
      <Divider className="my-3" />
      <p className="text-[11px] text-ink-500 leading-relaxed">{description}</p>
    </Card>
  );
}

function Field({ label, value, mono, note, danger, valueClassName }: { label: string; value: string; mono?: boolean; note?: string; danger?: boolean; valueClassName?: string }) {
  return (
    <div className="panel-2 p-3.5">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">{label}</span>
        {danger && <span className="w-1.5 h-1.5 rounded-full bg-accent-600 accent-glow-sm" />}
      </div>
      <div className={cn('text-[13px] truncate', mono ? 'mono' : '', valueClassName ?? (danger ? 'text-accent-300' : 'text-ink-200'))}>
        {value}
      </div>
      {note && <div className="text-[10px] text-ink-600 mt-1">{note}</div>}
    </div>
  );
}

function Anomaly({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2.5">
      <span className="mono text-[10px] text-accent-600 mt-0.5">!</span>
      <span className="text-[12px] text-ink-400 leading-relaxed">{text}</span>
    </div>
  );
}

function ChainField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="section-label mb-1">{label}</div>
      <div className={cn('text-[11px] text-ink-300 break-all', mono && 'mono')}>{value}</div>
    </div>
  );
}

function renderForensicsPreview(email: MappedForensicEmail, onInvestigate: () => void) {
  const replyTo = getHeaderValue(email.headers, 'Reply-To');
  const returnPath = getHeaderValue(email.headers, 'Return-Path');
  const messageId = getHeaderValue(email.headers, 'Message-ID');
  const replyToMismatch = !!replyTo && replyTo !== 'N/A' && replyTo !== email.sender;
  const attachmentCount = (email.attachments || []).length;
  const isThreat = email.threatScore >= 60;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Forensics Preview</SectionLabel>
        <Badge variant={isThreat ? 'danger' : 'neutral'}>Score {email.threatScore}</Badge>
      </div>

      <div className="flex items-start gap-3 mb-4">
        <User className="w-5 h-5 mt-0.5 shrink-0 text-ink-400" />
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">{email.subject}</div>
          <div className="mono text-[10px] text-ink-500 mt-1 truncate">{email.sender}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2.5 mb-4">
        <PreviewField
          label="Reply-To"
          value={replyTo || 'N/A'}
          mono
          valueClassName={replyToMismatch ? 'text-accent-400' : undefined}
        />
        <PreviewField label="Return-Path" value={returnPath || 'N/A'} mono />
        <PreviewField label="Message-ID" value={messageId || 'N/A'} mono />
      </div>

      <Divider className="mb-4" />

      <SectionLabel className="block mb-2.5">Authentication</SectionLabel>
      <div className="flex items-center gap-2 mb-4">
        <AuthChip label="SPF" status={email.spf} />
        <AuthChip label="DKIM" status={email.dkim} />
        <AuthChip label="DMARC" status={email.dmarc} />
      </div>

      <div className="grid grid-cols-1 gap-2.5 mb-4">
        <PreviewField label="Attachments" value={String(attachmentCount)} />
      </div>

      <SectionLabel className="block mb-2.5">Major Header Anomalies</SectionLabel>
      {email.senderAnomalies.length > 0 ? (
        <ul className="space-y-2 mb-5">
          {email.senderAnomalies.slice(0, 4).map((a: string, i: number) => (
            <li key={i} className="flex items-start gap-2 text-[11px] text-ink-400 leading-relaxed">
              <span className="mono text-[9px] text-accent-600 mt-0.5 shrink-0">!</span>
              <span>{a}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="flex items-center gap-2 text-[12px] text-emerald-400 mb-5">
          <CheckCircle className="w-3.5 h-3.5" /> No sender anomalies
        </div>
      )}

      <PreviewInvestigateButton label="Open Full Forensics" onClick={onInvestigate} />
    </div>
  );
}