import { useState, useMemo } from 'react';
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
import type { ScannedEmail, ThreatIndicator } from '@/data/mockData';
import { cn } from '@/lib/utils';

const tabs = [
  { key: 'headers', label: 'Headers', icon: FileSearch },
  { key: 'sender', label: 'Sender Identity', icon: User },
  { key: 'auth', label: 'Authentication', icon: Shield },
  { key: 'chain', label: 'Received Chain', icon: Network },
  { key: 'attachments', label: 'Attachments', icon: Paperclip },
  { key: 'flagged', label: 'Why Flagged', icon: Flag },
];

/**
 * Attachments aren't a separate field in the mock dataset — we derive them
 * from the existing Hash-type / "Attachment Analysis" indicators already on
 * each email, plus a filename pulled from the existing whyFlagged text where
 * one is quoted. No new mock dataset introduced; size is reported as
 * "Unknown" where the underlying data genuinely doesn't include it.
 */
function extractAttachments(email: ScannedEmail) {
  const hashIndicators = email.indicators.filter(
    (i): i is ThreatIndicator => i.type === 'Hash' && i.source.toLowerCase().includes('attachment')
  );
  const filenameMatch = email.whyFlagged.join(' ').match(/"([^"]+\.\w+)"/);
  const filename = filenameMatch ? filenameMatch[1] : null;
  const ext = filename?.split('.').pop()?.toLowerCase();
  const mimeMap: Record<string, string> = {
    docm: 'application/vnd.ms-word.document.macroEnabled.12',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    pdf: 'application/pdf',
    xlsm: 'application/vnd.ms-excel.sheet.macroEnabled.12',
    xls: 'application/vnd.ms-excel',
    zip: 'application/zip',
    exe: 'application/x-msdownload',
  };
  return hashIndicators.map((ind, i) => ({
    filename: filename ?? `attachment-${i + 1}.${ext ?? 'bin'}`,
    mimeType: (ext && mimeMap[ext]) ?? 'application/octet-stream',
    hash: ind.value,
    tags: ind.tags,
  }));
}

export function ForensicsPage() {
  // Locally-owned selection — this page's own `forensicsSelectedEmailId`.
  // Not shared with Indicators/Infrastructure/AI/Reports.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [forensicsSelectedEmailId, setForensicsSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );
  const [activeTab, setActiveTab] = useState<string>('headers');

  const activeEmail = useMemo(() => getEmail(forensicsSelectedEmailId), [getEmail, forensicsSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
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
      selectedEmail={activeEmail}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setForensicsSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setForensicsSelectedEmailId(null)}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'forensics' } : undefined}
    >
      {!activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderForensicsPreview} />
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

function HeadersView({ headers }: { headers: Record<string, string> }) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-base-500/20">
        <SectionLabel>Raw Headers</SectionLabel>
        <button className="flex items-center gap-1.5 text-[10px] font-medium text-ink-500 hover:text-ink-300 transition-colors uppercase tracking-wider">
          <Copy className="w-3 h-3" /> Copy
        </button>
      </div>
      <div className="divide-y divide-base-500/10">
        {Object.entries(headers).map(([key, value]) => (
          <div key={key} className="flex items-start px-5 py-3 hover:bg-base-700/30 transition-colors">
            <div className="w-44 shrink-0">
              <span className="text-[11px] font-semibold text-ink-400 mono">
                {key.replace(/-/g, ' ')}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <span className="text-[12px] text-ink-300 mono break-all">{value}</span>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SenderView({ email }: { email: ScannedEmail }) {
  const replyTo = email.headers?.['Reply-To'] || 'N/A';
  const returnPath = email.headers?.['Return-Path'] || 'N/A';
  const xMailer = email.headers?.['X-Mailer'] || 'N/A';
  const messageId = email.headers?.['Message-ID'] || 'N/A';
  const mimeVersion = email.headers?.['MIME-Version'] || 'N/A';
  const contentType = email.headers?.['Content-Type'] || 'N/A';

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
            {email.senderAnomalies.map((anomaly, i) => (
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
          <Field label="Case ID" value={email.caseId || email.id} mono />
        </div>
      </Card>
    </div>
  );
}

function AuthView({ email }: { email: ScannedEmail }) {
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

function ChainView({ chain }: { chain: ScannedEmail['receivedChain'] }) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <Network className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Received Chain</SectionLabel>
        </div>
        <div className="flex items-center gap-3 text-[9px] uppercase tracking-wider text-ink-600">
          <span className="flex items-center gap-1"><Eye className="w-2.5 h-2.5 text-ink-500" /> Observed (from headers)</span>
          <span className="flex items-center gap-1"><Sparkles className="w-2.5 h-2.5 text-amber-500" /> Inferred (pattern-based)</span>
        </div>
      </div>
      {chain.length > 0 ? (
        <div className="space-y-0">
          {chain.map((hop, i) => {
            const isForged = hop.from.includes('unknown');
            return (
              <div key={i} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent-700/10 border border-accent-700/20">
                    <span className="mono text-[11px] font-bold text-accent-400">{hop.hop}</span>
                  </div>
                  {i < chain.length - 1 && <div className="w-px h-16 bg-base-500/30 my-1" />}
                </div>
                <div className="flex-1 pb-6">
                  <div className="panel-2 p-4">
                    <div className="flex items-center gap-1.5 mb-3 text-[9px] uppercase tracking-wider text-ink-600">
                      <Eye className="w-2.5 h-2.5 text-ink-500" /> Observed header evidence
                    </div>
                    <div className="grid grid-cols-3 gap-4">
                      <ChainField label="From" value={hop.from} mono />
                      <ChainField label="By" value={hop.by} mono />
                      <ChainField label="Timestamp" value={hop.timestamp} mono />
                    </div>
                    <div className="mt-3 pt-3 border-t border-base-500/15 flex items-center gap-3">
                      <span className="section-label">Delay</span>
                      <span className="mono text-[11px] text-ink-400">{hop.delay}</span>
                      {isForged && (
                        <Badge variant="warning" className="ml-auto">
                          <Sparkles className="w-2.5 h-2.5" /> Inferred: Forged Hop
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-[12px] text-ink-600 text-center py-8">No received chain data available</div>
      )}
    </Card>
  );
}

function AttachmentsView({ email }: { email: ScannedEmail }) {
  const attachments = extractAttachments(email);
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
          {attachments.map((att, i) => (
            <div key={i} className="panel-2 p-4">
              <div className="flex items-start gap-3">
                <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/10 border border-accent-700/25 shrink-0">
                  <Paperclip className="w-4 h-4 text-accent-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold text-ink-100 mono">{att.filename}</div>
                  <div className="grid grid-cols-3 gap-3 mt-3">
                    <ChainField label="MIME Type" value={att.mimeType} mono />
                    <ChainField label="Size" value="Unknown" />
                    <ChainField label="SHA-256" value={att.hash} mono />
                  </div>
                  {att.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {att.tags.map((tag) => (
                        <Badge key={tag} variant="warning">{tag}</Badge>
                      ))}
                    </div>
                  )}
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

function WhyFlaggedView({ email }: { email: ScannedEmail }) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Flag className="w-3.5 h-3.5 text-accent-500" />
        <SectionLabel>Why Flagged</SectionLabel>
      </div>
      {email.whyFlagged.length > 0 ? (
        <ul className="space-y-3">
          {email.whyFlagged.map((reason, i) => (
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
  const isFail = status === 'fail' || status === 'none';
  return (
    <Card className={cn('p-5', isFail && 'border-accent-700/20')}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-bold text-ink-200">{label}</span>
        {isFail ? (
          <XCircle className="w-5 h-5 text-accent-500" />
        ) : (
          <CheckCircle className="w-5 h-5 text-emerald-500" />
        )}
      </div>
      <div className={cn('mono text-2xl font-bold uppercase mb-3', isFail ? 'text-accent-400' : 'text-emerald-400')}>
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

/**
 * Forensics-only single-click preview — matches the doc's required field
 * set: Sender, Reply-To, Return-Path, Subject, Message-ID, Threat Score,
 * SPF/DKIM/DMARC, major header anomalies, attachment count.
 */
function renderForensicsPreview(email: ScannedEmail, onInvestigate: () => void) {
  const replyTo = email.headers?.['Reply-To'];
  const returnPath = email.headers?.['Return-Path'];
  const messageId = email.headers?.['Message-ID'];
  const replyToMismatch = !!replyTo && replyTo !== email.sender;
  const attachmentCount = extractAttachments(email).length;
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
          {email.senderAnomalies.slice(0, 4).map((a, i) => (
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
