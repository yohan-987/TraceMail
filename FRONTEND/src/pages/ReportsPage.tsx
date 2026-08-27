import { useState, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import {
  FileText,
  Printer,
  Shield,
  ArrowLeft,
  Radar,
  ShieldQuestion,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import { ProvenanceTag, provenanceMeta, type Provenance } from '@/components/ProvenanceTag';
import { mockEmails, type ScannedEmail } from '@/data/mockData';
import { cn } from '@/lib/utils';

/** Same cosmetic-only placeholder hash used on the Scanner page — not a real
 *  digest, just a deterministic-looking stand-in until a backend supplies one. */
function mockSha256(seed: string): string {
  let h1 = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h1 ^= seed.charCodeAt(i);
    h1 = Math.imul(h1, 0x01000193);
  }
  let out = '';
  let x = h1 >>> 0;
  while (out.length < 64) {
    x = (Math.imul(x, 48271) + 1) >>> 0;
    out += x.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}

function getRecommendedAction(email: ScannedEmail): string | null {
  return email.reportSections.find((s) => s.title === 'RECOMMENDATIONS')?.content ?? null;
}

function getRelatedEmailCount(email: ScannedEmail): number {
  if (!email.caseId) return 0;
  return mockEmails.filter((e) => e.caseId === email.caseId && e.id !== email.id).length;
}

/**
 * Six-value provenance taxonomy used sparingly — one badge per report
 * section, never per field, so it stays "subtle" rather than overwhelming.
 * Defined once in @/components/ProvenanceTag and reused here.
 */

function ReportSection({ num, title, provenance, children }: { num: number; title: string; provenance?: Provenance; children: React.ReactNode }) {
  return (
    <Card className="p-5 break-inside-avoid">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <span className="mono text-[10px] font-bold text-accent-600 w-6">{String(num).padStart(2, '0')}</span>
          <SectionLabel>{title}</SectionLabel>
        </div>
        {provenance && <ProvenanceTag type={provenance} />}
      </div>
      {children}
    </Card>
  );
}

function Field({ label, value, mono }: { label: string; value: string | null; mono?: boolean }) {
  const isUnavailable = value === null || value === '';
  return (
    <div className="panel-2 p-3">
      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">{label}</div>
      {isUnavailable ? (
        <div className="flex items-center gap-1.5 text-[11px] text-ink-600 italic">
          <ShieldQuestion className="w-3 h-3 shrink-0" /> UNAVAILABLE
        </div>
      ) : (
        <div className={cn('text-[12px] text-ink-200 truncate', mono && 'mono')}>{value}</div>
      )}
    </div>
  );
}

export function ReportsPage() {
  // Locally-owned selection — this page's own `reportsSelectedEmailId`.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [reportsSelectedEmailId, setReportsSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const activeEmail = useMemo(() => getEmail(reportsSelectedEmailId), [getEmail, reportsSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
    setReportsSelectedEmailId(email.id);
    setLastViewed(email.id);
  };

  const backToList = () => setReportsSelectedEmailId(null);

  const actions = activeEmail ? (
    <div className="flex items-center gap-2">
      <button
        onClick={backToList}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium text-ink-400 hover:text-ink-200 bg-base-800/60 border border-base-500/30 transition-colors uppercase tracking-wider"
      >
        <ArrowLeft className="w-3 h-3" /> Back to Email List
      </button>
      <button
        onClick={() => window.print()}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors uppercase tracking-wider"
      >
        <Printer className="w-3 h-3" /> Print / Save as PDF
      </button>
    </div>
  ) : undefined;

  return (
    <InvestigationShell
      breadcrumb="Reports"
      title="Forensic Report"
      subtitle={activeEmail ? `${activeEmail.id} · Generated report` : undefined}
      actions={actions}
      hideCaseSelector={!activeEmail}
      selectedEmail={activeEmail}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setReportsSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setReportsSelectedEmailId(null)}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'report' } : undefined}
    >
      {!activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderReportsPreview} enableCaseFilter />
      ) : (
        <FullReport email={activeEmail} />
      )}
    </InvestigationShell>
  );
}

function FullReport({ email }: { email: ScannedEmail }) {
  const isThreat = email.threatScore >= 60;
  const hash = mockSha256(`${email.id}:${email.subject}`);
  const filename = `${email.id}.eml`;
  const relatedCount = getRelatedEmailCount(email);
  const recommendedAction = getRecommendedAction(email);
  const confidence = Math.min(99, Math.round(email.threatScore * 0.9 + 8));
  const urlDomainIocs = email.indicators.filter((i) => i.type === 'URL' || i.type === 'Domain');

  return (
    <div key={email.id} className="space-y-5 animate-fade-in">
      {/* Report header — quick-glance identity + evidence integrity summary */}
      <Card className="p-5">
        <div className="flex items-start justify-between mb-4 flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-accent-700/10 border border-accent-700/25">
              <Shield className="w-5 h-5 text-accent-500" />
            </div>
            <div>
              <div className="text-base font-bold text-ink-50">Forensic Analysis Report</div>
              <div className="text-[11px] text-ink-500 mt-0.5">{email.subject}</div>
            </div>
          </div>
          <div className="flex gap-2">
            <Badge variant={isThreat ? 'critical' : 'neutral'}>{email.riskLevel}</Badge>
            <Badge variant="danger">{email.classification}</Badge>
          </div>
        </div>
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
          <Field label="Email ID" value={email.id} mono />
          <Field label="Case ID" value={email.caseId || null} mono />
          <Field label="Original Filename" value={filename} mono />
          <Field label="SHA-256" value={hash} mono />
          <Field label="Upload Timestamp" value={email.date} mono />
          <Field label="Analysis Timestamp" value={null} mono />
        </div>
      </Card>

      <ReportSection num={1} title="Case Information" provenance="observed">
        <div className="grid grid-cols-4 gap-3">
          <Field label="Case ID" value={email.caseId || null} mono />
          <Field label="Email ID" value={email.id} mono />
          <Field label="Assigned Analyst" value="M. Chen" />
          <Field label="Analysis Status" value="Automated Analysis Complete" />
        </div>
      </ReportSection>

      <ReportSection num={2} title="Evidence Integrity" provenance="observed">
        <div className="grid grid-cols-4 gap-3">
          <Field label="Original Filename" value={filename} mono />
          <Field label="SHA-256 Hash" value={hash} mono />
          <Field label="Upload Timestamp" value={email.date} mono />
          <Field label="Analysis Timestamp" value={null} mono />
        </div>
      </ReportSection>

      <ReportSection num={3} title="Email Metadata" provenance="observed">
        <div className="grid grid-cols-4 gap-3">
          <Field label="Sender" value={email.sender} mono />
          <Field label="Recipient" value={email.recipient} mono />
          <Field label="Subject" value={email.subject} />
          <Field label="Date" value={email.date} mono />
          <Field label="Size" value={email.size} mono />
          <Field label="Message-ID" value={email.headers?.['Message-ID'] || null} mono />
        </div>
      </ReportSection>

      <ReportSection num={4} title="Authentication" provenance="deterministic">
        <div className="grid grid-cols-3 gap-3 mb-4">
          <AuthMini label="SPF" status={email.spf} />
          <AuthMini label="DKIM" status={email.dkim} />
          <AuthMini label="DMARC" status={email.dmarc} />
        </div>
        <p className="text-[12px] text-ink-400 leading-relaxed">{email.authenticationSummary}</p>
      </ReportSection>

      <ReportSection num={5} title="Header Forensics" provenance="observed">
        <div className="max-h-64 overflow-y-auto scrollbar-thin divide-y divide-base-500/10">
          {Object.entries(email.headers).map(([k, v]) => (
            <div key={k} className="flex items-start gap-4 py-2">
              <span className="mono text-[10px] text-ink-500 w-40 shrink-0">{k}</span>
              <span className="mono text-[11px] text-ink-300 break-all">{v}</span>
            </div>
          ))}
        </div>
      </ReportSection>

      <ReportSection num={6} title="Received Relay Chain" provenance="observed">
        {email.receivedChain.length > 0 ? (
          <div className="space-y-2.5">
            {email.receivedChain.map((hop, i) => (
              <div key={i} className="panel-2 p-3 grid grid-cols-4 gap-3 items-center">
                <span className="mono text-[10px] text-accent-500">Hop {hop.hop}</span>
                <span className="mono text-[11px] text-ink-300 truncate">{hop.from}</span>
                <span className="mono text-[11px] text-ink-300 truncate">{hop.by}</span>
                <span className="mono text-[10px] text-ink-500">{hop.timestamp}</span>
                {hop.from.includes('unknown') && <Badge variant="warning" className="col-span-4 w-fit">Inferred: Forged Hop</Badge>}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No received chain data available</div>
        )}
      </ReportSection>

      <ReportSection num={7} title="Threat Assessment" provenance="deterministic">
        <div className="grid grid-cols-4 gap-3 mb-4">
          <Field label="Threat Score" value={String(email.threatScore)} mono />
          <Field label="Risk Level" value={email.riskLevel} />
          <Field label="Classification" value={email.classification} />
          <Field label="Status" value={email.status} />
        </div>
        <p className="text-[12px] text-ink-400 leading-relaxed">{email.threatSummary}</p>
      </ReportSection>

      <ReportSection num={8} title="Indicators" provenance="external">
        <div className="grid grid-cols-5 gap-2 mb-3">
          {(['IP', 'Domain', 'URL', 'Hash', 'Email'] as const).map((type) => (
            <div key={type} className="panel-2 p-2 text-center">
              <div className="text-[14px] font-bold text-ink-200">{email.indicators.filter((i) => i.type === type).length}</div>
              <div className="text-[8px] text-ink-600 uppercase tracking-wider mt-0.5">{type}</div>
            </div>
          ))}
        </div>
        <div className="text-[10px] text-ink-600">{email.indicators.length} total indicators processed — see the Indicators tab for full detail.</div>
      </ReportSection>

      <ReportSection num={9} title="URL / Domain Analysis" provenance="external">
        {urlDomainIocs.length > 0 ? (
          <div className="space-y-1.5">
            {urlDomainIocs.map((ioc) => (
              <div key={ioc.id} className="flex items-center gap-2 text-[11px] panel-2 px-2.5 py-2">
                <span className="mono text-ink-600 w-14 uppercase text-[9px]">{ioc.type}</span>
                <span className="text-ink-300 truncate mono flex-1">{ioc.value}</span>
                <span className={cn('text-[9px] font-semibold uppercase', ioc.reputation === 'malicious' ? 'text-accent-400' : ioc.reputation === 'suspicious' ? 'text-amber-400' : ioc.reputation === 'clean' ? 'text-emerald-400' : 'text-ink-500')}>
                  {ioc.reputation === 'unknown' ? 'Unavailable' : ioc.reputation}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No URL or Domain indicators identified</div>
        )}
      </ReportSection>

      <ReportSection num={10} title="Infrastructure / Geolocation" provenance="external">
        {email.geoData.length > 0 ? (
          <div className="grid grid-cols-3 gap-3">
            {email.geoData.map((geo) => (
              <div key={geo.ip} className="panel-2 p-3">
                <div className="mono text-[11px] text-ink-200 mb-1.5">{geo.ip}</div>
                <div className="text-[10px] text-ink-500">{geo.city}, {geo.country}</div>
                <div className="text-[10px] text-ink-600 mt-1">ISP: {geo.isp} · ASN: {geo.asn}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No infrastructure geolocation data available</div>
        )}
      </ReportSection>

      <ReportSection num={11} title="ML Assessment" provenance="ml">
        <div className="grid grid-cols-3 gap-3">
          <Field label="Model Output Score" value={String(email.threatScore)} mono />
          <Field label="Classification" value={email.classification} />
          <Field label="Risk Level" value={email.riskLevel} />
        </div>
      </ReportSection>

      <ReportSection num={12} title="AI Assessment" provenance="ai">
        <div className="mb-3">
          <Field label="Model Confidence" value={`${confidence}%`} mono />
        </div>
        <p className="text-[12px] text-ink-400 leading-relaxed">{email.threatSummary}</p>
      </ReportSection>

      <ReportSection num={13} title="Related Campaigns / Emails" provenance="inferred">
        <div className="panel-2 p-3 mb-3">
          <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Related Emails In Case</div>
          <div className="text-[12px] text-ink-200">
            {email.caseId ? `${relatedCount} other email${relatedCount === 1 ? '' : 's'} in ${email.caseId}` : 'Not part of a case'}
          </div>
        </div>
        <div className="flex items-center gap-1.5 mb-2">
          <Radar className="w-3 h-3 text-sky-400" />
          <span className="text-[9px] font-semibold uppercase tracking-wider text-ink-500">Likely Related Campaign</span>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <Field label="Campaign ID" value={null} />
          <Field label="Shared Indicators" value={null} />
          <Field label="Shared Infrastructure" value={null} />
          <Field label="Correlation Confidence" value={null} />
        </div>
      </ReportSection>

      <ReportSection num={14} title="Recommended Actions" provenance="ai">
        {recommendedAction ? (
          <p className="text-[12px] text-ink-300 leading-relaxed whitespace-pre-line">{recommendedAction}</p>
        ) : (
          <div className="text-[11px] text-ink-600">No recommended actions available</div>
        )}
      </ReportSection>

      <ReportSection num={15} title="Why Flagged" provenance="deterministic">
        {email.whyFlagged.length > 0 ? (
          <ul className="space-y-2">
            {email.whyFlagged.map((reason, i) => (
              <li key={i} className="flex items-start gap-3 text-[12px] text-ink-300 leading-relaxed">
                <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[11px] text-ink-600">No flags raised for this email</div>
        )}
      </ReportSection>

      <ReportSection num={16} title="Evidence Provenance">
        <p className="text-[11px] text-ink-500 mb-3">Every finding in this report is tagged with how it was produced:</p>
        <div className="grid grid-cols-2 gap-2.5">
          {(Object.keys(provenanceMeta) as Provenance[]).map((key) => (
            <div key={key} className="flex items-center gap-2 panel-2 p-2.5">
              <ProvenanceTag type={key} />
              <span className="text-[10px] text-ink-500">{provenanceMeta[key].description}</span>
            </div>
          ))}
        </div>
      </ReportSection>

      <ReportSection num={17} title="Limitations">
        <ul className="space-y-2.5">
          <li className="flex items-start gap-2.5 text-[12px] text-ink-300 leading-relaxed">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
            <span>Geolocation represents probable network infrastructure and does not establish attacker identity or physical location.</span>
          </li>
          <li className="flex items-start gap-2.5 text-[12px] text-ink-300 leading-relaxed">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
            <span>Threat scores are analytical risk assessments and are not legal conclusions.</span>
          </li>
          <li className="flex items-start gap-2.5 text-[12px] text-ink-500 leading-relaxed">
            <ShieldQuestion className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" />
            <span>This report is generated from mock analysis data in a frontend prototype and has not been reviewed by a human analyst.</span>
          </li>
          <li className="flex items-start gap-2.5 text-[12px] text-ink-500 leading-relaxed">
            <ShieldQuestion className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" />
            <span>Fields marked UNAVAILABLE reflect data the backend has not yet supplied, not a negative finding.</span>
          </li>
        </ul>
      </ReportSection>
    </div>
  );
}

function AuthMini({ label, status }: { label: string; status: string }) {
  const isFail = status === 'fail' || status === 'none';
  return (
    <div className="panel-2 p-3 flex items-center justify-between">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">{label}</span>
      <div className="flex items-center gap-1.5">
        {isFail ? <XCircle className="w-3.5 h-3.5 text-accent-500" /> : <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />}
        <span className={cn('mono text-[11px] font-bold uppercase', isFail ? 'text-accent-400' : 'text-emerald-400')}>{status}</span>
      </div>
    </div>
  );
}

/**
 * Reports-only single-click preview — matches the doc's field list exactly.
 * Evidence ID isn't part of the mock dataset (a backend chain-of-custody
 * concept), so it's shown as UNAVAILABLE rather than invented.
 */
function renderReportsPreview(email: ScannedEmail, onInvestigate: () => void) {
  const isThreat = email.threatScore >= 60;
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Report Preview</SectionLabel>
        <Badge variant={isThreat ? 'danger' : 'neutral'}>{email.classification}</Badge>
      </div>

      <div className="flex items-center gap-2.5 mb-4">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/15 border border-accent-700/30 shrink-0">
          <FileText className="w-4 h-4 text-accent-500" />
        </div>
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">{email.subject}</div>
          <div className="mono text-[10px] text-ink-500 mt-1">{email.sender}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2.5 mb-4">
        <PreviewField label="Email ID" value={email.id} mono />
        <PreviewField label="Case ID" value={email.caseId || 'No Case'} mono />
        <PreviewField label="Evidence ID" value="UNAVAILABLE" />
        <PreviewField label="Threat Score" value={String(email.threatScore)} valueClassName={isThreat ? 'text-accent-400' : 'text-emerald-400'} />
        <PreviewField label="Evidence Count" value={String(email.indicators.length)} />
        <PreviewField label="Report Status" value="Generated" />
      </div>

      {email.whyFlagged.length > 0 && (
        <>
          <SectionLabel className="block mb-2.5">Main Findings</SectionLabel>
          <ul className="space-y-1.5 mb-5">
            {email.whyFlagged.slice(0, 3).map((reason, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] text-ink-400 leading-relaxed">
                <span className="mono text-[9px] text-accent-600 mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <PreviewInvestigateButton label="Open Full Report" onClick={onInvestigate} />
    </div>
  );
}
