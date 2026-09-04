import { useState, useMemo, useEffect } from 'react';
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
  Loader2,
} from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import { ProvenanceTag, provenanceMeta, type Provenance } from '@/components/ProvenanceTag';
import { type ScannedEmail } from '@/types/email';
import { getEmailReport, type ApiForensicReport } from '@/api/api';
import { cn } from '@/lib/utils';

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

  // The real backend report (Batch 6) — fetched fresh whenever the
  // selected email changes. This replaces the old client-side
  // fabrication (mock hash, mock analyst, mock campaign fields) with
  // the actual GET /api/v1/emails/:emailId/report response.
  const [report, setReport] = useState<ApiForensicReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    if (!reportsSelectedEmailId) {
      setReport(null);
      setReportError(null);
      return;
    }
    let cancelled = false;
    setReportLoading(true);
    setReportError(null);
    getEmailReport(reportsSelectedEmailId)
      .then((data) => {
        if (!cancelled) setReport(data);
      })
      .catch((err) => {
        if (!cancelled) setReportError(err instanceof Error ? err.message : 'Failed to load report');
      })
      .finally(() => {
        if (!cancelled) setReportLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reportsSelectedEmailId]);

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
      ) : reportLoading ? (
        <div className="flex items-center justify-center gap-2 py-20 text-ink-500 text-[12px]">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading report…
        </div>
      ) : reportError ? (
        <Card className="p-6 text-center">
          <div className="text-[13px] text-ink-300 mb-1">Failed to load report</div>
          <div className="text-[11px] text-ink-500">{reportError}</div>
        </Card>
      ) : report ? (
        <FullReport report={report} />
      ) : null}
    </InvestigationShell>
  );
}

function FullReport({ report }: { report: ApiForensicReport }) {
  const risk = report.threatAssessment;
  const isThreat = (risk.score ?? 0) >= 60;
  const ml = report.mlAiAssessment.ml;
  const ai = report.mlAiAssessment.ai;
  const campaign = report.relatedCampaign;

  return (
    <div key={report.emailId} className="space-y-5 animate-fade-in">
      {/* Report header — quick-glance identity + evidence integrity summary */}
      <Card className="p-5">
        <div className="flex items-start justify-between mb-4 flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-accent-700/10 border border-accent-700/25">
              <Shield className="w-5 h-5 text-accent-500" />
            </div>
            <div>
              <div className="text-base font-bold text-ink-50">Forensic Analysis Report</div>
              <div className="text-[11px] text-ink-500 mt-0.5">{report.emailMetadata.subject ?? 'UNAVAILABLE'}</div>
            </div>
          </div>
          <div className="flex gap-2">
            <Badge variant={isThreat ? 'critical' : 'neutral'}>{risk.level ?? 'UNKNOWN'}</Badge>
            <Badge variant="danger">{risk.classification ?? 'unclassified'}</Badge>
          </div>
        </div>
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
          <Field label="Email ID" value={report.emailId} mono />
          <Field label="Case ID" value={report.caseInformation.caseId} mono />
          <Field label="Original Filename" value={report.caseInformation.filename} mono />
          <Field label="SHA-256" value={report.evidenceIntegrity.sha256} mono />
          <Field label="Upload Timestamp" value={report.evidenceIntegrity.collectedAt} mono />
          <Field label="Report Generated" value={report.generatedAt} mono />
        </div>
      </Card>

      <ReportSection num={1} title="Case Information" provenance="observed">
        <div className="grid grid-cols-3 gap-3">
          <Field label="Case ID" value={report.caseInformation.caseId} mono />
          <Field label="Email ID" value={report.caseInformation.emailId} mono />
          <Field label="Report Generated" value={report.caseInformation.generatedAt} mono />
        </div>
      </ReportSection>

      <ReportSection num={2} title="Evidence Integrity" provenance="observed">
        <div className="grid grid-cols-4 gap-3">
          <Field label="Original Filename" value={report.caseInformation.filename} mono />
          <Field label="SHA-256 Hash" value={report.evidenceIntegrity.sha256} mono />
          <Field label="Upload Timestamp" value={report.evidenceIntegrity.collectedAt} mono />
          <Field label="File Size" value={`${report.evidenceIntegrity.fileSizeBytes} bytes`} mono />
        </div>
        <p className="text-[11px] text-ink-500 mt-3">{report.evidenceIntegrity.note}</p>
      </ReportSection>

      <ReportSection num={3} title="Email Metadata" provenance="observed">
        {report.emailMetadata.status === 'AVAILABLE' ? (
          <div className="grid grid-cols-4 gap-3">
            <Field label="Sender" value={report.emailMetadata.from[0]?.email ?? null} mono />
            <Field label="Recipient" value={report.emailMetadata.to[0]?.email ?? null} mono />
            <Field label="Subject" value={report.emailMetadata.subject} />
            <Field label="Date" value={report.emailMetadata.date} mono />
            <Field label="Message-ID" value={report.emailMetadata.messageId} mono />
            <Field label="Attachments" value={String(report.emailMetadata.attachmentCount)} mono />
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">Email metadata unavailable</div>
        )}
      </ReportSection>

      <ReportSection num={4} title="Authentication" provenance="deterministic">
        {report.authentication.status === 'AVAILABLE' ? (
          <div className="grid grid-cols-3 gap-3">
            <AuthMini label="SPF" status={report.authentication.spf?.result ?? 'unavailable'} />
            <AuthMini label="DKIM" status={report.authentication.dkim?.result ?? 'unavailable'} />
            <AuthMini label="DMARC" status={report.authentication.dmarc?.result ?? 'unavailable'} />
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">Authentication data unavailable</div>
        )}
      </ReportSection>

      <ReportSection num={5} title="Header Forensics" provenance="observed">
        {report.headerForensics.anomalies.length > 0 ? (
          <div className="space-y-2">
            {report.headerForensics.anomalies.map((a, i) => (
              <div key={i} className="panel-2 p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="mono text-[10px] text-ink-500">{a.type}</span>
                  <Badge variant={a.severity === 'high' ? 'danger' : a.severity === 'medium' ? 'warning' : 'neutral'}>{a.severity}</Badge>
                </div>
                <div className="text-[11px] text-ink-300">{a.message}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No header anomalies detected ({report.headerForensics.status})</div>
        )}
      </ReportSection>

      <ReportSection num={6} title="Received Relay Chain" provenance="observed">
        {report.headerForensics.receivedChain.length > 0 ? (
          <div className="space-y-2.5">
            {report.headerForensics.receivedChain.map((hop) => (
              <div key={hop.hop} className="panel-2 p-3 grid grid-cols-4 gap-3 items-center">
                <span className="mono text-[10px] text-accent-500">Hop {hop.hop}</span>
                <span className="mono text-[11px] text-ink-300 truncate">{hop.fromHostname ?? hop.fromIp ?? 'unknown'}</span>
                <span className="mono text-[11px] text-ink-300 truncate">{hop.byHostname ?? 'unknown'}</span>
                <span className="mono text-[10px] text-ink-500">{hop.timestampIso ?? 'unavailable'}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No received chain data available</div>
        )}
      </ReportSection>

      <ReportSection num={7} title="Threat Assessment" provenance="deterministic">
        {risk.status === 'AVAILABLE' ? (
          <>
            <div className="grid grid-cols-5 gap-3 mb-4">
              <Field label="Overall Risk" value={risk.score !== null ? String(risk.score) : null} mono />
              <Field label="Risk Level" value={risk.level} />
              <Field label="Classification" value={risk.classification} />
              <Field label="Risk Confidence" value={risk.confidence !== null ? `${Math.round(risk.confidence * 100)}%` : null} mono />
              <Field label="Evidence Coverage" value={risk.evidenceCoverage !== null ? `${Math.round(risk.evidenceCoverage * 100)}%` : null} mono />
            </div>
            {risk.categoryScores && (
              <div className="grid grid-cols-5 gap-2">
                {Object.entries(risk.categoryScores).map(([category, result]) => (
                  <div key={category} className="panel-2 p-2.5 text-center">
                    <div className="text-[9px] uppercase tracking-wider text-ink-500 mb-1">{category}</div>
                    <div className="text-[13px] font-bold text-ink-200">{result.score ?? '—'}</div>
                    <div className="text-[8px] text-ink-600 mt-0.5">{result.status}</div>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="text-[11px] text-ink-600">Insufficient evidence to compute a threat score</div>
        )}
      </ReportSection>

      <ReportSection num={8} title="Indicators" provenance="external">
        {report.iocs.status === 'AVAILABLE' ? (
          <div className="grid grid-cols-5 gap-2 mb-3">
            {([
              ['IP', report.iocs.ips.length],
              ['Domain', report.iocs.domains.length],
              ['URL', report.iocs.urls.length],
              ['Hash', report.iocs.hashes.length],
              ['Email', report.iocs.emails.length],
            ] as const).map(([type, count]) => (
              <div key={type} className="panel-2 p-2 text-center">
                <div className="text-[14px] font-bold text-ink-200">{count}</div>
                <div className="text-[8px] text-ink-600 uppercase tracking-wider mt-0.5">{type}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No IOC data available</div>
        )}
      </ReportSection>

      <ReportSection num={9} title="URL / Domain Analysis" provenance="external">
        {report.urlDomainAnalysis.status === 'AVAILABLE' ? (
          <div className="space-y-1.5">
            {report.urlDomainAnalysis.domains.map((d, i) => (
              <div key={`d-${i}`} className="flex items-center gap-2 text-[11px] panel-2 px-2.5 py-2">
                <span className="mono text-ink-600 w-16 uppercase text-[9px]">domain</span>
                <span className="text-ink-300 truncate mono flex-1">{d.domain}</span>
                {d.lookalikeOf && <Badge variant="warning">resembles {d.lookalikeOf}</Badge>}
              </div>
            ))}
            {report.urlDomainAnalysis.urls.map((u, i) => (
              <div key={`u-${i}`} className="flex items-center gap-2 text-[11px] panel-2 px-2.5 py-2">
                <span className="mono text-ink-600 w-16 uppercase text-[9px]">url</span>
                <span className="text-ink-300 truncate mono flex-1">{u.url}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No URL or Domain indicators identified</div>
        )}
      </ReportSection>

      <ReportSection num={10} title="Infrastructure / Geolocation" provenance="external">
        {report.infrastructure ? (
          <div className="grid grid-cols-3 gap-3">
            <div className="panel-2 p-3">
              <div className="mono text-[11px] text-ink-200 mb-1.5">{report.infrastructure.candidateIp ?? 'UNAVAILABLE'}</div>
              <div className="text-[10px] text-ink-500">{report.infrastructure.city ?? '—'}, {report.infrastructure.country ?? '—'}</div>
              <div className="text-[10px] text-ink-600 mt-1">ISP: {report.infrastructure.isp ?? '—'} · ASN: {report.infrastructure.asn ?? '—'}</div>
            </div>
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">No infrastructure geolocation data available</div>
        )}
      </ReportSection>

      <ReportSection num={11} title="ML Assessment" provenance="ml">
        {ml && ml.status === 'AVAILABLE' ? (
          <div className="grid grid-cols-4 gap-3">
            <Field label="Model" value={ml.model} mono />
            <Field label="Model Version" value={ml.modelVersion} mono />
            <Field label="Classification" value={ml.classification} />
            <Field label="Probability" value={ml.probability !== null ? `${Math.round(ml.probability * 100)}%` : null} mono />
          </div>
        ) : (
          <div className="text-[11px] text-ink-600">ML UNAVAILABLE — {ml?.status ?? 'not run'}</div>
        )}
      </ReportSection>

      <ReportSection num={12} title="AI Assessment" provenance="ai">
        {ai && ai.status === 'AVAILABLE' ? (
          <>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <Field label="Attack Type" value={ai.attackType} />
              <Field label="AI Content Score" value={ai.aiContentScore !== null ? `${Math.round(ai.aiContentScore * 100)}%` : null} mono />
              <Field label="Phishing Intent" value={ai.phishingIntent !== null ? `${Math.round(ai.phishingIntent * 100)}%` : null} mono />
            </div>
            <p className="text-[12px] text-ink-400 leading-relaxed">{ai.summary}</p>
          </>
        ) : (
          <div className="text-[11px] text-ink-600">AI UNAVAILABLE — {ai?.status ?? 'no provider configured'}</div>
        )}
      </ReportSection>

      <ReportSection num={13} title="Related Campaigns / Emails" provenance="inferred">
        {campaign.available && campaign.relatedEmailIds.length > 0 ? (
          <>
            <div className="flex items-center gap-1.5 mb-2">
              <Radar className="w-3 h-3 text-sky-400" />
              <span className="text-[9px] font-semibold uppercase tracking-wider text-ink-500">Likely Related Campaign</span>
            </div>
            <div className="grid grid-cols-4 gap-3">
              <Field label="Campaign ID" value={campaign.campaignId} mono />
              <Field label="Related Emails" value={String(campaign.relatedEmailIds.length)} />
              <Field label="Shared Indicators" value={campaign.sharedIndicators.length ? String(campaign.sharedIndicators.length) : null} />
              <Field label="Correlation Confidence" value={`${Math.round(campaign.confidence * 100)}%`} mono />
            </div>
          </>
        ) : (
          <div className="text-[11px] text-ink-600">No related emails or campaign correlation found</div>
        )}
      </ReportSection>

      <ReportSection num={14} title="Recommended Actions" provenance="deterministic">
        {report.recommendedActions.length > 0 ? (
          <ul className="space-y-3">
            {report.recommendedActions.map((rec, i) => (
              <li key={i} className="text-[12px]">
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant={rec.priority === 'critical' || rec.priority === 'high' ? 'danger' : 'neutral'}>{rec.priority}</Badge>
                  <span className="mono text-[11px] text-ink-200 font-semibold">{rec.action}</span>
                </div>
                <p className="text-ink-400">{rec.reason}</p>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[11px] text-ink-600">No recommended actions for this email</div>
        )}
      </ReportSection>

      <ReportSection num={15} title="Why Flagged" provenance="deterministic">
        {report.whyFlagged.length > 0 ? (
          <ul className="space-y-2">
            {report.whyFlagged.map((item, i) => (
              <li key={i} className="flex items-start gap-3 text-[12px] text-ink-300 leading-relaxed">
                <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                <span>{item.message}</span>
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
          {report.limitations.map((limitation, i) => (
            <li key={i} className="flex items-start gap-2.5 text-[12px] text-ink-300 leading-relaxed">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
              <span>{limitation}</span>
            </li>
          ))}
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
