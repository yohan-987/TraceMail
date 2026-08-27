import { useState, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { Brain, Sparkles, ListChecks, ShieldAlert, Cpu, ShieldQuestion, FlaskConical } from 'lucide-react';
import { ThreatRing } from '@/components/ThreatRing';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import { ProvenanceTag } from '@/components/ProvenanceTag';
import type { ScannedEmail } from '@/data/mockData';
import { cn } from '@/lib/utils';

type AvailabilityStatus = 'Available' | 'Unavailable' | 'Inconclusive';

/**
 * ML/AI status is derived from the email's own existing status field — an
 * email the deterministic pipeline itself marked "inconclusive" honestly
 * produces an inconclusive ML/AI status too, rather than pretending a clean
 * verdict exists. Every other email has real score/classification data, so
 * it's genuinely Available. Nothing here is a fabricated confidence number.
 */
function mlAiStatus(email: ScannedEmail): AvailabilityStatus {
  if (email.status === 'inconclusive') return 'Inconclusive';
  if (!email.classification) return 'Unavailable';
  return 'Available';
}

function getRecommendedAction(email: ScannedEmail): string | null {
  return email.reportSections.find((s) => s.title === 'RECOMMENDATIONS')?.content ?? null;
}

/**
 * The five discrete attack-technique flags the doc asks for (phishing
 * intent, credential harvesting, impersonation, financial fraud, social
 * engineering) aren't structured fields anywhere in the mock dataset — only
 * free-text classification/summary exist. Keyword-guessing them would mean
 * inventing a judgment call the backend hasn't actually made, which is
 * exactly what "do not create another mock AI dataset" rules out. So every
 * one of these renders as UNAVAILABLE until a real aiAssessment payload
 * supplies them — never guessed at from text.
 */
const TECHNIQUE_FLAGS = [
  'Phishing Intent',
  'Credential Harvesting',
  'Impersonation',
  'Financial Fraud',
  'Social Engineering',
] as const;

function statusColor(status: AvailabilityStatus): string {
  if (status === 'Available') return 'text-emerald-400';
  if (status === 'Inconclusive') return 'text-amber-400';
  return 'text-ink-500';
}

export function AIInvestigationPage() {
  // Locally-owned selection — this page's own `aiSelectedEmailId`.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [aiSelectedEmailId, setAiSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const activeEmail = useMemo(() => getEmail(aiSelectedEmailId), [getEmail, aiSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
    setAiSelectedEmailId(email.id);
    setLastViewed(email.id);
  };

  return (
    <InvestigationShell
      breadcrumb="AI Investigation"
      title="AI Investigation"
      subtitle={activeEmail ? `Model-assisted analysis · ${activeEmail.id}` : undefined}
      actions={activeEmail ? <Badge variant={activeEmail.threatScore >= 60 ? 'danger' : 'neutral'}>{activeEmail.classification}</Badge> : undefined}
      hideCaseSelector={!activeEmail}
      selectedEmail={activeEmail}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setAiSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setAiSelectedEmailId(null)}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'ai' } : undefined}
    >
      {!activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderAIPreview} enableCaseFilter />
      ) : (
        <AIInvestigationDetail email={activeEmail} />
      )}
    </InvestigationShell>
  );
}

function AIInvestigationDetail({ email }: { email: ScannedEmail }) {
  const isThreat = email.threatScore >= 60;
  const mlStatus = mlAiStatus(email);
  const aiStatus = mlAiStatus(email);
  const maliciousIocs = email.indicators.filter((i) => i.reputation === 'malicious').length;
  const recommendedAction = getRecommendedAction(email);

  return (
    <div key={email.id} className="space-y-5 animate-fade-in">
      {/* Technical Evidence comes first and stands entirely on its own — the
          ML/AI sections below interpret this evidence, they are never its
          source. */}
      <Card className="p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <FlaskConical className="w-3.5 h-3.5 text-accent-500" />
            <SectionLabel>Technical Evidence</SectionLabel>
          </div>
          <ProvenanceTag type="observed" />
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <SignalStat label="Malicious IOCs" value={maliciousIocs} danger={maliciousIocs > 0} />
          <SignalStat label="SPF" value={email.spf.toUpperCase()} danger={email.spf !== 'pass'} />
          <SignalStat label="DKIM" value={email.dkim.toUpperCase()} danger={email.dkim !== 'pass'} />
          <SignalStat label="DMARC" value={email.dmarc.toUpperCase()} danger={email.dmarc !== 'pass'} />
        </div>
        <p className="text-[11px] text-ink-500 leading-relaxed">{email.authenticationSummary}</p>
        <p className="text-[10px] text-ink-600 mt-2 italic">
          This evidence was observed directly from the email. The ML and AI sections below interpret it — they are not where it came from.
        </p>
      </Card>

      <div className="grid grid-cols-12 gap-5">
        <Card className="col-span-4 flex flex-col items-center justify-center py-8 min-h-[380px] relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 flex items-center justify-center gap-2 pt-4">
            <SectionLabel>ML Assessment</SectionLabel>
            <ProvenanceTag type="ml" />
          </div>
          {mlStatus === 'Available' ? (
            <ThreatRing mode="result" score={email.threatScore} riskLevel={email.riskLevel} threatType={email.classification} size={260} />
          ) : (
            <UnavailablePanel status={mlStatus} label="ML" />
          )}
        </Card>

        <div className="col-span-8 space-y-5">
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-violet-400" />
                <SectionLabel>ML Assessment</SectionLabel>
                <ProvenanceTag type="ml" />
              </div>
              <span className={cn('text-[10px] font-bold uppercase tracking-wider', statusColor(mlStatus))}>
                Model Status: {mlStatus}
              </span>
            </div>
            {mlStatus === 'Available' ? (
              <div className="grid grid-cols-4 gap-3">
                <PreviewField label="Classification" value={email.classification} />
                <PreviewField label="Model Name / Version" value="UNAVAILABLE" />
                <PreviewField label="ML Probability" value={`${email.threatScore}%`} mono valueClassName={isThreat ? 'text-accent-400' : 'text-emerald-400'} />
                <PreviewField label="Model Status" value={mlStatus} />
              </div>
            ) : (
              <div className="text-[12px] text-ink-500 italic">ML assessment {mlStatus.toLowerCase()} for this email.</div>
            )}
          </Card>

          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Brain className="w-3.5 h-3.5 text-amber-400" />
                <SectionLabel>AI-Assisted Interpretation</SectionLabel>
                <ProvenanceTag type="ai" />
              </div>
              <span className={cn('text-[10px] font-bold uppercase tracking-wider', statusColor(aiStatus))}>
                AI Status: {aiStatus}
              </span>
            </div>

            {aiStatus !== 'Unavailable' ? (
              <>
                <div className="grid grid-cols-5 gap-2 mb-4">
                  {TECHNIQUE_FLAGS.map((flag) => (
                    <div key={flag} className="panel-2 p-2.5 text-center">
                      <div className="flex items-center justify-center gap-1 text-[9px] text-ink-600 italic mb-1">
                        <ShieldQuestion className="w-2.5 h-2.5" />
                      </div>
                      <div className="text-[8px] text-ink-600 uppercase tracking-wider">{flag}</div>
                      <div className="text-[9px] text-ink-600 italic mt-0.5">UNAVAILABLE</div>
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <PreviewField label="Attack Type" value={email.classification} />
                  <PreviewField label="Likely Attack Objective" value="UNAVAILABLE" />
                </div>

                <SectionLabel className="block mb-2">AI Summary</SectionLabel>
                <p className="text-sm text-ink-300 leading-relaxed mb-4">{email.threatSummary}</p>

                {email.whyFlagged.length > 0 && (
                  <>
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className="w-3.5 h-3.5 text-accent-500" />
                      <SectionLabel>Semantic Reasons</SectionLabel>
                    </div>
                    <ul className="space-y-2 mb-4">
                      {email.whyFlagged.map((reason, i) => (
                        <li key={i} className="flex items-start gap-2.5 text-[13px] text-ink-300 leading-relaxed">
                          <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}

                <div className="flex items-center gap-2 mb-2">
                  <ListChecks className="w-3.5 h-3.5 text-accent-500" />
                  <SectionLabel>Recommended Actions</SectionLabel>
                </div>
                {recommendedAction ? (
                  <p className="text-[13px] text-ink-300 leading-relaxed whitespace-pre-line">{recommendedAction}</p>
                ) : (
                  <div className="text-[12px] text-ink-600 italic">No recommended actions available</div>
                )}
              </>
            ) : (
              <div className="text-[12px] text-ink-500 italic">AI interpretation unavailable for this email.</div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

function UnavailablePanel({ status, label }: { status: AvailabilityStatus; label: string }) {
  return (
    <div className="flex flex-col items-center justify-center text-center px-6">
      <ShieldQuestion className="w-8 h-8 text-ink-600 mb-3" />
      <div className={cn('text-sm font-bold uppercase tracking-wider', statusColor(status))}>{label} {status}</div>
      <p className="text-[11px] text-ink-600 mt-1.5 max-w-[200px]">
        The rest of this investigation remains fully usable — see Forensics, Indicators, and Infrastructure.
      </p>
    </div>
  );
}

function SignalStat({ label, value, danger }: { label: string; value: string | number; danger?: boolean }) {
  return (
    <div className="panel-2 p-3.5">
      <div className={cn('text-xl font-bold tabular-nums mono', danger ? 'text-accent-400' : 'text-emerald-400')}>
        {value}
      </div>
      <div className="section-label mt-1">{label}</div>
    </div>
  );
}

/**
 * AI Investigation-only single-click preview — matches the doc's field
 * list. The five technique flags are UNAVAILABLE for the same reason as the
 * full view: they aren't real structured data in the mock dataset.
 */
function renderAIPreview(email: ScannedEmail, onInvestigate: () => void) {
  const isThreat = email.threatScore >= 60;
  const mlStatus = mlAiStatus(email);
  const aiStatus = mlAiStatus(email);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>AI Preview</SectionLabel>
        <Badge variant={isThreat ? 'critical' : 'neutral'}>{isThreat ? 'MALICIOUS' : 'SAFE'}</Badge>
      </div>

      <div className="flex items-center gap-2.5 mb-4">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/15 border border-accent-700/30 shrink-0">
          <Brain className="w-4 h-4 text-accent-500" />
        </div>
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">{email.subject}</div>
          <div className="mono text-[10px] text-ink-500 mt-1">{email.caseId || email.id}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2.5 mb-4">
        <PreviewField label="ML Classification" value={email.classification} />
        <PreviewField label="Threat Type" value={email.riskLevel} />
        <PreviewField label="ML Status" value={mlStatus} valueClassName={statusColor(mlStatus)} />
        <PreviewField label="AI Status" value={aiStatus} valueClassName={statusColor(aiStatus)} />
      </div>

      <SectionLabel className="block mb-2">Technique Flags</SectionLabel>
      <div className="grid grid-cols-3 gap-1.5 mb-5">
        {TECHNIQUE_FLAGS.slice(0, 3).map((flag) => (
          <div key={flag} className="panel-2 p-1.5 text-center">
            <div className="text-[7px] text-ink-600 uppercase tracking-wider truncate">{flag}</div>
            <div className="text-[8px] text-ink-600 italic mt-0.5">N/A</div>
          </div>
        ))}
      </div>

      <PreviewInvestigateButton label="Run Full AI Investigation" onClick={onInvestigate} />
    </div>
  );
}
