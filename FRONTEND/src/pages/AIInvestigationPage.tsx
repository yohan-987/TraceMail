

import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Brain,
  Sparkles,
  ListChecks,
  ShieldQuestion,
  FlaskConical,
} from 'lucide-react';
import { ThreatRing } from '@/components/ThreatRing';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import {
  InvestigationWorkspace,
  PreviewField,
  PreviewInvestigateButton,
} from '@/components/InvestigationWorkspace';
import { ProvenanceTag } from '@/components/ProvenanceTag';
import { cn } from '@/lib/utils';
import { getEmail as fetchEmailDetails } from '@/api/api';

type AvailabilityStatus =
  | 'Available'
  | 'Unavailable'
  | 'Inconclusive';

const TECHNIQUE_FLAGS = [
  'Phishing Intent',
  'Credential Harvesting',
  'Impersonation',
  'Financial Fraud',
  'Social Engineering',
] as const;

function normalizeAvailability(
  value: unknown
): AvailabilityStatus {
  const normalized = String(value ?? '').toLowerCase();

  switch (normalized) {
    case 'available':
    case 'success':
    case 'ok':
      return 'Available';

    case 'inconclusive':
      return 'Inconclusive';

    case 'unavailable':
    case 'error':
    case 'not_applicable':
    case 'not applicable':
    case '':
    default:
      return 'Unavailable';
  }
}

function statusColor(status: AvailabilityStatus): string {
  switch (status) {
    case 'Available':
      return 'text-emerald-400';
    case 'Inconclusive':
      return 'text-amber-400';
    case 'Unavailable':
    default:
      return 'text-ink-500';
  }
}

function formatProbability(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 'UNAVAILABLE';
  }

  // Backend normally uses 0–1 probability.
  // Also tolerate 0–100 values without changing the meaning.
  const percentage = value <= 1 ? value * 100 : value;

  return `${Math.round(
    Math.max(0, Math.min(100, percentage))
  )}%`;
}

function formatRiskScore(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 'UNAVAILABLE';
  }

  return `${Math.round(
    Math.max(0, Math.min(100, value))
  )}/100`;
}

function formatFraction(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 'UNAVAILABLE';
  }

  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

// Backend RiskCategory keys -> display labels, matching the taxonomy
// used on the Reports page / backend riskEngine.ts. Kept local since
// this is the only place on this page that needs the human-readable
// label rather than the raw key.
const CATEGORY_LABELS: Record<string, string> = {
  technical: 'Technical Integrity',
  identity: 'Identity Consistency',
  urlDomain: 'URL / Domain Risk',
  content: 'Content / Social Engineering',
  infrastructure: 'Infrastructure Risk',
};

export function AIInvestigationPage() {
  const location = useLocation();
  const { setLastViewed, availableEmails, getEmail } = useActiveCase();

  const [aiSelectedEmailId, setAiSelectedEmailId] =
    useState<string | null>(
      (location.state as { emailId?: string } | null)?.emailId ?? null
    );

  const [activeEmailData, setActiveEmailData] =
    useState<any | null>(null);

  const [isLoadingDetails, setIsLoadingDetails] =
    useState(false);

  const [detailsError, setDetailsError] =
    useState<string | null>(null);

  useEffect(() => {
    if (!aiSelectedEmailId) {
      setActiveEmailData(null);
      setDetailsError(null);
      return;
    }

    let cancelled = false;

    setIsLoadingDetails(true);
    setDetailsError(null);

    fetchEmailDetails(aiSelectedEmailId)
      .then((data) => {
        if (!cancelled) {
          setActiveEmailData(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setDetailsError(
            err instanceof Error
              ? err.message
              : 'Failed to load AI investigation details'
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoadingDetails(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [aiSelectedEmailId]);

  const handleInvestigate = (emailId: string) => {
    setAiSelectedEmailId(emailId);
    setLastViewed(emailId);
  };

  const handleSelectEmail = (emailId: string) => {
    setAiSelectedEmailId(emailId);
    setLastViewed(emailId);
  };

  // Use the real, already-fetched lightweight record from availableEmails —
  // never a fabricated stub — so InvestigationShell/CaseSelector always
  // receive a complete ScannedEmail (or null, which they render safely).
const headerEmailContext = activeEmailData
    ? getEmail(activeEmailData.emailId)
    : null;

  return (
    <InvestigationShell
      breadcrumb="AI Investigation"
      title="AI Investigation"
      subtitle={
        activeEmailData
          ? `Model-assisted analysis · ${activeEmailData.emailId}`
          : undefined
      }
      actions={
        activeEmailData ? (
          <Badge
            variant={
              typeof activeEmailData.risk?.score === 'number' &&
              activeEmailData.risk.score >= 60
                ? 'danger'
                : 'neutral'
            }
          >
            {activeEmailData.risk?.classification || 'Unknown'}
          </Badge>
        ) : undefined
      }
      hideCaseSelector={!activeEmailData}
      selectedEmail={headerEmailContext}
      availableEmails={availableEmails}
      onSelectEmail={handleSelectEmail}
      onClearEmail={() => setAiSelectedEmailId(null)}
      investigationNav={
        activeEmailData
          ? {
              emailId: activeEmailData.emailId,
              activeSection: 'ai',
            }
          : undefined
      }
    >
      {isLoadingDetails ? (
        <div className="flex items-center justify-center h-[500px] w-full text-ink-400 font-mono text-sm animate-pulse">
          Loading model-assisted analysis...
        </div>
      ) : detailsError ? (
        <div className="flex items-center justify-center h-[500px] w-full text-accent-500 font-mono text-sm">
          Error: {detailsError}
        </div>
      ) : !activeEmailData ? (
        <InvestigationWorkspace
          onInvestigate={(email: any) =>
            handleInvestigate(email.id)
          }
          renderPreview={renderAIPreview}
          enableCaseFilter
        />
      ) : (
        <AIInvestigationDetail emailData={activeEmailData} />
      )}
    </InvestigationShell>
  );
}

function AIInvestigationDetail({
  emailData,
}: {
  emailData: any;
}) {
  // The stored EmailRecord nests the deterministic risk assessment
  // under `risk` (RiskAssessment: score/level/classification/
  // confidence/evidenceCoverage/categoryScores) — it is never a
  // top-level `score`/`level`/`classification` on the record itself.
  // Reading those top-level fields (as this page previously did) is
  // exactly why this page showed UNAVAILABLE while the Reports page
  // (which reads report.threatAssessment, sourced from the same
  // `risk` object) showed real values.
  const risk = emailData.risk ?? {};

  const threatScore =
    typeof risk.score === 'number'
      ? risk.score
      : null;

  const riskLevel = String(
    risk.level ?? 'UNKNOWN'
  ).toUpperCase();

  const classification =
    risk.classification || 'Unknown';

  const riskConfidence = risk.confidence;
  const evidenceCoverage = risk.evidenceCoverage;
  const categoryScores: Record<string, { score: number | null; status: string }> | null =
    risk.categoryScores ?? null;
  const riskStatus = normalizeAvailability(
    threatScore !== null ? 'AVAILABLE' : risk.status ?? 'UNAVAILABLE'
  );

  const mlAssessment =
    emailData.mlAssessment ?? {};

  const aiAssessment =
    emailData.aiAssessment ?? {};

  const mlStatus = normalizeAvailability(
    mlAssessment.status
  );

  const aiStatus = normalizeAvailability(
    aiAssessment.status
  );

  const mlProbabilityLabel = formatProbability(
    mlAssessment.probability
  );

  const ips = Array.isArray(emailData.iocs?.ips)
    ? emailData.iocs.ips
    : [];

  const domains = Array.isArray(
    emailData.iocs?.domains
  )
    ? emailData.iocs.domains
    : [];

  const ipDomainIndicatorCount =
    ips.length + domains.length;

  const spfResult = String(
    emailData.authentication?.spf?.result ?? 'unknown'
  ).toLowerCase();

  const dkimResult = String(
    emailData.authentication?.dkim?.result ?? 'unknown'
  ).toLowerCase();

  const dmarcResult = String(
    emailData.authentication?.dmarc?.result ?? 'unknown'
  ).toLowerCase();

  const explanations = Array.isArray(
    emailData.explanations
  )
    ? emailData.explanations
    : [];

  const whyFlagged = explanations
    .map((item: any) => item?.message)
    .filter(
      (value: unknown): value is string =>
        typeof value === 'string' &&
        value.trim().length > 0
    );

  const aiSummary =
    typeof aiAssessment.summary === 'string' &&
    aiAssessment.summary.trim().length > 0
      ? aiAssessment.summary
      : 'UNAVAILABLE';

  const attackType =
    typeof aiAssessment.attackType === 'string' &&
    aiAssessment.attackType.trim().length > 0
      ? aiAssessment.attackType
      : 'UNAVAILABLE';

  const recommendedActions = Array.isArray(
    aiAssessment.recommendedActions
  )
    ? aiAssessment.recommendedActions
    : [];

  return (
    <div
      key={emailData.emailId}
      className="space-y-5 animate-fade-in"
    >
      {/* ==================== TECHNICAL EVIDENCE ==================== */}
      <Card className="p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <FlaskConical className="w-3.5 h-3.5 text-accent-500" />
            <SectionLabel>
              Technical Evidence
            </SectionLabel>
          </div>

          <ProvenanceTag type="observed" />
        </div>

        <div className="grid grid-cols-4 gap-3 mb-4">
          <SignalStat
            label="IP / Domain Indicators"
            value={ipDomainIndicatorCount}
            danger={ipDomainIndicatorCount > 0}
          />

          <SignalStat
            label="SPF"
            value={spfResult.toUpperCase()}
            danger={
              spfResult === 'fail' ||
              spfResult === 'softfail'
            }
          />

          <SignalStat
            label="DKIM"
            value={dkimResult.toUpperCase()}
            danger={
              dkimResult === 'fail' ||
              dkimResult === 'softfail'
            }
          />

          <SignalStat
            label="DMARC"
            value={dmarcResult.toUpperCase()}
            danger={
              dmarcResult === 'fail' ||
              dmarcResult === 'softfail'
            }
          />
        </div>

        <p className="text-[11px] text-ink-500 leading-relaxed">
          SPF: {spfResult}, DKIM: {dkimResult}, DMARC:{' '}
          {dmarcResult}
        </p>

        <p className="text-[10px] text-ink-600 mt-2 italic">
          Technical evidence is derived from the scanned
          email and deterministic analysis. ML and AI
          sections interpret this evidence; they are not the
          source of the underlying technical facts.
        </p>
      </Card>

      <div className="grid grid-cols-12 gap-5">
        {/* ============ DETERMINISTIC THREAT ASSESSMENT ============ */}
        <Card className="col-span-4 flex flex-col items-center justify-center py-8 min-h-[380px] relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 flex items-center justify-center gap-2 pt-4">
            <SectionLabel>
              Deterministic Threat Assessment
            </SectionLabel>
            <ProvenanceTag type="deterministic" />
          </div>

          {riskStatus === 'Available' &&
          threatScore !== null ? (
            <ThreatRing
              mode="result"
              score={threatScore}
              riskLevel={riskLevel}
              threatType={classification}
              size={260}
            />
          ) : (
            <UnavailablePanel
              status={riskStatus}
              label="Threat assessment"
            />
          )}
        </Card>

        <div className="col-span-8 space-y-5">
          {/* Deterministic risk engine output — score, level,
              classification, confidence, coverage, and the five
              category scores. This is the ONLY source for these
              values; it is never derived from ML probability or the
              AI content score (Part B requirement). */}
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <SectionLabel>
                  Risk Engine Breakdown
                </SectionLabel>
                <ProvenanceTag type="deterministic" />
              </div>

              <span
                className={cn(
                  'text-[10px] font-bold uppercase tracking-wider',
                  statusColor(riskStatus)
                )}
              >
                Status: {riskStatus}
              </span>
            </div>

            {riskStatus === 'Available' ? (
              <>
                <div className="grid grid-cols-4 gap-3 mb-3">
                  <PreviewField
                    label="Overall Risk Score"
                    value={formatRiskScore(threatScore)}
                    mono
                  />
                  <PreviewField
                    label="Risk Level"
                    value={riskLevel}
                  />
                  <PreviewField
                    label="Risk Confidence"
                    value={formatFraction(riskConfidence)}
                    mono
                  />
                  <PreviewField
                    label="Evidence Coverage"
                    value={formatFraction(evidenceCoverage)}
                    mono
                  />
                </div>

                {categoryScores && (
                  <div className="grid grid-cols-5 gap-2">
                    {Object.entries(categoryScores).map(
                      ([category, result]) => (
                        <div
                          key={category}
                          className="panel-2 p-2.5 text-center"
                        >
                          <div className="text-[8px] uppercase tracking-wider text-ink-500 mb-1 leading-tight">
                            {CATEGORY_LABELS[category] ?? category}
                          </div>
                          <div className="text-[13px] font-bold text-ink-200">
                            {result?.score ?? '—'}
                          </div>
                          <div className="text-[8px] text-ink-600 mt-0.5">
                            {result?.status ?? 'UNAVAILABLE'}
                          </div>
                        </div>
                      )
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="text-[12px] text-ink-500 italic">
                Insufficient evidence to compute a deterministic
                threat score for this email.
              </div>
            )}
          </Card>

          {/* ML model output — a distinct, separately-labeled signal.
              Its classification/probability are the model's own and
              are never substituted for the deterministic risk score
              above (Part B requirement). */}
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <SectionLabel>
                  ML Assessment
                </SectionLabel>
                <ProvenanceTag type="ml" />
              </div>

              <span
                className={cn(
                  'text-[10px] font-bold uppercase tracking-wider',
                  statusColor(mlStatus)
                )}
              >
                Model Status: {mlStatus}
              </span>
            </div>

            {mlStatus === 'Available' ? (
              <div className="grid grid-cols-4 gap-3">
                <PreviewField
                  label="ML Classification"
                  value={mlAssessment.classification || 'UNAVAILABLE'}
                />

                <PreviewField
                  label="Model Name / Version"
                  value={
                    mlAssessment.model ||
                    mlAssessment.modelVersion ||
                    'UNAVAILABLE'
                  }
                />

                <PreviewField
                  label="ML Probability (model output)"
                  value={mlProbabilityLabel}
                  mono
                  valueClassName={
                    mlProbabilityLabel !==
                    'UNAVAILABLE'
                      ? 'text-accent-400'
                      : 'text-ink-500'
                  }
                />

                <PreviewField
                  label="Model Status"
                  value={mlStatus}
                />
              </div>
            ) : (
              <div className="text-[12px] text-ink-500 italic">
                ML assessment{' '}
                {mlStatus.toLowerCase()} for this
                email.
              </div>
            )}

            <p className="text-[10px] text-ink-600 mt-3 italic">
              ML probability is a model output, not the final threat
              score. The deterministic risk engine (above) is the
              source of the overall risk score and classification.
            </p>
          </Card>


          {/* ==================== AI INTERPRETATION ==================== */}
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Brain className="w-3.5 h-3.5 text-amber-400" />
                <SectionLabel>
                  AI-Assisted Interpretation
                </SectionLabel>
                <ProvenanceTag type="ai" />
              </div>

              <span
                className={cn(
                  'text-[10px] font-bold uppercase tracking-wider',
                  statusColor(aiStatus)
                )}
              >
                AI Status: {aiStatus}
              </span>
            </div>

            {aiStatus === 'Available' ? (
              <>
                {/* Technique scores only appear if the backend
                    actually provides them. No fake values. */}
                <div className="grid grid-cols-5 gap-2 mb-4">
                  {TECHNIQUE_FLAGS.map((flag) => {
                    const keyMap: Record<
                      (typeof TECHNIQUE_FLAGS)[number],
                      string
                    > = {
                      'Phishing Intent':
                        'phishingIntent',
                      'Credential Harvesting':
                        'credentialHarvesting',
                      Impersonation:
                        'impersonation',
                      'Financial Fraud':
                        'financialFraud',
                      'Social Engineering':
                        'socialEngineering',
                    };

                    const rawValue =
                      aiAssessment[keyMap[flag]];

                    const value =
                      typeof rawValue === 'number'
                        ? formatProbability(rawValue)
                        : 'UNAVAILABLE';

                    return (
                      <div
                        key={flag}
                        className="panel-2 p-2.5 text-center"
                      >
                        <div className="text-[8px] text-ink-600 uppercase tracking-wider">
                          {flag}
                        </div>

                        <div
                          className={cn(
                            'text-sm font-bold mt-1',
                            value === 'UNAVAILABLE'
                              ? 'text-ink-600'
                              : 'text-accent-400'
                          )}
                        >
                          {value}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <PreviewField
                    label="Attack Type"
                    value={attackType}
                  />

                  <PreviewField
                    label="Threat Classification"
                    value={classification}
                  />
                </div>

                <SectionLabel className="block mb-2">
                  AI Summary
                </SectionLabel>

                <p className="text-sm text-ink-300 leading-relaxed mb-4">
                  {aiSummary}
                </p>

                {whyFlagged.length > 0 && (
                  <>
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className="w-3.5 h-3.5 text-accent-500" />
                      <SectionLabel>
                        Supporting / Semantic Reasons
                      </SectionLabel>
                    </div>

                    <ul className="space-y-2 mb-4">
                      {whyFlagged.map(
                        (
                          reason: string,
                          index: number
                        ) => (
                          <li
                            key={index}
                            className="flex items-start gap-2.5 text-[13px] text-ink-300 leading-relaxed"
                          >
                            <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">
                              {String(
                                index + 1
                              ).padStart(2, '0')}
                            </span>

                            <span>{reason}</span>
                          </li>
                        )
                      )}
                    </ul>
                  </>
                )}

                <div className="flex items-center gap-2 mb-2">
                  <ListChecks className="w-3.5 h-3.5 text-accent-500" />
                  <SectionLabel>
                    Recommended Actions
                  </SectionLabel>
                </div>

                {recommendedActions.length > 0 ? (
                  <ul className="space-y-1.5">
                    {recommendedActions.map(
                      (
                        action: any,
                        index: number
                      ) => (
                        <li
                          key={index}
                          className="text-[13px] text-ink-300 flex items-start gap-2"
                        >
                          <span className="text-accent-500">
                            •
                          </span>

                          <span>
                            {typeof action ===
                            'string'
                              ? action
                              : action?.action ||
                                action?.reason ||
                                'UNAVAILABLE'}
                          </span>
                        </li>
                      )
                    )}
                  </ul>
                ) : (
                  <div className="text-[12px] text-ink-600 italic">
                    No recommended actions available
                  </div>
                )}
              </>
            ) : (
              <div className="text-[12px] text-ink-500 italic">
                AI interpretation{' '}
                {aiStatus.toLowerCase()} for this
                email.
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* ==================== OVERALL ASSESSMENT ==================== */}
      <Card className="p-5">
        <div className="flex items-center justify-between mb-3">
          <SectionLabel>
            Overall Threat Assessment
          </SectionLabel>

          <Badge
            variant={
              typeof threatScore === 'number' &&
              threatScore >= 60
                ? 'danger'
                : 'neutral'
            }
          >
            {riskLevel}
          </Badge>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <PreviewField
            label="Threat Score"
            value={formatRiskScore(threatScore)}
          />

          <PreviewField
            label="Classification"
            value={classification}
          />

          <PreviewField
            label="AI Status"
            value={aiStatus}
          />
        </div>

        <Divider className="my-4" />

        <p className="text-[10px] text-ink-600 italic">
          Threat scores are analytical risk assessments
          and are not legal conclusions or definitive
          attacker attribution.
        </p>
      </Card>
    </div>
  );
}

function UnavailablePanel({
  status,
  label,
}: {
  status: AvailabilityStatus;
  label: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center px-6">
      <ShieldQuestion className="w-8 h-8 text-ink-600 mb-3" />

      <div
        className={cn(
          'text-sm font-bold uppercase tracking-wider',
          statusColor(status)
        )}
      >
        {label} {status}
      </div>

      <p className="text-[11px] text-ink-600 mt-1.5 max-w-[200px]">
        The rest of this investigation remains fully usable.
        Review Forensics, Indicators, and Infrastructure for
        supporting evidence.
      </p>
    </div>
  );
}

function SignalStat({
  label,
  value,
  danger,
}: {
  label: string;
  value: string | number;
  danger?: boolean;
}) {
  return (
    <div className="panel-2 p-3.5">
      <div
        className={cn(
          'text-xl font-bold tabular-nums mono',
          danger
            ? 'text-accent-400'
            : 'text-emerald-400'
        )}
      >
        {value}
      </div>

      <div className="section-label mt-1">
        {label}
      </div>
    </div>
  );
}

function renderAIPreview(
  email: any,
  onInvestigate: () => void
) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>AI Preview</SectionLabel>
        <Badge variant="neutral">
          Detailed View
        </Badge>
      </div>

      <div className="flex items-center gap-2.5 mb-4">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/15 border border-accent-700/30 shrink-0">
          <Brain className="w-4 h-4 text-accent-500" />
        </div>

        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">
            {email.subject || 'No Subject'}
          </div>

          <div className="mono text-[10px] text-ink-500 mt-1">
            {email.caseId || email.id}
          </div>
        </div>
      </div>

      <Card className="flex flex-col items-center justify-center py-12 border-dashed border-base-500/30 bg-base-900/30 mb-5">
        <Brain className="w-8 h-8 text-ink-600 mb-3" />

        <div className="text-[12px] font-semibold text-ink-300 mb-1">
          Detailed AI / ML Analysis
        </div>

        <div className="text-[11px] text-ink-500 text-center max-w-[220px] leading-relaxed">
          Open the full investigation to load the
          selected email's stored ML and AI analysis.
        </div>
      </Card>

      <PreviewInvestigateButton
        label="Open AI Investigation"
        onClick={onInvestigate}
      />
    </div>
  );
}