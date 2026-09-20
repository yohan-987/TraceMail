import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Brain,
  Sparkles,
  ListChecks,
  ShieldQuestion,
  FlaskConical,
  ChevronDown,
  ChevronUp,
  Gauge,
  Route,
} from 'lucide-react';
import { ThreatRing } from '@/components/ThreatRing';
import { Card, SectionLabel, Badge } from '@/components/ui/Primitives';
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

// Prompt 9 — AI Investigation UX. Restructures presentation into a
// layered view (executive verdict -> top evidence -> technical vs
// content -> attack story -> confidence -> expandable detailed
// analysis) and groups/dedupes repeated observations before display.
// Deliberately does NOT change any backend scoring or LLM semantics:
// every value below is read from the exact same fields this page
// already read before this pass (plus the new Prompt 6/7 fields —
// aiAssessment.concernLevel/topReasons/benignExplanation/confidence
// and archetype.compromiseTier — which are additive, not replacements
// for anything that existed here already).

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

/** Frontend F4 — SNAKE_CASE archetype value to Title Case for display,
 *  e.g. "ANONYMIZED_INFRASTRUCTURE" -> "Anonymized Infrastructure". */
function archetypeLabel(value: string): string {
  return value
    .toLowerCase()
    .split('_')
    .map((word) => (word ? word.charAt(0).toUpperCase() + word.slice(1) : word))
    .join(' ');
}

/** Frontend F4 — reuses this project's existing Badge variants only
 *  (see statusColor in CasesPage.tsx / badgeStyles in Primitives.tsx for
 *  the same palette) rather than inventing new colors. INCONCLUSIVE is
 *  explicitly 'neutral', not a failure color — it's a legitimate,
 *  honest answer when evidence is thin, and must never read as worse
 *  than the other four archetypes. */
function archetypeVariant(value: string): 'neutral' | 'warning' | 'danger' | 'critical' {
  switch (value) {
    case 'DIRECT_MALICIOUS_INFRASTRUCTURE':
      return 'critical';
    case 'SPOOFED_DOMAIN':
      return 'danger';
    case 'COMPROMISED_ACCOUNT':
    case 'ANONYMIZED_INFRASTRUCTURE':
      return 'warning';
    case 'INCONCLUSIVE':
    default:
      return 'neutral';
  }
}

/** Prompt 7 — compromiseTier is a NARROWER confidence label than the
 *  outer archetype badge, only meaningful when archetype ===
 *  'COMPROMISED_ACCOUNT'. LIKELY reads as 'warning'; POSSIBLE (the
 *  weaker, single-signal case) is deliberately a step down from that,
 *  never the same or a stronger color, so the UI doesn't visually
 *  overstate an uncorroborated single signal. CONFIRMED is included
 *  for completeness even though the backend documents that it is
 *  never actually emitted today. */
function compromiseTierVariant(tier: string): 'neutral' | 'warning' | 'danger' {
  switch (tier) {
    case 'CONFIRMED':
      return 'danger';
    case 'LIKELY':
      return 'warning';
    case 'POSSIBLE':
    default:
      return 'neutral';
  }
}

/** Prompt 10 — "unambiguous model/version display": expands the
 *  backend's internal model slug into the human-readable family name
 *  for display, without inventing or overriding the underlying value.
 *  Falls back to the raw slug for any value this mapping doesn't
 *  recognize (e.g. a future retrained/renamed model), so this never
 *  silently mislabels something it doesn't actually know about. */
function formatModelName(slug: string | null): string {
  if (!slug) return 'UNAVAILABLE';
  const known: Record<string, string> = {
    'tfidf-logistic-v1': 'TF-IDF + Logistic Regression',
  };
  return known[slug] ?? slug;
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

// Prompt 9 — which risk categories are "technical/forensic" (about the
// message's transport and structure) vs "content" (about what it says
// and the AI's read of that) for the Technical vs Content comparison
// panel. Purely a display grouping of the SAME five categories already
// shown elsewhere on this page — no new computation.
const TECHNICAL_CATEGORY_KEYS = ['technical', 'identity', 'urlDomain', 'infrastructure'];
const CONTENT_CATEGORY_KEYS = ['content'];

import { consolidateTopEvidencePoints } from '@/lib/evidenceConsolidation';

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

  // Frontend F4 correction — Backend Batch 4 has landed. The real field
  // is `archetype`, a sibling of `recommendations` on the email detail
  // response (see routes/emails.ts: `{ ...toPublicEmailRecord(record),
  // recommendations, archetype }`) — NOT `archetypeAssessment`, which
  // was this file's original unverified guess. The object itself is
  // { archetype: AttackArchetype, basis: string[], confidence } — note
  // the inner field is also named `archetype`, which is why the local
  // variable below is named `archetypeResult` rather than shadowing it.
  const archetypeResult = emailData.archetype ?? {};
  const archetype: string | null = archetypeResult.archetype ?? null;
  const archetypeBasis: string[] = Array.isArray(archetypeResult.basis)
    ? archetypeResult.basis
    : [];
  const archetypeConfidence: string | null =
    archetypeResult.confidence ?? null;
  // Prompt 7 — only meaningful when archetype === 'COMPROMISED_ACCOUNT';
  // undefined for every other archetype, exactly as the backend documents.
  const compromiseTier: string | null = archetypeResult.compromiseTier ?? null;

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

  // Prompt 6 fields — additive, read defensively (older stored records
  // predate these and simply won't have them).
  const aiConcernLevel: string | null =
    typeof aiAssessment.concernLevel === 'string' ? aiAssessment.concernLevel : null;
  const aiTopReasons: string[] = Array.isArray(aiAssessment.topReasons) ? aiAssessment.topReasons : [];
  const aiBenignExplanation: string | null =
    typeof aiAssessment.benignExplanation === 'string' && aiAssessment.benignExplanation.trim().length > 0
      ? aiAssessment.benignExplanation
      : null;
  const aiConfidence: string | null =
    typeof aiAssessment.confidence === 'string' ? aiAssessment.confidence : null;

  // Prompt 9, requirement: "Repeated identical observations should be
  // grouped" + "Top 3-5 evidence points". Consolidates the deterministic
  // explanation list with the AI's own (already-consolidated, per
  // Prompt 6's prompt instructions) topReasons into ONE deduplicated
  // list, capped at 5. Dedup is exact-string on the trimmed message —
  // this does not re-interpret or re-score anything, it only prevents
  // the same sentence appearing twice when both the deterministic
  // evidence and the AI summary happen to describe the same finding in
  // the same words.
  const topEvidencePoints: string[] = consolidateTopEvidencePoints(whyFlagged, aiTopReasons);

  const [showDetails, setShowDetails] = useState(false);

  return (
    <div
      key={emailData.emailId}
      className="space-y-5 animate-fade-in"
    >
      {/* ==================== 1. EXECUTIVE VERDICT ==================== */}
      <ExecutiveVerdict
        riskStatus={riskStatus}
        threatScore={threatScore}
        riskLevel={riskLevel}
        classification={classification}
        archetype={archetype}
        compromiseTier={compromiseTier}
      />

      <div className="grid grid-cols-12 gap-5">
        <Card className="col-span-4 flex flex-col items-center justify-center py-8 min-h-[300px] relative overflow-hidden">
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
              size={220}
            />
          ) : (
            <UnavailablePanel
              status={riskStatus}
              label="Threat assessment"
            />
          )}
        </Card>

        <div className="col-span-8 space-y-5">
          {/* ==================== 2. TOP EVIDENCE POINTS ==================== */}
          <TopEvidencePoints points={topEvidencePoints} />

          {/* ==================== 3. TECHNICAL vs CONTENT ASSESSMENT ==================== */}
          <TechnicalVsContentAssessment
            categoryScores={categoryScores}
            aiStatus={aiStatus}
            aiConcernLevel={aiConcernLevel}
            aiBenignExplanation={aiBenignExplanation}
          />
        </div>
      </div>

      {/* ==================== 4. ATTACK STORY ==================== */}
      {archetype && (
        <AttackStorySummary
          archetype={archetype}
          archetypeConfidence={archetypeConfidence}
          compromiseTier={compromiseTier}
          basis={archetypeBasis}
          attackType={attackType}
        />
      )}

      {/* ==================== 5. CONFIDENCE ==================== */}
      <ConfidencePanel
        riskConfidence={riskConfidence}
        evidenceCoverage={evidenceCoverage}
        archetypeConfidence={archetypeConfidence}
        aiConfidence={aiConfidence}
      />

      {/* ==================== 6. EXPANDABLE DETAILED ANALYSIS ==================== */}
      <button
        type="button"
        onClick={() => setShowDetails((v) => !v)}
        className="w-full flex items-center justify-center gap-2 py-2.5 text-[12px] font-semibold uppercase tracking-wider text-ink-400 hover:text-ink-200 transition-colors border border-base-500/20 rounded-lg hover:border-base-500/40"
      >
        {showDetails ? (
          <>
            <ChevronUp className="w-3.5 h-3.5" /> Hide Detailed Analysis
          </>
        ) : (
          <>
            <ChevronDown className="w-3.5 h-3.5" /> Show Detailed Analysis
          </>
        )}
      </button>

      {showDetails && (
        <div className="space-y-5 animate-fade-in">
          {/* Technical Evidence */}
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

          {/* Risk Engine Breakdown */}
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

          {/* ML model output */}
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
              <div className="grid grid-cols-5 gap-3">
                <PreviewField
                  label="ML Classification"
                  value={mlAssessment.classification || 'UNAVAILABLE'}
                />

                <PreviewField
                  label="Model"
                  value={formatModelName(mlAssessment.model)}
                />

                <PreviewField
                  label="Version"
                  value={mlAssessment.modelVersion || 'UNAVAILABLE'}
                  mono
                />

                <PreviewField
                  label="Tokenization"
                  value={mlAssessment.tokenizer || 'UNAVAILABLE'}
                  mono
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

          {/* Semantic Content Assessment (Prompt 6 terminology) */}
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Brain className="w-3.5 h-3.5 text-amber-400" />
                <SectionLabel>
                  Semantic Content Assessment
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

            <p className="text-[10px] text-ink-600 mb-3 italic">
              A separate, secondary content signal — not the authoritative
              overall verdict. Score, level, and classification above come
              from the deterministic risk engine only.
            </p>

            {aiStatus === 'Available' ? (
              <>
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
                    label="Concern Level"
                    value={aiConcernLevel ?? 'UNAVAILABLE'}
                  />
                </div>

                <SectionLabel className="block mb-2">
                  AI Summary
                </SectionLabel>

                <p className="text-sm text-ink-300 leading-relaxed mb-4">
                  {aiSummary}
                </p>

                {aiBenignExplanation && (
                  <div className="mb-4 panel-2 p-3">
                    <div className="text-[10px] uppercase tracking-wider text-ink-500 mb-1">
                      Benign Contextual Explanation
                    </div>
                    <p className="text-[12px] text-ink-300 leading-relaxed">{aiBenignExplanation}</p>
                  </div>
                )}

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
      )}

      <p className="text-[10px] text-ink-600 italic text-center pt-1">
        Threat scores are analytical risk assessments and are not legal
        conclusions or definitive attacker attribution.
      </p>
    </div>
  );
}

/** 1. Executive verdict — the single, plain-language statement at the
 *  top of the page. Reads exactly the same score/level/classification/
 *  archetype/compromiseTier values shown elsewhere; does not compute
 *  anything new. */
function ExecutiveVerdict({
  riskStatus,
  threatScore,
  riskLevel,
  classification,
  archetype,
  compromiseTier,
}: {
  riskStatus: AvailabilityStatus;
  threatScore: number | null;
  riskLevel: string;
  classification: string;
  archetype: string | null;
  compromiseTier: string | null;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Gauge className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>Executive Verdict</SectionLabel>
          <ProvenanceTag type="deterministic" />
        </div>
        {archetype && (
          <div className="flex items-center gap-1.5">
            <Badge variant={archetypeVariant(archetype)}>{archetypeLabel(archetype)}</Badge>
            {compromiseTier && (
              <Badge variant={compromiseTierVariant(compromiseTier)}>{compromiseTier}</Badge>
            )}
          </div>
        )}
      </div>

      {riskStatus === 'Available' && threatScore !== null ? (
        <p className="text-[15px] text-ink-100 leading-relaxed">
          This email is classified <span className="font-bold">{String(classification).toUpperCase()}</span> with a{' '}
          <span className="font-bold">{riskLevel}</span> risk level, scoring{' '}
          <span className="mono font-bold">{formatRiskScore(threatScore)}</span>.
        </p>
      ) : (
        <p className="text-[13px] text-ink-500 italic">
          Insufficient evidence to compute a deterministic verdict for this email.
        </p>
      )}
    </Card>
  );
}

/** 2. Top 3-5 evidence points — already deduplicated/consolidated (see
 *  AIInvestigationDetail's topEvidencePoints derivation above). This
 *  component only renders; it performs no grouping of its own. */
function TopEvidencePoints({ points }: { points: string[] }) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Sparkles className="w-3.5 h-3.5 text-accent-500" />
        <SectionLabel>Top Evidence Points</SectionLabel>
      </div>
      {points.length > 0 ? (
        <ul className="space-y-2">
          {points.map((point, index) => (
            <li key={index} className="flex items-start gap-2.5 text-[13px] text-ink-300 leading-relaxed">
              <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">{String(index + 1).padStart(2, '0')}</span>
              <span>{point}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-[12px] text-ink-600 italic">No distinguishing evidence points available.</div>
      )}
    </Card>
  );
}

/** 3. Technical vs content assessment — a side-by-side comparison of
 *  the SAME categoryScores object already shown in the detailed
 *  breakdown below, grouped into "technical/forensic" (technical,
 *  identity, urlDomain, infrastructure) vs "content" (content) columns,
 *  plus the Semantic Content Assessment's concern level alongside it.
 *  No new scoring — purely a regrouped view of existing values. */
function TechnicalVsContentAssessment({
  categoryScores,
  aiStatus,
  aiConcernLevel,
  aiBenignExplanation,
}: {
  categoryScores: Record<string, { score: number | null; status: string }> | null;
  aiStatus: AvailabilityStatus;
  aiConcernLevel: string | null;
  aiBenignExplanation: string | null;
}) {
  return (
    <Card className="p-5">
      <SectionLabel className="block mb-3">Technical vs Content Assessment</SectionLabel>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-500 mb-2">Forensic / Technical Risk</div>
          {categoryScores ? (
            <div className="space-y-1.5">
              {TECHNICAL_CATEGORY_KEYS.map((key) => {
                const result = categoryScores[key];
                return (
                  <div key={key} className="flex items-center justify-between text-[12px]">
                    <span className="text-ink-400">{CATEGORY_LABELS[key] ?? key}</span>
                    <span className="mono text-ink-200 font-semibold">{result?.score ?? '—'}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-[12px] text-ink-600 italic">Unavailable</div>
          )}
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-500 mb-2">Content Risk</div>
          {categoryScores ? (
            <div className="space-y-1.5 mb-2">
              {CONTENT_CATEGORY_KEYS.map((key) => {
                const result = categoryScores[key];
                return (
                  <div key={key} className="flex items-center justify-between text-[12px]">
                    <span className="text-ink-400">{CATEGORY_LABELS[key] ?? key}</span>
                    <span className="mono text-ink-200 font-semibold">{result?.score ?? '—'}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-[12px] text-ink-600 italic mb-2">Unavailable</div>
          )}
          <div className="flex items-center justify-between text-[12px] pt-1.5 border-t border-base-500/15">
            <span className="text-ink-400">Semantic Content Assessment</span>
            <span className="mono text-ink-200 font-semibold">
              {aiStatus === 'Available' && aiConcernLevel ? aiConcernLevel.toUpperCase() : 'UNAVAILABLE'}
            </span>
          </div>
          {aiBenignExplanation && (
            <p className="text-[11px] text-ink-500 italic mt-1.5 leading-relaxed">{aiBenignExplanation}</p>
          )}
        </div>
      </div>
    </Card>
  );
}

/** 4. Attack story / path summary — reuses the archetype's own basis
 *  list (already the specific evidence citations behind the archetype
 *  call) as the narrative, rather than inventing separate prose. */
function AttackStorySummary({
  archetype,
  archetypeConfidence,
  compromiseTier,
  basis,
  attackType,
}: {
  archetype: string;
  archetypeConfidence: string | null;
  compromiseTier: string | null;
  basis: string[];
  attackType: string;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-2">
        <Route className="w-3.5 h-3.5 text-accent-500" />
        <SectionLabel>Attack Story</SectionLabel>
        <ProvenanceTag type="deterministic" />
      </div>

      <div className="flex items-center gap-2 flex-wrap mb-1.5">
        <Badge variant={archetypeVariant(archetype)}>{archetypeLabel(archetype)}</Badge>
        {compromiseTier && <Badge variant={compromiseTierVariant(compromiseTier)}>{compromiseTier}</Badge>}
        {archetypeConfidence && (
          <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">
            Confidence: {archetypeConfidence}
          </span>
        )}
        {attackType !== 'UNAVAILABLE' && (
          <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">
            Semantic attack type: {attackType}
          </span>
        )}
      </div>

      <p className="text-[11px] text-ink-600 italic mb-2">
        Evidence-based assessment, not confirmed attacker identity.
      </p>

      {basis.length > 0 ? (
        <ul className="space-y-1.5">
          {basis.map((item, index) => (
            <li key={index} className="flex items-start gap-2 text-[12px] text-ink-300 leading-relaxed">
              <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">&bull;</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-[12px] text-ink-600 italic">No path summary available.</div>
      )}
    </Card>
  );
}

/** 5. Confidence — pulls together the three separate confidence
 *  signals this page already tracks (deterministic risk confidence,
 *  archetype confidence, AI confidence) into one place rather than
 *  leaving them scattered across three different cards. */
function ConfidencePanel({
  riskConfidence,
  evidenceCoverage,
  archetypeConfidence,
  aiConfidence,
}: {
  riskConfidence: unknown;
  evidenceCoverage: unknown;
  archetypeConfidence: string | null;
  aiConfidence: string | null;
}) {
  return (
    <Card className="p-5">
      <SectionLabel className="block mb-3">Confidence</SectionLabel>
      <div className="grid grid-cols-4 gap-3">
        <PreviewField label="Risk Engine Confidence" value={formatFraction(riskConfidence)} mono />
        <PreviewField label="Evidence Coverage" value={formatFraction(evidenceCoverage)} mono />
        <PreviewField label="Archetype Confidence" value={archetypeConfidence ?? 'UNAVAILABLE'} />
        <PreviewField label="Semantic Assessment Confidence" value={aiConfidence ?? 'UNAVAILABLE'} />
      </div>
    </Card>
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
