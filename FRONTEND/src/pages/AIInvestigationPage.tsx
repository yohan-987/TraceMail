import { useState, useEffect, useId, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Mail,
  ShieldCheck,
  Box,
  Crosshair,
  Brain,
  BrainCircuit,
  Sparkles,
  FileText,
  ListChecks,
  User,
  Link2,
  Server,
  ChevronRight,
} from 'lucide-react';
import { Card, SectionLabel, Badge } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import {
  InvestigationWorkspace,
  PreviewInvestigateButton,
} from '@/components/InvestigationWorkspace';
import { ProvenanceTag } from '@/components/ProvenanceTag';
import {
  SectionPanel,
  ExplainToggle,
  ExplainPanel,
  StatusNotice,
  useExplain,
} from '@/components/investigation/SectionPanel';
import { RiskRadar, DIMENSION_COLORS } from '@/components/investigation/RiskRadar';
import { cn } from '@/lib/utils';
import { getEmail as fetchEmailDetails } from '@/api/api';
import { mapApiEmailToUiEmail } from '@/api/emailMapper';
import {
  CATEGORY_LABELS,
  archetypeLabel,
  asScore,
  authTone,
  explainAi,
  explainArchetype,
  explainMl,
  explainRiskDimensions,
  explainRiskEngine,
  explainTechnicalEvidence,
  formatModelName,
  formatUtcTimestamp,
  fractionToPercent,
  groupRepeated,
  levelTone,
  normalizeAvailability,
  orderedCategoryKeys,
  percentLabel,
  probabilityToPercent,
  resolveRiskDimensions,
  usableCategoryScore,
  type AuthTone,
  type AvailabilityStatus,
  type CategoryScores,
  type LevelTone,
  type ResolvedRiskDimensions,
} from '@/lib/investigationView';

// Prompt 12 — AI Investigation UI/UX redesign.
//
// FRONTEND PRESENTATION ONLY. Every value on this page is read from the
// same GET /api/v1/emails/:emailId response the page already used before
// this pass (risk / archetype / mlAssessment / aiAssessment /
// authentication / iocs / explanations / forwarding / evidence). Nothing
// here computes, re-weights or re-classifies risk: the deterministic risk
// engine remains the sole authority for the overall verdict, the ML model
// and the AI interpretation stay clearly secondary, and the archetype
// stays an evidence-based label rather than an attribution.
//
// Information flow (matches the reference layout):
//   header -> Risk Engine Breakdown -> 3D Risk Analysis -> Attack
//   Archetype + ML Assessment -> AI-Assisted Interpretation ->
//   Technical Evidence (collapsed) -> Detailed Analysis (collapsed)
//
// Pure formatting / dimension-selection / explanation-text logic lives in
// @/lib/investigationView (unit-tested with node --test).

const TECHNIQUE_FLAGS: Array<{ label: string; key: string }> = [
  { label: 'Phishing Intent', key: 'phishingIntent' },
  { label: 'Credential Harvesting', key: 'credentialHarvesting' },
  { label: 'Impersonation', key: 'impersonation' },
  { label: 'Financial Fraud', key: 'financialFraud' },
  { label: 'Social Engineering', key: 'socialEngineering' },
];

const LEVEL_TEXT: Record<LevelTone, string> = {
  low: 'text-emerald-400',
  moderate: 'text-amber-400',
  high: 'text-orange-400',
  critical: 'text-accent-400',
  unknown: 'text-ink-400',
};

const AUTH_TONE_TEXT: Record<AuthTone | 'plain', string> = {
  good: 'text-emerald-400',
  bad: 'text-accent-400',
  neutral: 'text-ink-300',
  plain: 'text-ink-100',
};

/** INCONCLUSIVE is explicitly neutral, never a failure colour: it is an
 *  honest answer when evidence is thin and must not read as worse than
 *  the other archetypes. */
function archetypeVariant(value: string): 'neutral' | 'warning' | 'danger' | 'critical' {
  switch (value) {
    case 'DIRECT_MALICIOUS_INFRASTRUCTURE':
      return 'critical';
    case 'SPOOFED_DOMAIN':
      return 'danger';
    case 'COMPROMISED_ACCOUNT':
    case 'ANONYMIZED_INFRASTRUCTURE':
      return 'warning';
    default:
      return 'neutral';
  }
}

/** compromiseTier is only meaningful for COMPROMISED_ACCOUNT. POSSIBLE
 *  (the weaker single-signal case) is deliberately a step down from
 *  LIKELY so an uncorroborated signal is never visually overstated. */
function compromiseTierVariant(tier: string): 'neutral' | 'warning' | 'danger' {
  switch (tier) {
    case 'CONFIRMED':
      return 'danger';
    case 'LIKELY':
      return 'warning';
    default:
      return 'neutral';
  }
}

const AVAILABILITY_TEXT: Record<AvailabilityStatus, string> = {
  Available: 'text-emerald-400',
  Inconclusive: 'text-amber-400',
  Unavailable: 'text-ink-400',
};

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v.trim() !== '') : [];
}

// ---------------------------------------------------------------------
// Page (data loading unchanged from Prompts 1-11)
// ---------------------------------------------------------------------

export function AIInvestigationPage() {
  const location = useLocation();
  const { setLastViewed, availableEmails, getEmail } = useActiveCase();

  const [aiSelectedEmailId, setAiSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const [activeEmailData, setActiveEmailData] = useState<any | null>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);

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
            err instanceof Error ? err.message : 'Failed to load AI investigation details'
          );
          setActiveEmailData(null);
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
  const headerEmailContext = activeEmailData ? getEmail(activeEmailData.emailId) : null;

  return (
    <InvestigationShell
      breadcrumb="AI Investigation"
      title="AI Investigation"
      // Once an email is open the page renders its own compact header card
      // (subject, sender, score, classification), so the generic page
      // heading and its duplicate classification badge are omitted.
      compactHeading={!!activeEmailData}
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
          onInvestigate={(email: any) => handleInvestigate(email.id)}
          renderPreview={renderAIPreview}
          enableCaseFilter
        />
      ) : (
        <AIInvestigationDetail emailData={activeEmailData} />
      )}
    </InvestigationShell>
  );
}

// ---------------------------------------------------------------------
// Detail view
// ---------------------------------------------------------------------

function AIInvestigationDetail({ emailData }: { emailData: any }) {
  // The stored EmailRecord nests the deterministic risk assessment under
  // `risk` (score/level/classification/confidence/evidenceCoverage/
  // categoryScores) — never as top-level fields on the record itself.
  const risk = emailData.risk ?? {};

  const threatScore = asScore(risk.score);
  const riskLevel = String(risk.level ?? 'UNKNOWN').toUpperCase();
  const classification: string = risk.classification || 'Unknown';
  const riskConfidencePct = fractionToPercent(risk.confidence);
  const coveragePct = fractionToPercent(risk.evidenceCoverage);
  const categoryScores: CategoryScores | null = risk.categoryScores ?? null;
  const riskStatus = normalizeAvailability(
    threatScore !== null ? 'AVAILABLE' : risk.status ?? 'UNAVAILABLE'
  );

  // `archetype` is a sibling of `recommendations` on the email detail
  // response; the object is { archetype, basis, confidence, compromiseTier? }
  // and its inner field is also called `archetype`, hence the local name.
  const archetypeResult = emailData.archetype ?? {};
  const archetype: string | null = nonEmptyString(archetypeResult.archetype);
  const archetypeBasis = stringList(archetypeResult.basis);
  const archetypeConfidence = nonEmptyString(archetypeResult.confidence);
  const compromiseTier = nonEmptyString(archetypeResult.compromiseTier);

  const mlAssessment = emailData.mlAssessment ?? {};
  const aiAssessment = emailData.aiAssessment ?? {};
  const mlStatus = normalizeAvailability(mlAssessment.status);
  const aiStatus = normalizeAvailability(aiAssessment.status);
  const mlProbabilityPct = probabilityToPercent(mlAssessment.probability);
  const mlClassification = nonEmptyString(mlAssessment.classification);

  const iocs = emailData.iocs ?? {};
  const ips = stringList(iocs.ips);
  const domains = stringList(iocs.domains);

  const spfResult = String(emailData.authentication?.spf?.result ?? 'unknown').toLowerCase();
  const dkimResult = String(emailData.authentication?.dkim?.result ?? 'unknown').toLowerCase();
  const dmarcResult = String(emailData.authentication?.dmarc?.result ?? 'unknown').toLowerCase();

  const dims = resolveRiskDimensions({ score: risk.score, categoryScores });

  return (
    <div key={emailData.emailId} className="space-y-3 animate-fade-in">
      <InvestigationHeader
        emailData={emailData}
        threatScore={threatScore}
        riskLevel={riskLevel}
        classification={classification}
      />

      <RiskEngineSection
        riskStatus={riskStatus}
        score={threatScore}
        level={riskLevel}
        confidencePct={riskConfidencePct}
        coveragePct={coveragePct}
        categoryScores={categoryScores}
      />

      <RiskDimensionsSection dims={dims} />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 items-stretch">
        <ArchetypeSection
          archetype={archetype}
          confidence={archetypeConfidence}
          compromiseTier={compromiseTier}
          basis={archetypeBasis}
        />
        <MlSection
          status={mlStatus}
          classification={mlClassification}
          modelName={formatModelName(nonEmptyString(mlAssessment.model))}
          modelVersion={nonEmptyString(mlAssessment.modelVersion)}
          tokenizer={nonEmptyString(mlAssessment.tokenizer)}
          probabilityPct={mlProbabilityPct}
        />
      </div>

      <AiSection
        status={aiStatus}
        aiAssessment={aiAssessment}
        concernLevel={nonEmptyString(aiAssessment.concernLevel)}
        confidence={nonEmptyString(aiAssessment.confidence)}
      />

      <TechnicalEvidenceSection
        spf={spfResult}
        dkim={dkimResult}
        dmarc={dmarcResult}
        ipCount={ips.length}
        domainCount={domains.length}
      />

      <DetailedAnalysisSection
        emailId={emailData.emailId}
        explanations={Array.isArray(emailData.explanations) ? emailData.explanations : []}
        categoryScores={categoryScores}
        aiStatus={aiStatus}
        aiAssessment={aiAssessment}
        iocs={{
          ips,
          domains,
          urls: stringList(iocs.urls),
          emails: stringList(iocs.emails),
          hashes: stringList(iocs.hashes),
        }}
      />

      <p className="text-[10px] text-ink-600 italic text-center pt-1">
        Threat scores are analytical risk assessments and are not legal conclusions or definitive attacker
        attribution.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------
// 1. Header
// ---------------------------------------------------------------------

function InvestigationHeader({
  emailData,
  threatScore,
  riskLevel,
  classification,
}: {
  emailData: any;
  threatScore: number | null;
  riskLevel: string;
  classification: string;
}) {
  // Reuses the app's canonical classification -> status mapping
  // (emailMapper) rather than re-deriving a verdict here.
  const ui = mapApiEmailToUiEmail(emailData);
  const statusVariant = (
    { safe: 'success', suspicious: 'warning', malicious: 'danger', inconclusive: 'neutral' } as const
  )[ui.status];
  const iconTone = {
    safe: 'border-emerald-700/40 bg-emerald-900/15 text-emerald-400',
    suspicious: 'border-amber-700/40 bg-amber-900/15 text-amber-400',
    malicious: 'border-accent-700/40 bg-accent-900/20 text-accent-400',
    inconclusive: 'border-base-400/40 bg-base-600/40 text-ink-400',
  }[ui.status];

  const forwarding = emailData.forwarding;
  const isForwarded = forwarding?.isForwarded === true;
  const originalSender =
    forwarding?.originalSender && typeof forwarding.originalSender === 'object'
      ? nonEmptyString(forwarding.originalSender.email)
      : forwarding?.originalSender === 'UNKNOWN'
        ? 'unknown'
        : null;

  const collected = formatUtcTimestamp(emailData.evidence?.createdAt);
  const dateHeader = formatUtcTimestamp(ui.date);

  const tone = levelTone(riskLevel);

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3">
        <div className="flex items-start gap-3.5 min-w-0 flex-1 basis-[20rem]">
          <div
            className={cn(
              'flex items-center justify-center w-12 h-12 rounded-xl border shrink-0',
              iconTone
            )}
          >
            <Mail aria-hidden="true" className="w-6 h-6" />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              <h2 className="text-lg font-semibold leading-snug text-ink-50 break-words min-w-0">
                {ui.subject || '(No subject)'}
              </h2>
              <Badge variant={statusVariant}>{String(classification).toUpperCase()}</Badge>
              {isForwarded && (
                <Badge variant="neutral" className="cursor-help">
                  <span title="This message was forwarded; the From address is the forwarder.">Forwarded</span>
                </Badge>
              )}
            </div>

            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12px] text-ink-400">
              <span className="min-w-0 break-all">
                From: <span className="text-sky-500">{ui.sender || 'Unknown sender'}</span>
              </span>
              <span aria-hidden="true" className="text-ink-700">|</span>
              <span className="min-w-0 break-all">To: {ui.recipient || 'unknown'}</span>
              {isForwarded && originalSender && (
                <>
                  <span aria-hidden="true" className="text-ink-700">|</span>
                  <span className="min-w-0 break-all">Original sender: {originalSender}</span>
                </>
              )}
            </div>

            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12px] text-ink-400 mono">
              <span className="break-all">Email ID: {emailData.emailId}</span>
              {collected && (
                <>
                  <span aria-hidden="true" className="text-ink-700">|</span>
                  <span>Collected: {collected}</span>
                </>
              )}
              {dateHeader && dateHeader !== collected && (
                <>
                  <span aria-hidden="true" className="text-ink-700">|</span>
                  <span>Date header: {dateHeader}</span>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="panel-2 px-6 py-3 text-center shrink-0 min-w-[9.5rem]">
          {threatScore !== null ? (
            <>
              <div className="tabular-nums leading-none">
                <span className="text-3xl font-bold text-ink-50">{threatScore}</span>
                <span className="text-lg text-ink-400"> / 100</span>
              </div>
              <div className={cn('mt-1.5 text-[15px] font-bold uppercase tracking-wide', LEVEL_TEXT[tone])}>
                {tone === 'unknown' ? 'No risk level' : `${riskLevel} RISK`}
              </div>
            </>
          ) : (
            <>
              <div className="text-3xl font-bold leading-none text-ink-500">—</div>
              <div className="mt-1.5 text-[12px] font-bold uppercase tracking-wide text-ink-400">
                Score unavailable
              </div>
            </>
          )}
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------
// 2. Risk Engine Breakdown
// ---------------------------------------------------------------------

const CATEGORY_ICON: Record<string, { icon: typeof User; color: string }> = {
  technical: { icon: ShieldCheck, color: 'text-teal-400' },
  identity: { icon: User, color: 'text-sky-400' },
  urlDomain: { icon: Link2, color: 'text-indigo-400' },
  content: { icon: FileText, color: 'text-fuchsia-400' },
  infrastructure: { icon: Server, color: 'text-cyan-400' },
};

function MetricCell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="panel-2 px-3.5 py-2.5 min-w-0">
      <div className="text-[12px] text-ink-400 truncate">{label}</div>
      <div className="mt-0.5 text-xl font-bold leading-tight tabular-nums text-ink-50">{children}</div>
    </div>
  );
}

function RiskEngineSection({
  riskStatus,
  score,
  level,
  confidencePct,
  coveragePct,
  categoryScores,
}: {
  riskStatus: AvailabilityStatus;
  score: number | null;
  level: string;
  confidencePct: number | null;
  coveragePct: number | null;
  categoryScores: CategoryScores | null;
}) {
  const tone = levelTone(level);
  const scoreAvailable = riskStatus === 'Available' && score !== null;

  return (
    <SectionPanel
      icon={<ShieldCheck aria-hidden="true" className="w-5 h-5 text-sky-400" />}
      title="Risk Engine Breakdown"
      tag={<ProvenanceTag type="deterministic" />}
      explainSide
      explanation={explainRiskEngine({
        score: scoreAvailable ? score : null,
        level,
        confidencePct,
        coveragePct,
        categoryScores,
      })}
    >
      <div className="space-y-2">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
          <MetricCell label="Overall Risk Score">
            {scoreAvailable ? (
              <>
                <span className={LEVEL_TEXT[tone]}>{score}</span>
                <span className="text-ink-300"> / 100</span>
              </>
            ) : (
              <span className="text-ink-500">N/A</span>
            )}
          </MetricCell>
          <MetricCell label="Risk Level">
            <span className={LEVEL_TEXT[tone]}>{tone === 'unknown' ? 'N/A' : level}</span>
          </MetricCell>
          <MetricCell label="Risk Confidence">
            {confidencePct !== null ? `${confidencePct}%` : <span className="text-ink-500">N/A</span>}
          </MetricCell>
          <MetricCell label="Evidence Coverage">
            {coveragePct !== null ? `${coveragePct}%` : <span className="text-ink-500">N/A</span>}
          </MetricCell>
        </div>

        {categoryScores && (
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-2">
            {orderedCategoryKeys(categoryScores).map((key) => {
              const value = usableCategoryScore(categoryScores[key]);
              const meta = CATEGORY_ICON[key];
              const Icon = meta?.icon ?? FileText;
              return (
                <div key={key} className="panel-2 px-3 py-2.5 min-w-0">
                  <div className="flex items-start gap-2">
                    <Icon aria-hidden="true" className={cn('w-4 h-4 mt-0.5 shrink-0', meta?.color ?? 'text-ink-400')} />
                    <div className="text-[12px] leading-tight text-ink-400">{CATEGORY_LABELS[key] ?? key}</div>
                  </div>
                  <div className="mt-1.5 flex items-end justify-between gap-2">
                    <div
                      className={cn(
                        'text-xl font-bold leading-none tabular-nums',
                        value === null ? 'text-ink-500' : 'text-ink-50'
                      )}
                    >
                      {value === null ? 'N/A' : value}
                    </div>
                    {value === null && (
                      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500">Unavailable</div>
                    )}
                  </div>
                  <div className="mt-2 h-1 rounded-full bg-base-500/40 overflow-hidden" aria-hidden="true">
                    <div className="h-full rounded-full bg-sky-400/70" style={{ width: `${value ?? 0}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {!scoreAvailable && (
          <p className="text-[12px] text-ink-500 italic">
            Insufficient evidence to compute a deterministic threat score for this email.
          </p>
        )}
      </div>
    </SectionPanel>
  );
}

// ---------------------------------------------------------------------
// 3. 3D Risk Analysis
// ---------------------------------------------------------------------

function RiskDimensionsSection({ dims }: { dims: ResolvedRiskDimensions }) {
  const rows = [dims.overall, dims.forensic, dims.content];

  return (
    <SectionPanel
      icon={<Box aria-hidden="true" className="w-5 h-5 text-sky-400" />}
      title="3D Risk Analysis"
      explainSide
      explanation={explainRiskDimensions(dims)}
    >
      <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)] items-center">
        <RiskRadar dims={dims} />

        <ul className="space-y-2 min-w-0" aria-label="Risk dimension values">
          {rows.map((d) => (
            <li key={d.key} className="panel-2 flex items-center gap-3 px-3.5 py-2.5">
              <span
                aria-hidden="true"
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ backgroundColor: DIMENSION_COLORS[d.key] }}
              />
              <div className="min-w-0 flex-1">
                <div className="text-[13px] text-ink-200">{d.label}</div>
                <div className="text-[10px] leading-snug text-ink-500">
                  {d.value === null ? 'No reliable assessment was returned for this dimension.' : d.basis}
                </div>
              </div>
              {d.value === null ? (
                <span className="text-[11px] font-bold uppercase tracking-wider text-ink-400 shrink-0">
                  Unavailable
                </span>
              ) : (
                <span className="text-[15px] font-bold tabular-nums text-ink-50 shrink-0">
                  {d.value} <span className="text-ink-400 font-semibold">/ 100</span>
                </span>
              )}
            </li>
          ))}
        </ul>
      </div>
    </SectionPanel>
  );
}

// ---------------------------------------------------------------------
// 4. Attack Archetype
// ---------------------------------------------------------------------

function ArchetypeSection({
  archetype,
  confidence,
  compromiseTier,
  basis,
}: {
  archetype: string | null;
  confidence: string | null;
  compromiseTier: string | null;
  basis: string[];
}) {
  return (
    <SectionPanel
      icon={<Crosshair aria-hidden="true" className="w-5 h-5 text-accent-400" />}
      title="Attack Archetype"
      tag={<ProvenanceTag type="deterministic" />}
      explanation={explainArchetype({ archetype, confidence, compromiseTier })}
    >
      {archetype ? (
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <Badge variant={archetypeVariant(archetype)} size="lg">
              {archetypeLabel(archetype)}
            </Badge>
            {compromiseTier && (
              <Badge variant={compromiseTierVariant(compromiseTier.toUpperCase())}>{compromiseTier}</Badge>
            )}
            <span className="text-[13px] text-ink-400">
              Confidence: <span className="font-semibold text-ink-200 uppercase">{confidence ?? 'UNAVAILABLE'}</span>
            </span>
          </div>

          <p className="text-[12px] text-ink-500 italic">Evidence-based assessment, not confirmed attacker identity.</p>

          {basis.length > 0 ? (
            <ul className="panel-2 px-3.5 py-2.5 space-y-1.5">
              {basis.map((item, index) => (
                <li key={index} className="flex items-start gap-2 text-[13px] leading-relaxed text-ink-200">
                  <span aria-hidden="true" className="text-ink-500 mt-px">&bull;</span>
                  <span className="min-w-0">{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-ink-500 italic">No supporting evidence was listed for this assessment.</p>
          )}
        </div>
      ) : (
        <StatusNotice
          label="Archetype"
          status="UNAVAILABLE"
          message="No archetype assessment was returned for this email."
        />
      )}
    </SectionPanel>
  );
}

// ---------------------------------------------------------------------
// 5. ML Assessment
// ---------------------------------------------------------------------

function KeyValueRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,11.5rem)_minmax(0,1fr)] gap-x-4 py-1.5 border-b border-base-500/20 last:border-b-0 text-[13px]">
      <dt className="text-ink-400">{label}</dt>
      <dd className="font-medium text-ink-100 min-w-0 break-words">{children}</dd>
    </div>
  );
}

function Missing() {
  return <span className="text-ink-500 font-normal">UNAVAILABLE</span>;
}

function MlSection({
  status,
  classification,
  modelName,
  modelVersion,
  tokenizer,
  probabilityPct,
}: {
  status: AvailabilityStatus;
  classification: string | null;
  modelName: string;
  modelVersion: string | null;
  tokenizer: string | null;
  probabilityPct: number | null;
}) {
  return (
    <SectionPanel
      icon={<BrainCircuit aria-hidden="true" className="w-5 h-5 text-violet-400" />}
      title="ML Assessment"
      tag={<ProvenanceTag type="ml" />}
      explanation={explainMl({ status, classification, probabilityPct })}
    >
      {status === 'Available' ? (
        <>
          <dl>
            <KeyValueRow label="Classification">{classification ?? <Missing />}</KeyValueRow>
            <KeyValueRow label="Model">{modelName === 'UNAVAILABLE' ? <Missing /> : modelName}</KeyValueRow>
            <KeyValueRow label="Version">{modelVersion ? <span className="mono">{modelVersion}</span> : <Missing />}</KeyValueRow>
            <KeyValueRow label="Tokenization">{tokenizer ? <span className="mono">{tokenizer}</span> : <Missing />}</KeyValueRow>
            <KeyValueRow label="ML Probability">
              {probabilityPct !== null ? <span className="mono">{percentLabel(probabilityPct)}</span> : <Missing />}
            </KeyValueRow>
            <KeyValueRow label="Model Status">
              <span className={AVAILABILITY_TEXT[status]}>{status}</span>
            </KeyValueRow>
          </dl>
          <p className="mt-2 text-[11px] text-ink-500 italic">
            Model output only — not the overall risk score or verdict.
          </p>
        </>
      ) : (
        <StatusNotice
          label="Model status"
          status={status.toUpperCase()}
          message={
            status === 'Inconclusive'
              ? 'The ML assessment was inconclusive for this email.'
              : 'No ML assessment was returned for this email.'
          }
        />
      )}
    </SectionPanel>
  );
}

// ---------------------------------------------------------------------
// 6. AI-Assisted Interpretation
// ---------------------------------------------------------------------

function AiSection({
  status,
  aiAssessment,
  concernLevel,
  confidence,
}: {
  status: AvailabilityStatus;
  aiAssessment: any;
  concernLevel: string | null;
  confidence: string | null;
}) {
  const attackType = nonEmptyString(aiAssessment.attackType);
  const summary = nonEmptyString(aiAssessment.summary);

  return (
    <SectionPanel
      icon={<Sparkles aria-hidden="true" className="w-5 h-5 text-amber-400" />}
      title="AI-Assisted Interpretation"
      tag={<ProvenanceTag type="ai" />}
      headerExtra={
        // When unavailable/inconclusive the body's status notice already says so; the pill is only
        // shown for the available state so the status is never repeated.
        status === 'Available' ? (
          <span className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-ink-400">
            AI Status:
            <span className="rounded border border-emerald-700/30 bg-emerald-900/15 px-2 py-0.5 text-[10px] font-bold tracking-wider text-emerald-400">
              AVAILABLE
            </span>
          </span>
        ) : undefined
      }
      explanation={explainAi({ status })}
    >
      {status === 'Available' ? (
        <div className="space-y-2">
          <p className="text-[11px] text-ink-500 italic">
            Secondary interpretation — the deterministic risk engine remains the authoritative verdict.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-2">
            {TECHNIQUE_FLAGS.map(({ label, key }) => {
              const raw = aiAssessment[key];
              const pct = typeof raw === 'number' ? probabilityToPercent(raw) : null;
              return (
                <div key={key} className="panel-2 px-3.5 py-2.5 min-w-0">
                  <div className="text-[12px] text-ink-400 truncate" title={label}>
                    {label}
                  </div>
                  <div
                    className={cn(
                      'mt-0.5 text-xl font-bold leading-tight tabular-nums',
                      pct === null ? 'text-ink-500' : 'text-ink-50'
                    )}
                  >
                    {pct === null ? 'N/A' : `${pct}%`}
                  </div>
                  {/* Magnitude bar only — no severity colouring or thresholds. */}
                  <div className="mt-1.5 h-1 rounded-full bg-base-500/40 overflow-hidden" aria-hidden="true">
                    <div className="h-full rounded-full bg-amber-400/70" style={{ width: `${pct ?? 0}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="grid gap-2 lg:grid-cols-2">
            <div className="panel-2 px-3.5 py-2.5 min-w-0">
              <div className="text-[12px] text-ink-400">Attack Type</div>
              <div className="mt-0.5 text-[13px] font-medium text-ink-100 break-words">
                {attackType ?? <Missing />}
              </div>
            </div>
            <div className="panel-2 px-3.5 py-2.5 min-w-0">
              <div className="text-[12px] text-ink-400">AI Concern Level</div>
              <div className="mt-0.5 text-[13px] font-medium text-ink-100 break-words">
                {concernLevel ? (
                  <>
                    <span className="uppercase">{concernLevel}</span>
                    {confidence && <span className="text-ink-400 font-normal"> ({confidence} confidence)</span>}
                  </>
                ) : (
                  <Missing />
                )}
              </div>
            </div>
          </div>

          <div className="panel-2 px-3.5 py-2.5">
            <div className="text-[12px] text-ink-400">AI Summary</div>
            <p className="mt-0.5 text-[13px] leading-relaxed text-ink-200">{summary ?? <Missing />}</p>
          </div>
        </div>
      ) : (
        <StatusNotice
          label="AI Status"
          status={status.toUpperCase()}
          message={
            status === 'Inconclusive'
              ? 'The semantic assessment was inconclusive for this email. The deterministic analysis remains the authoritative result.'
              : 'No semantic assessment was returned for this email. The deterministic analysis remains the authoritative result.'
          }
        />
      )}
    </SectionPanel>
  );
}

// ---------------------------------------------------------------------
// 7 & 8. Collapsible rows: Technical Evidence / Detailed Analysis
// ---------------------------------------------------------------------

function CollapsibleRow({
  icon,
  title,
  subtitle,
  explanation,
  children,
}: {
  icon: ReactNode;
  title: string;
  subtitle: string;
  explanation: string[];
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();
  const explain = useExplain(false);
  const titleId = useId();

  return (
    <section aria-labelledby={titleId}>
      <Card>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
          <div className="flex items-center gap-3 min-w-0 flex-1 basis-[16rem]">
            {icon}
            <h2 id={titleId} className="text-[15px] font-semibold text-ink-100 shrink-0">
              {title}
            </h2>
            <span className="hidden lg:inline text-[12px] text-ink-500 truncate min-w-0">{subtitle}</span>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            <ExplainToggle open={explain.open} panelId={explain.panelId} onToggle={explain.toggle} />
            <button
              type="button"
              aria-expanded={open}
              aria-controls={bodyId}
              onClick={() => setOpen((v) => !v)}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12px] font-semibold text-ink-200 whitespace-nowrap',
                'hover:text-ink-50 hover:bg-base-600/40 transition-colors',
                'focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60'
              )}
            >
              {open ? 'Hide Details' : 'Show Details'}
              <span className="sr-only"> for {title}</span>
              <ChevronRight
                aria-hidden="true"
                className={cn('w-4 h-4 transition-transform duration-150', open && 'rotate-90')}
              />
            </button>
          </div>
        </div>

        <ExplainPanel
          open={explain.open}
          panelId={explain.panelId}
          paragraphs={explanation}
          className="mx-4 mb-3"
        />

        <div id={bodyId} hidden={!open} className="px-4 pb-4 pt-3 border-t border-base-500/20">
          {open && children}
        </div>
      </Card>
    </section>
  );
}

function SignalStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone: AuthTone | 'plain';
}) {
  return (
    <div className="panel-2 px-3.5 py-2.5 min-w-0">
      <div className="text-[12px] text-ink-400">{label}</div>
      <div className={cn('mt-0.5 text-xl font-bold leading-tight tabular-nums mono break-words', AUTH_TONE_TEXT[tone])}>
        {value}
      </div>
    </div>
  );
}

function TechnicalEvidenceSection({
  spf,
  dkim,
  dmarc,
  ipCount,
  domainCount,
}: {
  spf: string;
  dkim: string;
  dmarc: string;
  ipCount: number;
  domainCount: number;
}) {
  return (
    <CollapsibleRow
      icon={<FileText aria-hidden="true" className="w-5 h-5 text-sky-400 shrink-0" />}
      title="Technical Evidence"
      subtitle="SPF, DKIM, DMARC, IPs, domains and other technical details"
      explanation={explainTechnicalEvidence({ spf, dkim, dmarc, ipCount, domainCount })}
    >
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
        {/* An indicator COUNT is neutral: many domains or IPs is not itself a risk signal. */}
        <SignalStat label="IP / Domain Indicators" value={ipCount + domainCount} tone="plain" />
        <SignalStat label="SPF" value={spf.toUpperCase()} tone={authTone(spf)} />
        <SignalStat label="DKIM" value={dkim.toUpperCase()} tone={authTone(dkim)} />
        <SignalStat label="DMARC" value={dmarc.toUpperCase()} tone={authTone(dmarc)} />
      </div>
      <p className="mt-2 text-[11px] text-ink-500 italic leading-relaxed">
        Technical evidence is derived from the scanned email and deterministic analysis. ML and AI sections
        interpret this evidence; they are not the source of the underlying technical facts.
      </p>
    </CollapsibleRow>
  );
}

function ChipList({ label, items, max = 24 }: { label: string; items: string[]; max?: number }) {
  if (items.length === 0) return null;
  const shown = items.slice(0, max);
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-500 mb-1.5">
        {label} <span className="text-ink-600">({items.length})</span>
      </div>
      <ul className="flex flex-wrap gap-1.5">
        {shown.map((item, i) => (
          <li key={`${item}-${i}`} className="mono text-[11px] text-ink-300 panel-2 px-2 py-1 break-all max-w-full">
            {item}
          </li>
        ))}
        {items.length > max && (
          <li className="text-[11px] text-ink-500 px-1 py-1">+{items.length - max} more</li>
        )}
      </ul>
    </div>
  );
}

function GroupedList({ messages, max = 8 }: { messages: unknown[]; max?: number }) {
  const grouped = groupRepeated(messages);
  if (grouped.length === 0) return null;
  const render = (g: { message: string; count: number }, i: number) => (
    <li key={i} className="flex items-start gap-2 text-[12px] leading-relaxed text-ink-300">
      <span aria-hidden="true" className="text-ink-500 mt-px">&bull;</span>
      <span className="min-w-0">
        {g.message}
        {g.count > 1 && <span className="ml-1.5 mono text-[10px] text-ink-500">×{g.count}</span>}
      </span>
    </li>
  );
  const head = grouped.slice(0, max);
  const rest = grouped.slice(max);
  return (
    <>
      <ul className="space-y-1">{head.map(render)}</ul>
      {rest.length > 0 && (
        <details className="mt-1">
          <summary className="cursor-pointer text-[11px] text-ink-400 hover:text-ink-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60 rounded">
            Show {rest.length} more
          </summary>
          <ul className="space-y-1 mt-1">{rest.map((g, i) => render(g, i + max))}</ul>
        </details>
      )}
    </>
  );
}

function DetailBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <SectionLabel className="block mb-2">{title}</SectionLabel>
      {children}
    </div>
  );
}

function DetailedAnalysisSection({
  emailId,
  explanations,
  categoryScores,
  aiStatus,
  aiAssessment,
  iocs,
}: {
  emailId: string;
  explanations: any[];
  categoryScores: CategoryScores | null;
  aiStatus: AvailabilityStatus;
  aiAssessment: any;
  iocs: { ips: string[]; domains: string[]; urls: string[]; emails: string[]; hashes: string[] };
}) {
  const whyFlagged = explanations.map((item) => item?.message);

  const categoriesWithEvidence = categoryScores
    ? orderedCategoryKeys(categoryScores)
        .map((key) => ({
          key,
          score: usableCategoryScore(categoryScores[key]),
          messages: (categoryScores[key]?.evidence ?? []).map((e) => e?.message),
        }))
        .filter((c) => groupRepeated(c.messages).length > 0)
    : [];

  const aiAvailable = aiStatus === 'Available';
  const aiReasons = aiAvailable ? stringList(aiAssessment.topReasons) : [];
  const aiBenign = aiAvailable ? nonEmptyString(aiAssessment.benignExplanation) : null;
  const aiActions: string[] = aiAvailable
    ? (Array.isArray(aiAssessment.recommendedActions) ? aiAssessment.recommendedActions : [])
        .map((a: any) => (typeof a === 'string' ? a : a?.action || a?.reason || ''))
        .filter((s: unknown): s is string => typeof s === 'string' && s.trim() !== '')
    : [];

  const hasWhy = groupRepeated(whyFlagged).length > 0;
  const hasIocs =
    iocs.ips.length + iocs.domains.length + iocs.urls.length + iocs.emails.length + iocs.hashes.length > 0;

  return (
    <CollapsibleRow
      icon={<ListChecks aria-hidden="true" className="w-5 h-5 text-sky-400 shrink-0" />}
      title="Detailed Analysis"
      subtitle="View full evidence, extracted IOCs, headers, body analysis and more"
      explanation={[
        'This area collects the lower-level material behind the summary above: the individual findings the deterministic engine recorded, the AI\u2019s own notes, and the indicators extracted from the message.',
        'Nothing here changes the scores. Repeated identical findings are grouped and shown once with a count.',
      ]}
    >
      <div className="space-y-5">
        <DetailBlock title="Evidence Recorded by the Risk Engine">
          {hasWhy ? (
            <GroupedList messages={whyFlagged} />
          ) : (
            <p className="text-[12px] text-ink-500 italic">No distinguishing evidence points were recorded.</p>
          )}
        </DetailBlock>

        {categoriesWithEvidence.length > 0 && (
          <DetailBlock title="Evidence by Category">
            <div className="grid gap-3 lg:grid-cols-2">
              {categoriesWithEvidence.map((c) => (
                <div key={c.key} className="panel-2 px-3.5 py-2.5 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-[12px] font-medium text-ink-200">{CATEGORY_LABELS[c.key] ?? c.key}</span>
                    <span className="mono text-[12px] text-ink-300">{c.score === null ? 'N/A' : c.score}</span>
                  </div>
                  <GroupedList messages={c.messages} max={5} />
                </div>
              ))}
            </div>
          </DetailBlock>
        )}

        {aiAvailable && (aiReasons.length > 0 || aiBenign || aiActions.length > 0) && (
          <DetailBlock title="AI Notes (secondary interpretation)">
            <div className="space-y-3">
              {aiReasons.length > 0 && <GroupedList messages={aiReasons} />}
              {aiBenign && (
                <div className="panel-2 px-3.5 py-2.5">
                  <div className="text-[11px] text-ink-500 mb-1">Benign contextual explanation</div>
                  <p className="text-[12px] leading-relaxed text-ink-300">{aiBenign}</p>
                </div>
              )}
              {aiActions.length > 0 && (
                <div>
                  <div className="text-[11px] text-ink-500 mb-1">Recommended actions</div>
                  <GroupedList messages={aiActions} />
                </div>
              )}
            </div>
          </DetailBlock>
        )}

        <DetailBlock title="Extracted Indicators (IOCs)">
          {hasIocs ? (
            <div className="space-y-3">
              <ChipList label="IP addresses" items={iocs.ips} />
              <ChipList label="Domains" items={iocs.domains} />
              <ChipList label="URLs" items={iocs.urls} />
              <ChipList label="Email addresses" items={iocs.emails} />
              <ChipList label="Hashes" items={iocs.hashes} />
            </div>
          ) : (
            <p className="text-[12px] text-ink-500 italic">No indicators were extracted from this message.</p>
          )}
        </DetailBlock>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-ink-400">
          <span>Full headers, received chain and body analysis:</span>
          <Link to="/forensics" state={{ emailId }} className="text-sky-500 hover:underline">
            Forensics
          </Link>
          <Link to="/indicators" state={{ emailId }} className="text-sky-500 hover:underline">
            Indicators
          </Link>
          <Link to="/infrastructure" state={{ emailId }} className="text-sky-500 hover:underline">
            Infrastructure
          </Link>
        </div>
      </div>
    </CollapsibleRow>
  );
}

// ---------------------------------------------------------------------
// Email picker preview (unchanged)
// ---------------------------------------------------------------------

function renderAIPreview(email: any, onInvestigate: () => void) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>AI Preview</SectionLabel>
        <Badge variant="neutral">Detailed View</Badge>
      </div>

      <div className="flex items-center gap-2.5 mb-4">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-700/15 border border-accent-700/30 shrink-0">
          <Brain className="w-4 h-4 text-accent-500" />
        </div>

        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">
            {email.subject || 'No Subject'}
          </div>

          <div className="mono text-[10px] text-ink-500 mt-1">{email.caseId || email.id}</div>
        </div>
      </div>

      <Card className="flex flex-col items-center justify-center py-12 border-dashed border-base-500/30 bg-base-900/30 mb-5">
        <Brain className="w-8 h-8 text-ink-600 mb-3" />

        <div className="text-[12px] font-semibold text-ink-300 mb-1">Detailed AI / ML Analysis</div>

        <div className="text-[11px] text-ink-500 text-center max-w-[220px] leading-relaxed">
          Open the full investigation to load the selected email's stored ML and AI analysis.
        </div>
      </Card>

      <PreviewInvestigateButton label="Open AI Investigation" onClick={onInvestigate} />
    </div>
  );
}
