
import type {
  AuthenticationAnalysis,
  CategoryResult,
  AIAssessment,
  RiskAssessment,
  RiskLevel,
} from "../schemas/types";

/**
 * Evidence Consistency Engine.
 *
 * Runs AFTER risk fusion (riskEngine.ts) and archetype assessment
 * (archetypeAssessment.ts) — it reads their already-computed outputs
 * and reconciles them into a plain-language verdict, without touching
 * the underlying category scores or fusion math. This is a read-only
 * interpretive layer, matching the same "pure recombination of
 * already-stored data" pattern used by assessArchetype and the
 * recommendations engine — it never re-runs ML/LLM/GeoIP/DNS and is
 * never persisted as a second dataset.
 *
 * WHY THIS EXISTS: risk fusion's coverage-aware weighted average can
 * dilute a strong single-category signal when every other category is
 * clean — e.g. an email with clean SPF/DKIM/DMARC, no domain spoofing,
 * and a legitimate-looking URL, but a 90%-confidence AI read of
 * financial fraud / social engineering in the body text, currently
 * blends down to a low overall score because four clean categories
 * (technical, identity, urlDomain, infrastructure) outvote one
 * alarming one (content, weighted only 20%). This module detects that
 * specific asymmetry and, where warranted, raises the classification
 * — with an evidence-specific explanation, never a silent override.
 */

export type ConsistencyVerdict =
  | "CONSISTENT_CLEAN"
  | "CONSISTENT_MALICIOUS"
  | "TECHNICAL_CLEAN_CONTENT_ALARMING"
  | "TECHNICAL_ALARMING_CONTENT_CLEAN"
  | "INSUFFICIENT_EVIDENCE";

export interface ConsistencyAssessment {
  verdict: ConsistencyVerdict;
  explanation: string;
  classificationOverride: "suspicious" | "malicious" | null;
  /** Moves together with classificationOverride — never set one without
   *  the other. Without this, the UI can show a raised classification
   *  text (e.g. "SUSPICIOUS") next to an unchanged low-band ring color/
   *  label, which reads as a worse contradiction than the original bug
   *  this module fixes. */
  levelOverride: RiskLevel | null;
  contributingCategories: string[];
}

interface AssessConsistencyInput {
  risk: RiskAssessment;
  authentication: AuthenticationAnalysis | null;
  aiAssessment: AIAssessment | null;
  urlDomainCategory: CategoryResult | null;
}

const AI_ALARM_THRESHOLD = 0.7;
const AI_CLEAN_THRESHOLD = 0.2;
// Mirrors riskEngine.ts's own "low" band ceiling (levelFromScore) — a
// urlDomain score at or below this is treated as clean/negligible,
// the same threshold archetypeAssessment.ts already reuses rather
// than inventing a new one.
const URL_DOMAIN_LOW_THRESHOLD = 25;

function isAuthCleanPass(auth: AuthenticationAnalysis | null): boolean {
  if (!auth) return false;
  return auth.spf.result === "pass" && auth.dkim.result === "pass" && auth.dmarc.result === "pass";
}

function isAuthFail(auth: AuthenticationAnalysis | null): boolean {
  if (!auth) return false;
  return auth.spf.result === "fail" || auth.dkim.result === "fail" || auth.dmarc.result === "fail";
}

function aiIsAlarming(ai: AIAssessment): boolean {
  return (
    (ai.financialFraud ?? 0) >= AI_ALARM_THRESHOLD ||
    (ai.socialEngineering ?? 0) >= AI_ALARM_THRESHOLD ||
    (ai.credentialHarvesting ?? 0) >= AI_ALARM_THRESHOLD
  );
}

function aiIsClean(ai: AIAssessment): boolean {
  return (
    (ai.phishingIntent ?? 0) < AI_CLEAN_THRESHOLD &&
    (ai.financialFraud ?? 0) < AI_CLEAN_THRESHOLD &&
    (ai.socialEngineering ?? 0) < AI_CLEAN_THRESHOLD
  );
}

function formatPercent(value: number | null): string {
  return value === null ? "unavailable" : `${Math.round(value * 100)}%`;
}

const RISK_LEVEL_RANK: Record<RiskLevel, number> = { low: 0, moderate: 1, high: 2, critical: 3 };

/**
 * Applies a ConsistencyAssessment's overrides to a risk result's
 * classification/level, with a rank guard so level can only ever be
 * RAISED, never lowered below what fusion already computed.
 *
 * Shared by every call site that needs the "effective" classification/
 * level for an email — currently routes/emails.ts's GET
 * /emails/:emailId and emailStore.ts's toEmailSummary. Extracted here
 * (rather than duplicated in both places) specifically because a
 * duplicated copy of this exact logic is what caused the bug this
 * fixes in the first place: summary.json's cached riskLevel and the
 * live detail route's overridden level drifted out of sync because the
 * override existed in only one of the two places that needed it.
 */
export function applyConsistencyOverride(
  risk: { classification: string | null; level: RiskLevel | null } | null | undefined,
  consistency: ConsistencyAssessment | null
): { classification: string | null; level: RiskLevel | null } {
  const classification = consistency?.classificationOverride ?? risk?.classification ?? null;
  const level =
    consistency?.levelOverride &&
    risk?.level &&
    RISK_LEVEL_RANK[consistency.levelOverride] > RISK_LEVEL_RANK[risk.level]
      ? consistency.levelOverride
      : risk?.level ?? null;
  return { classification, level };
}

/**
 * Evaluated in this order — first match wins, mirroring
 * assessArchetype's own convention of ordered, mutually-exclusive
 * checks rather than a scoring function.
 */
export function assessConsistency(input: AssessConsistencyInput): ConsistencyAssessment {
  const { risk, authentication, aiAssessment, urlDomainCategory } = input;

  const coverage = risk.evidenceCoverage ?? 0;
  const aiAvailable = aiAssessment !== null && aiAssessment.status === "AVAILABLE";

  // 1. INSUFFICIENT_EVIDENCE — too little to reason about at all.
  // Reuses the same "too thin to conclude" shape as archetypeAssessment's
  // own availableCount < 2 check: if less than half the risk categories
  // were available, or the AI layer wasn't available, don't force a verdict.
  if (coverage < 0.4 || !aiAvailable) {
    return {
      verdict: "INSUFFICIENT_EVIDENCE",
      explanation: !aiAvailable
        ? "AI content interpretation was not available for this email, so cross-category consistency cannot be assessed."
        : `Only ${Math.round(coverage * 100)}% of evidence categories were available — insufficient coverage to assess consistency across categories.`,
      classificationOverride: null,
      levelOverride: null,
      contributingCategories: [],
    };
  }

  const authClean = isAuthCleanPass(authentication);
  const authBad = isAuthFail(authentication);
  const urlClean =
    urlDomainCategory?.status === "AVAILABLE" &&
    (urlDomainCategory.score ?? 0) <= URL_DOMAIN_LOW_THRESHOLD;
  const urlBad =
    urlDomainCategory?.status === "AVAILABLE" &&
    (urlDomainCategory.score ?? 0) > URL_DOMAIN_LOW_THRESHOLD;

  const aiAlarming = aiIsAlarming(aiAssessment);
  const aiClean = aiIsClean(aiAssessment);

  // 2. TECHNICAL_CLEAN_CONTENT_ALARMING — the case this module exists for.
  if (authClean && urlClean && aiAlarming) {
    const parts: string[] = [
      `Authentication is clean (SPF/DKIM/DMARC all pass) and URL/domain risk is low`,
      `but AI content analysis indicates a high-confidence social-engineering pattern`,
      `(financial fraud ${formatPercent(aiAssessment!.financialFraud)}, social engineering ${formatPercent(aiAssessment!.socialEngineering)}, credential harvesting ${formatPercent(aiAssessment!.credentialHarvesting)}${aiAssessment!.attackType ? `, attack type: ${aiAssessment!.attackType}` : ""})`,
      `Clean infrastructure does not rule out a purely social-engineering attack using legitimate services.`,
    ];
    return {
      verdict: "TECHNICAL_CLEAN_CONTENT_ALARMING",
      explanation: parts.join(" "),
      classificationOverride: "suspicious",
      // "moderate," not "high"/"critical" — this is an interpretive AI
      // signal on otherwise-clean infrastructure, same reasoning as why
      // classificationOverride stops at "suspicious" rather than
      // "malicious". Raised via the rank-guard in routes/emails.ts, so
      // it only ever lifts the level, never lowers one fusion already
      // computed higher.
      levelOverride: "moderate",
      contributingCategories: ["content"],
    };
  }

  // 3. TECHNICAL_ALARMING_CONTENT_CLEAN — the inverse. Never soften an
  // observed technical failure just because the LLM's interpretive read
  // was benign — observed fact outranks interpretation in this direction.
  if ((authBad || urlBad) && aiClean) {
    const reasons: string[] = [];
    if (authentication?.spf.result === "fail") reasons.push("SPF fail");
    if (authentication?.dkim.result === "fail") reasons.push("DKIM fail");
    if (authentication?.dmarc.result === "fail") reasons.push("DMARC fail");
    if (urlBad) reasons.push(`elevated URL/domain risk score (${urlDomainCategory?.score})`);

    return {
      verdict: "TECHNICAL_ALARMING_CONTENT_CLEAN",
      explanation: `Technical evidence shows a real authentication or domain issue (${reasons.join(", ")}), while AI content analysis read the message body as benign (phishing intent ${formatPercent(aiAssessment!.phishingIntent)}). The technical finding is an observed fact and is not softened by the AI's benign content read.`,
      classificationOverride: null,
      levelOverride: null,
      contributingCategories: ["technical", "identity", "urlDomain"].filter((cat) => {
        if (cat === "technical" || cat === "identity") return authBad;
        if (cat === "urlDomain") return urlBad;
        return false;
      }),
    };
  }

  // 4. CONSISTENT_MALICIOUS — technical/domain evidence and AI both agree
  // something is wrong. No override needed — fusion already reflects it.
  if ((authBad || urlBad) && aiAlarming) {
    return {
      verdict: "CONSISTENT_MALICIOUS",
      explanation: `Technical/domain evidence and AI content analysis independently agree this email is high-risk.`,
      classificationOverride: null,
      levelOverride: null,
      contributingCategories: ["technical", "urlDomain", "content"],
    };
  }

  // 5. CONSISTENT_CLEAN — everything agrees this is low-risk.
  return {
    verdict: "CONSISTENT_CLEAN",
    explanation: `Technical, domain, and AI content evidence all independently indicate low risk.`,
    classificationOverride: null,
    levelOverride: null,
    contributingCategories: [],
  };
}