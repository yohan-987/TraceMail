import type {
  RiskEvidenceItem,
  RiskAssessment,
  RiskCategory,
  RiskLevel,
  CategoryResult,
  EvidenceAvailability,
} from "../schemas/types";

/**
 * WHY NOT A FLAT WEIGHTED SUM
 * ---------------------------
 * The spec's example weights (SPF fail=25, DKIM fail=25, DMARC fail=30,
 * ...) read like they're meant to be added together and capped at 100.
 * That's exactly what produces double-counting: SPF, DKIM, and DMARC
 * are NOT independent signals — DMARC alignment failure is very often
 * *caused by* the same underlying SPF/DKIM misalignment, so naively
 * summing all three overstates the evidence for what is largely one
 * underlying fact ("this message doesn't authenticate cleanly").
 *
 * Instead, each category's evidence weights are combined with a
 * "noisy-OR" — treat each weight/100 as an independent probability that
 * a given piece of evidence alone would justify concern, then combine:
 *
 *   combined = 1 - Π(1 - weight_i / 100)
 *
 * This is still monotonic (more/stronger evidence never lowers the
 * score) and still bounded at 100, but two correlated 25-weight signals
 * combine to ~44, not 50 — and three correlated ~25-30 signals combine
 * to ~61, not 80. The marginal contribution of each additional signal
 * shrinks as more evidence accumulates, which is the correct shape for
 * evidence that overlaps rather than being additive proof.
 *
 * UNCHANGED from Batch 3 — Batch 3.5 only changes how category results
 * are wrapped (status/coverage) and how the final score normalizes
 * across them, not this combination itself.
 */
function combineEvidence(weights: number[]): number {
  if (weights.length === 0) return 0;
  const product = weights.reduce((acc, w) => acc * (1 - Math.min(Math.max(w, 0), 100) / 100), 1);
  return Math.round(100 * (1 - product));
}

function levelFromScore(score: number): RiskLevel {
  if (score < 25) return "low";
  if (score < 50) return "moderate";
  if (score < 75) return "high";
  return "critical";
}

/**
 * UNCHANGED from Batch 3 — reads the flat evidence list directly (never
 * touched category-result wrapping), so it needed no modification for
 * Batch 3.5. Genuinely no evidence at all is the only case classified
 * as legitimate outright; specific evidence types are checked before
 * falling back to the score band, so an isolated strong signal isn't
 * silently discarded just because its blended contribution alone
 * doesn't clear the low-band threshold.
 */
function classify(evidence: RiskEvidenceItem[], level: RiskLevel): string {
  if (evidence.length === 0) return "legitimate";

  const types = new Set(evidence.map((e) => e.type));
  const has = (t: string) => types.has(t);

  if (has("display_name_brand_impersonation") || has("display_name_authority_impersonation")) {
    return "impersonation";
  }
  if (has("possible_lookalike_domain") || has("raw_ip_host")) {
    return "phishing";
  }
  if (has("financial_request_language") && (has("urgency_language") || has("reply_to_mismatch"))) {
    return "financial_fraud";
  }
  if (has("spf_fail") || has("dkim_fail") || has("dmarc_fail")) {
    return "suspicious_authentication";
  }
  return level === "low" ? "legitimate" : "suspicious";
}

/**
 * Wraps a category's evidence + noisy-OR score with an explicit
 * availability status. When status isn't AVAILABLE, score is null —
 * never 0 — because 0 means "evaluated and found clean," which is a
 * different claim from "couldn't be evaluated at all."
 */
function computeCategoryResult(
  evidence: RiskEvidenceItem[],
  category: RiskCategory,
  status: EvidenceAvailability
): CategoryResult {
  const categoryEvidence = evidence.filter((e) => e.category === category);

  if (status !== "AVAILABLE") {
    return { score: null, status, evidence: categoryEvidence };
  }

  const weights = categoryEvidence.map((e) => e.weight);
  return { score: combineEvidence(weights), status: "AVAILABLE", evidence: categoryEvidence };
}

const CATEGORY_WEIGHTS: Record<RiskCategory, number> = {
  technical: 0.25,
  identity: 0.2,
  urlDomain: 0.2,
  content: 0.2,
  infrastructure: 0.15,
};

type CategoryScoresMap = RiskAssessment["categoryScores"] extends infer T | null ? NonNullable<T> : never;

/**
 * Combines category scores into the final risk score, but ONLY across
 * categories that are actually AVAILABLE. An UNAVAILABLE or
 * NOT_APPLICABLE category is excluded from the weighted average
 * entirely — never substituted with 0 — and its fixed weight (e.g.
 * infrastructure's 15%) is redistributed proportionally among whatever
 * categories DID produce evidence. This is what stops "we haven't
 * built GeoIP yet" from silently dragging every score down, while
 * still never inventing evidence that doesn't exist.
 *
 * evidenceCoverage reports what fraction of the five categories were
 * available, so the score is never presented as if it had full
 * coverage when it didn't.
 */
function combineFinalScore(categoryScores: CategoryScoresMap): {
  score: number | null;
  level: RiskLevel | null;
  evidenceCoverage: number;
} {
  const allCategories = Object.keys(categoryScores) as RiskCategory[];
  const available = allCategories.filter(
    (c) => categoryScores[c].status === "AVAILABLE" && categoryScores[c].score !== null
  );
  const evidenceCoverage = Math.round((available.length / allCategories.length) * 100) / 100;

  if (available.length === 0) {
    // No category could be evaluated at all — an essentially-never-hit
    // edge case (would require zero headers AND zero content), but the
    // correct answer is "unknown," never "0 = safe."
    return { score: null, level: null, evidenceCoverage };
  }

  const totalWeight = available.reduce((sum, c) => sum + CATEGORY_WEIGHTS[c], 0);
  const weightedSum = available.reduce(
    (sum, c) => sum + CATEGORY_WEIGHTS[c] * (categoryScores[c].score ?? 0),
    0
  );
  const score = Math.round(weightedSum / totalWeight);
  const level = levelFromScore(score);

  return { score, level, evidenceCoverage };
}

/**
 * Confidence reflects how many INDEPENDENT AVAILABLE categories
 * corroborate the assessment, not a calibrated probability — the
 * prototype risk bands aren't calibrated probabilities, and neither is
 * this. One category alone (e.g. only content language) is weaker
 * corroboration than three categories agreeing.
 */
function estimateConfidence(categoryScores: CategoryScoresMap): number {
  const scoredCategories = (["technical", "identity", "urlDomain", "content"] as const).filter(
    (cat) => categoryScores[cat].status === "AVAILABLE" && (categoryScores[cat].score ?? 0) > 0
  ).length;
  const confidence = 0.4 + 0.15 * scoredCategories;
  return Math.round(Math.min(confidence, 0.95) * 100) / 100;
}

/**
 * Context the caller (the scan route) supplies because availability
 * can't be inferred from the evidence list alone — an empty evidence
 * array for a category could mean "checked, found nothing" (AVAILABLE,
 * score 0) or "nothing to check" (NOT_APPLICABLE/UNAVAILABLE), and only
 * the caller knows which.
 */
export interface RiskComputationContext {
  /** false only when the email had no parseable headers at all (Batch 1's UNAVAILABLE case). */
  headerDataAvailable: boolean;
  /** false when there were zero URLs AND zero domains extracted — nothing to analyze. */
  urlDomainApplicable: boolean;
  /** false when infrastructure enrichment did not run or produced no usable status. */
  infrastructureAvailable: boolean;
  /**
   * Optional Batch 4 override. When set, this is the infrastructure
   * category status (AVAILABLE / NOT_APPLICABLE / UNAVAILABLE / ERROR /
   * INCONCLUSIVE). The boolean above remains for Batch 3.5 tests.
   */
  infrastructureStatus?: EvidenceAvailability;
}

/**
 * Combines every RiskEvidenceItem (from header forensics, IOC/URL/domain
 * analysis, and content heuristics) into the five category results and
 * a final risk score — normalized across only the categories that were
 * actually available (see combineFinalScore), so missing evidence is
 * never interpreted as evidence of safety.
 */
export function computeRisk(
  emailId: string,
  evidence: RiskEvidenceItem[],
  context: RiskComputationContext
): RiskAssessment {
  const categoryScores: CategoryScoresMap = {
    technical: computeCategoryResult(
      evidence,
      "technical",
      context.headerDataAvailable ? "AVAILABLE" : "UNAVAILABLE"
    ),
    identity: computeCategoryResult(
      evidence,
      "identity",
      context.headerDataAvailable ? "AVAILABLE" : "UNAVAILABLE"
    ),
    urlDomain: computeCategoryResult(
      evidence,
      "urlDomain",
      context.urlDomainApplicable ? "AVAILABLE" : "NOT_APPLICABLE"
    ),
    // Content heuristics always run — even an empty body is a valid
    // (if empty) analysis, not an inapplicable one.
    content: computeCategoryResult(evidence, "content", "AVAILABLE"),
    infrastructure: computeCategoryResult(
      evidence,
      "infrastructure",
      context.infrastructureStatus ??
        (context.infrastructureAvailable ? "AVAILABLE" : "UNAVAILABLE")
    ),
  };

  const { score, level, evidenceCoverage } = combineFinalScore(categoryScores);

  if (score === null) {
    return {
      emailId,
      categoryScores,
      score: null,
      level: null,
      classification: "insufficient_evidence",
      confidence: 0,
      evidenceCoverage,
    };
  }

  const classification = classify(evidence, level as RiskLevel);
  const confidence = estimateConfidence(categoryScores);

  return {
    emailId,
    categoryScores,
    score,
    level,
    classification,
    confidence,
    evidenceCoverage,
  };
}
