import type {
  EmailRecord,
  Recommendation,
  RecommendationPriority,
  RecommendedActionType,
  RelatedEmailsResponse,
  RiskEvidenceItem,
} from "../schemas/types";

// Batch 5C — advisory, explainable investigator recommendations built
// only from ALREADY-STORED evidence: the deterministic risk assessment
// (categoryScores/explanations), domain analysis, infrastructure
// assessment, and (optionally) Batch 5B correlation results. This module
// never executes anything — no quarantine, block, contact, or firewall
// action is taken here or anywhere downstream of it; every returned
// object is a suggestion for a human investigator to act on.
//
// Deliberately excluded as a trigger input: aiAssessment (the LLM's
// semantic read). The spec requires recommendations not be based
// SOLELY on an LLM statement — the simplest way to guarantee that is to
// never let it originate one; deterministic risk/domain/infra/
// correlation evidence is what triggers every recommendation below.

const LEVEL_TO_PRIORITY: Record<string, RecommendationPriority> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
};

function evidenceRef(item: RiskEvidenceItem): string {
  return `${item.type}: ${item.message}`;
}

function topEvidence(evidence: RiskEvidenceItem[], n: number): string[] {
  return [...evidence]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, n)
    .map(evidenceRef);
}

function pushIfAbsent(list: Recommendation[], rec: Recommendation): void {
  if (!list.some((r) => r.action === rec.action)) list.push(rec);
}

/**
 * Builds the recommended-actions list for one already-scored
 * EmailRecord. `relatedEmails`, when supplied, is a Batch 5B
 * correlation result for the same email — passing it in (rather than
 * this module computing it itself) keeps this a pure function of data
 * the caller already has, and keeps it independently testable without
 * a full stored-email corpus.
 */
export function generateRecommendations(
  record: EmailRecord,
  relatedEmails: RelatedEmailsResponse | null = null
): Recommendation[] {
  const recommendations: Recommendation[] = [];
  const risk = record.risk;
  const explanations = record.explanations ?? [];

  // --- Insufficient evidence takes priority over everything else: a
  // score computed from partial evidence should not also trigger
  // quarantine/warn recommendations that imply full confidence. ---
  if (!risk || risk.score === null || risk.level === null) {
    const unavailable: string[] = [];
    if (risk?.categoryScores) {
      for (const [category, result] of Object.entries(risk.categoryScores)) {
        if (result.status !== "AVAILABLE") unavailable.push(`${category}: ${result.status}`);
      }
    } else {
      unavailable.push("risk assessment: not computed");
    }
    pushIfAbsent(recommendations, {
      action: "COLLECT_ADDITIONAL_EVIDENCE",
      priority: "medium",
      reason:
        "The deterministic risk assessment could not reach a score because too few categories had available evidence. Gather more evidence before relying on an automated verdict.",
      supportingEvidence: unavailable.length > 0 ? unavailable : ["no analysis categories were available"],
    });
    return recommendations;
  }

  const priority = LEVEL_TO_PRIORITY[risk.level] ?? "low";

  // --- QUARANTINE_EMAIL: strong deterministic risk. ---
  if (risk.level === "high" || risk.level === "critical") {
    recommendations.push({
      action: "QUARANTINE_EMAIL",
      priority,
      reason: `Deterministic risk assessment classified this email as ${risk.level} risk (score ${risk.score}/100, classification: ${risk.classification ?? "unclassified"}).`,
      supportingEvidence: topEvidence(explanations, 3),
    });
  }

  // --- WARN_RECIPIENT: moderate-or-above risk with a non-legitimate
  // classification — the recipient should be cautioned even when the
  // email isn't yet strong enough to quarantine outright. ---
  if (
    (risk.level === "moderate" || risk.level === "high" || risk.level === "critical") &&
    risk.classification &&
    risk.classification !== "legitimate"
  ) {
    recommendations.push({
      action: "WARN_RECIPIENT",
      priority,
      reason: `This email was classified as "${risk.classification}" with ${risk.level} risk (score ${risk.score}/100). The recipient should be cautioned before interacting with it.`,
      supportingEvidence: topEvidence(explanations, 3),
    });
  }

  // --- REVIEW_BLOCK_DOMAIN: a domain was flagged as a look-alike of a
  // trusted brand, or a URL used a raw-IP host — both are urlDomain
  // category evidence already computed by Batch 3. ---
  const domainEvidence = explanations.filter(
    (e) => e.type === "possible_lookalike_domain" || e.type === "raw_ip_host"
  );
  const lookalikeDomains = (record.domainAnalysis?.domains ?? []).filter((d) => d.lookalikeOf);
  if (domainEvidence.length > 0 || lookalikeDomains.length > 0) {
    const evidenceRefs =
      domainEvidence.length > 0
        ? topEvidence(domainEvidence, 3)
        : lookalikeDomains
            .slice(0, 3)
            .map((d) => `possible_lookalike_domain: "${d.domain}" resembles trusted domain "${d.lookalikeOf}"`);
    recommendations.push({
      action: "REVIEW_BLOCK_DOMAIN",
      priority: risk.level === "critical" || risk.level === "high" ? "high" : "medium",
      reason:
        "One or more domains or links in this email were flagged as a likely look-alike of a trusted brand or used a raw IP address as a host — review for blocklisting.",
      supportingEvidence: evidenceRefs,
    });
  }

  // --- INVESTIGATE_SOURCE_INFRASTRUCTURE: infrastructure category
  // evidence actually fired (suspicious ASN/IP, cloud/VPS indicator,
  // multiple anomalous source IPs, confirmed external intel), or the
  // infrastructure assessment could only reach an INCONCLUSIVE/ERROR
  // status and warrants a manual look. ---
  const infraEvidence = explanations.filter((e) => e.category === "infrastructure");
  const infra = record.infrastructure;
  if (infraEvidence.length > 0 || infra?.status === "INCONCLUSIVE" || infra?.status === "ERROR") {
    recommendations.push({
      action: "INVESTIGATE_SOURCE_INFRASTRUCTURE",
      priority: infraEvidence.some((e) => e.severity === "high") ? "high" : "medium",
      reason:
        infraEvidence.length > 0
          ? "Infrastructure enrichment flagged anomalies in the email's candidate source IP(s) — review before drawing conclusions about origin."
          : `Infrastructure enrichment reached status ${infra?.status} and could not be fully resolved — manual review of source infrastructure is recommended.`,
      supportingEvidence:
        infraEvidence.length > 0
          ? topEvidence(infraEvidence, 3)
          : [`infrastructure status: ${infra?.status ?? "unknown"}`],
    });
  }

  // --- REVIEW_RELATED_EMAILS: Batch 5B correlation found related
  // emails. Only fires when the caller actually supplied a correlation
  // result — this module never computes it itself. ---
  if (relatedEmails && relatedEmails.relatedEmailIds.length > 0) {
    recommendations.push({
      action: "REVIEW_RELATED_EMAILS",
      priority: relatedEmails.confidence >= 0.5 ? "high" : "medium",
      reason: relatedEmails.campaignId
        ? `This email shares evidence with ${relatedEmails.relatedEmailIds.length} other stored email(s), grouped under Potentially Related Campaign ${relatedEmails.campaignId} (confidence ${relatedEmails.confidence}). This does not confirm a threat-actor identity.`
        : `This email shares evidence with ${relatedEmails.relatedEmailIds.length} other stored email(s) (confidence ${relatedEmails.confidence}).`,
      supportingEvidence: [
        ...relatedEmails.sharedIndicators.slice(0, 3),
        ...relatedEmails.sharedInfrastructure.slice(0, 2),
      ],
    });
  }

  // --- COLLECT_ADDITIONAL_EVIDENCE: even when a score was reached,
  // coverage across the five risk categories may still be partial. ---
  if (risk.evidenceCoverage !== null && risk.evidenceCoverage < 0.8) {
    const unavailable = risk.categoryScores
      ? Object.entries(risk.categoryScores)
          .filter(([, result]) => result.status !== "AVAILABLE")
          .map(([category, result]) => `${category}: ${result.status}`)
      : [];
    pushIfAbsent(recommendations, {
      action: "COLLECT_ADDITIONAL_EVIDENCE",
      priority: "low",
      reason: `Only ${Math.round(risk.evidenceCoverage * 100)}% of risk categories had available evidence when this assessment was computed. Additional evidence would strengthen confidence.`,
      supportingEvidence: unavailable.length > 0 ? unavailable : [`evidence coverage: ${risk.evidenceCoverage}`],
    });
  }

  return recommendations;
}
