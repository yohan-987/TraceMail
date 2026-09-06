import type {
  AuthenticationAnalysis,
  CategoryResult,
  EarliestOriginResult,
} from "../schemas/types";

/**
 * Batch 4 — Attack Archetype Assessment.
 *
 * Recombines evidence ALREADY produced by header forensics (Batch 2/3),
 * URL/domain analysis (Batch 3), content heuristics (Batch 3), and
 * infrastructure intelligence (Batch 4's infrastructure.ts) into an
 * evidence-backed guess at which of five archetypes an email fits.
 * Introduces no new data source — every check below reads evidence
 * types that already exist elsewhere in the codebase.
 *
 * IMPORTANT — grounded against the REAL infrastructureEvidence() output
 * (analyzers/infrastructure.ts), not an idealized spec:
 *   - "known_suspicious_infrastructure" / "suspicious_asn" only fire
 *     when KNOWN_SUSPICIOUS_IPS / SUSPICIOUS_ASNS (config/
 *     infrastructureSignals.ts) actually contain entries — both are
 *     EMPTY by default ("we never invent intel matches"). Until those
 *     lists are populated with real values, DIRECT_MALICIOUS_
 *     INFRASTRUCTURE below will not fire in a demo, by design — this
 *     is a content/config gap, not a bug in this module.
 *   - There is no separate TOR/VPN evidence type in this codebase —
 *     only "cloud_vps_indicator" (hosting/VPS marker matching via
 *     CLOUD_VPS_MARKERS). ANONYMIZED_INFRASTRUCTURE below checks for
 *     that, not a nonexistent "tor_or_vpn" type.
 */

export type AttackArchetype =
  | "SPOOFED_DOMAIN"
  | "COMPROMISED_ACCOUNT"
  | "ANONYMIZED_INFRASTRUCTURE"
  | "DIRECT_MALICIOUS_INFRASTRUCTURE"
  | "INCONCLUSIVE";

export interface ArchetypeAssessment {
  archetype: AttackArchetype;
  /** Short, specific evidence citations — never a generic placeholder. */
  basis: string[];
  confidence: "low" | "medium" | "high";
}

interface AssessArchetypeInput {
  authentication: AuthenticationAnalysis | null;
  /** risk.categoryScores.urlDomain */
  urlDomainCategory: CategoryResult | null;
  /** risk.categoryScores.content */
  contentCategory: CategoryResult | null;
  /** risk.categoryScores.infrastructure — infra evidence lives HERE, not
   *  on InfrastructureAssessment itself. */
  infrastructureCategory: CategoryResult | null;
  /** headerAnalysis.earliestOrigin */
  earliestOrigin: EarliestOriginResult | null;
}

const CONTENT_MODERATE_THRESHOLD = 25; // mirrors riskEngine.ts's "low" band ceiling — see levelFromScore

function hasType(category: CategoryResult | null, ...types: string[]): boolean {
  if (!category || category.status !== "AVAILABLE") return false;
  const set = new Set(category.evidence.map((e) => e.type));
  return types.some((t) => set.has(t));
}

function isAuthFail(auth: AuthenticationAnalysis | null): boolean {
  if (!auth) return false;
  return auth.spf.result === "fail" || auth.dkim.result === "fail" || auth.dmarc.result === "fail";
}

function isAuthCleanPass(auth: AuthenticationAnalysis | null): boolean {
  if (!auth) return false;
  return auth.spf.result === "pass" && auth.dkim.result === "pass" && auth.dmarc.result === "pass";
}

/**
 * Evaluated in this exact order — first match wins. Ordering matters:
 * DIRECT_MALICIOUS_INFRASTRUCTURE and ANONYMIZED_INFRASTRUCTURE are
 * checked before SPOOFED_DOMAIN/COMPROMISED_ACCOUNT because a known-bad
 * or anonymized origin is a stronger, more specific claim than a bare
 * authentication/content pattern, and should not be shadowed by it.
 */
export function assessArchetype(input: AssessArchetypeInput): ArchetypeAssessment {
  const { authentication, urlDomainCategory, contentCategory, infrastructureCategory, earliestOrigin } = input;

  const infraAvailable = infrastructureCategory?.status === "AVAILABLE";
  const authAvailable = authentication !== null;
  const urlAvailable = urlDomainCategory?.status === "AVAILABLE";
  const contentAvailable = contentCategory?.status === "AVAILABLE";

  const knownSuspicious = hasType(infrastructureCategory, "known_suspicious_infrastructure", "suspicious_asn");
  const cloudVpsMarker = hasType(infrastructureCategory, "cloud_vps_indicator");
  const lookalikeOrRawIp = hasType(urlDomainCategory, "possible_lookalike_domain", "raw_ip_host");
  const authFail = isAuthFail(authentication);
  const authCleanPass = isAuthCleanPass(authentication);

  // 1. DIRECT_MALICIOUS_INFRASTRUCTURE
  if (infraAvailable && knownSuspicious && authAvailable && authFail) {
    const basis: string[] = ["Candidate origin matched a configured suspicious-IP/ASN list"];
    if (authentication?.spf.result === "fail") basis.push("SPF fail");
    if (authentication?.dkim.result === "fail") basis.push("DKIM fail");
    if (authentication?.dmarc.result === "fail") basis.push("DMARC fail");
    return {
      archetype: "DIRECT_MALICIOUS_INFRASTRUCTURE",
      basis,
      confidence: "high",
    };
  }

  // 2. ANONYMIZED_INFRASTRUCTURE
  if (infraAvailable && cloudVpsMarker) {
    const basis = ["Candidate origin resolves to a cloud/VPS hosting provider (probable infrastructure, not identity)"];
    if (earliestOrigin?.earliestReliableOrigin) {
      basis.push(`Earliest reliable origin: ${earliestOrigin.earliestReliableOrigin}`);
    }
    return {
      archetype: "ANONYMIZED_INFRASTRUCTURE",
      basis,
      confidence: infraAvailable && authAvailable ? "medium" : "low",
    };
  }

  // 3. SPOOFED_DOMAIN
  if (authAvailable && authFail && urlAvailable && lookalikeOrRawIp) {
    const basis: string[] = [];
    if (authentication?.spf.result === "fail") basis.push("SPF fail");
    if (authentication?.dkim.result === "fail") basis.push("DKIM fail");
    if (authentication?.dmarc.result === "fail") basis.push("DMARC fail");
    const lookalikeEvidence = urlDomainCategory?.evidence.find(
      (e) => e.type === "possible_lookalike_domain" || e.type === "raw_ip_host"
    );
    basis.push(lookalikeEvidence ? lookalikeEvidence.message : "Look-alike or raw-IP URL detected");
    return {
      archetype: "SPOOFED_DOMAIN",
      basis,
      confidence: "high",
    };
  }

  // 4. COMPROMISED_ACCOUNT
  if (
    authAvailable &&
    authCleanPass &&
    contentAvailable &&
    (contentCategory?.score ?? 0) > CONTENT_MODERATE_THRESHOLD &&
    !lookalikeOrRawIp &&
    !cloudVpsMarker &&
    !knownSuspicious
  ) {
    const basis = ["SPF/DKIM/DMARC all pass (authentic sending path)"];
    const contentEvidence = contentCategory?.evidence.filter((e) => e.weight > 0).slice(0, 2) ?? [];
    for (const e of contentEvidence) basis.push(e.message);
    return {
      archetype: "COMPROMISED_ACCOUNT",
      basis,
      confidence: contentEvidence.length >= 2 ? "medium" : "low",
    };
  }

  // 5. INCONCLUSIVE — a correct answer when evidence is thin or conflicting,
  // never a forced guess.
  const availableCount = [infraAvailable, authAvailable, urlAvailable, contentAvailable].filter(Boolean).length;
  return {
    archetype: "INCONCLUSIVE",
    basis:
      availableCount < 2
        ? ["Insufficient evidence coverage to support a specific archetype"]
        : ["Available evidence does not clearly match a single archetype pattern"],
    confidence: "low",
  };
}
