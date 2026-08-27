import type { DomainAnalysis, RiskEvidenceItem } from "../schemas/types";
import { TRUSTED_BRANDS } from "../config/trustedIdentities";
import { normalizedSimilarity } from "../utils/levenshtein";

// Reuses the same small trusted-brand list Batch 2 uses for display-name
// impersonation — one configuration source, not a parallel list.
const TRUSTED_DOMAINS = TRUSTED_BRANDS.flatMap((b) => b.domains);

// Below this, domains are just different — not a plausible look-alike.
const LOOKALIKE_SIMILARITY_THRESHOLD = 0.75;

function tldOf(domain: string): string | null {
  const parts = domain.split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : null;
}

function subdomainOf(domain: string): string | null {
  const parts = domain.split(".");
  return parts.length > 2 ? parts.slice(0, -2).join(".") : null;
}

function hyphenCount(s: string): number {
  return (s.match(/-/g) ?? []).length;
}

function digitCount(s: string): number {
  return (s.match(/\d/g) ?? []).length;
}

function bestSimilarityToTrusted(domain: string, trusted: string): number {
  // Two comparison strategies, take whichever scores higher:
  // (1) Full-string similarity — catches short variants like
  //     "paypa1.com" vs "paypal.com" where the whole domain is close.
  // (2) Prefix similarity — catches brand-name-plus-suffix typosquats
  //     like "paypa1-secure-login.com", where only the FIRST N
  //     characters of the domain's first label resemble the brand
  //     (N = length of the trusted brand's own first label). A full-
  //     string comparison would score this low just because of the
  //     added "-secure-login" suffix, even though "paypa1" is an
  //     obvious one-character edit of "paypal".
  const fullSim = normalizedSimilarity(domain, trusted);

  const domainSld = domain.split(".")[0] ?? domain;
  const trustedSld = trusted.split(".")[0] ?? trusted;
  const prefix = domainSld.slice(0, trustedSld.length);
  const prefixSim = normalizedSimilarity(prefix, trustedSld);

  return Math.max(fullSim, prefixSim);
}

interface DomainFeatures {
  domain: string;
  tld: string | null;
  subdomain: string | null;
  hostnameLength: number;
  hyphenCount: number;
  digitCount: number;
  isPunycode: boolean;
  lookalikeOf: string | null;
  similarityScore: number | null;
}

function analyzeOneDomain(domain: string): DomainFeatures {
  const lower = domain.toLowerCase();

  let lookalikeOf: string | null = null;
  let similarityScore: number | null = null;

  // Only worth comparing if it's NOT already an exact trusted domain
  // (or a legitimate subdomain of one) — otherwise everything would
  // trivially "look like itself".
  const isTrustedOrSubdomain = TRUSTED_DOMAINS.some(
    (t) => lower === t || lower.endsWith(`.${t}`)
  );

  if (!isTrustedOrSubdomain) {
    for (const trusted of TRUSTED_DOMAINS) {
      const sim = bestSimilarityToTrusted(lower, trusted);
      if (sim >= LOOKALIKE_SIMILARITY_THRESHOLD && (similarityScore === null || sim > similarityScore)) {
        similarityScore = sim;
        lookalikeOf = trusted;
      }
    }
  }

  return {
    domain: lower,
    tld: tldOf(lower),
    subdomain: subdomainOf(lower),
    hostnameLength: lower.length,
    hyphenCount: hyphenCount(lower),
    digitCount: digitCount(lower),
    isPunycode: lower.includes("xn--"),
    lookalikeOf,
    similarityScore: similarityScore !== null ? Math.round(similarityScore * 100) / 100 : null,
  };
}

export interface DomainAnalysisResult {
  domainAnalysis: DomainAnalysis;
  evidence: RiskEvidenceItem[];
}

/**
 * Structural + look-alike analysis only — a high similarity score is
 * evidence worth surfacing, never an automatic malicious verdict (a
 * domain can closely resemble a trusted one and still be entirely
 * legitimate, e.g. a regional subsidiary or rebrand).
 */
export function analyzeDomains(emailId: string, domains: string[]): DomainAnalysisResult {
  const analyzed = domains.map(analyzeOneDomain);
  const evidence: RiskEvidenceItem[] = [];

  for (const d of analyzed) {
    if (d.lookalikeOf) {
      evidence.push({
        type: "possible_lookalike_domain",
        severity: "high",
        weight: 35,
        message: `Domain "${d.domain}" closely resembles the trusted domain "${d.lookalikeOf}" (similarity ${Math.round(
          (d.similarityScore ?? 0) * 100
        )}%).`,
        evidence: { domain: d.domain, lookalikeOf: d.lookalikeOf, similarityScore: d.similarityScore },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
      });
    }
  }

  return {
    domainAnalysis: { emailId, domains: analyzed },
    evidence,
  };
}
