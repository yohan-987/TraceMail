import type { URLAnalysis, RiskEvidenceItem } from "../schemas/types";
import net from "net";

const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
]);

function isIpHost(hostname: string): boolean {
  // Strip brackets for IPv6 literal hosts like [2001:db8::1].
  const bare = hostname.replace(/^\[|\]$/g, "");
  return net.isIP(bare) !== 0;
}

function domainOf(hostname: string): string {
  // Naive last-two-labels heuristic — doesn't handle multi-part TLDs
  // like co.uk correctly, which is an accepted limitation for the
  // prototype (documented, not silently wrong).
  const parts = hostname.split(".");
  return parts.length <= 2 ? hostname : parts.slice(-2).join(".");
}

function subdomainOf(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length <= 2 ? "" : parts.slice(0, -2).join(".");
}

interface UrlFeatures {
  url: string;
  hostname: string;
  domain: string;
  isHttps: boolean;
  urlLength: number;
  subdomainLength: number;
  pathLength: number;
  queryLength: number;
  hasIpHost: boolean;
  hasAtSymbol: boolean;
  hasEncodedCharacters: boolean;
  hasMultipleSubdomains: boolean;
  isShortened: boolean;
  riskNotes: string[];
}

function analyzeOneUrl(rawUrl: string): UrlFeatures | null {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null; // unparseable — skip rather than guess
  }

  const hostname = parsed.hostname.toLowerCase();
  const subdomain = subdomainOf(hostname);
  const hasIp = isIpHost(hostname);
  const hasAt = rawUrl.includes("@");
  const hasEncoded = /%[0-9a-fA-F]{2}/.test(rawUrl);
  const hasMultipleSubdomains = subdomain.split(".").filter(Boolean).length > 1;
  const isShortened = SHORTENER_HOSTS.has(hostname);

  const riskNotes: string[] = [];
  if (hasIp) riskNotes.push("raw_IP_host");
  if (hasAt || hasEncoded || hasMultipleSubdomains) riskNotes.push("suspicious_structure");
  if (isShortened) riskNotes.push("shortened_URL");

  return {
    url: rawUrl,
    hostname,
    domain: hasIp ? hostname : domainOf(hostname),
    isHttps: parsed.protocol === "https:",
    urlLength: rawUrl.length,
    subdomainLength: subdomain.length,
    pathLength: parsed.pathname.length,
    queryLength: parsed.search.length,
    hasIpHost: hasIp,
    hasAtSymbol: hasAt,
    hasEncodedCharacters: hasEncoded,
    hasMultipleSubdomains,
    isShortened,
    riskNotes,
  };
}

export interface UrlAnalysisResult {
  urlAnalysis: URLAnalysis;
  evidence: RiskEvidenceItem[];
}

/**
 * Structural analysis only — signals, not verdicts. Never fetches any
 * URL. Evidence weights feed the urlDomain risk category; the risk
 * engine combines them (not a flat sum) to avoid overcounting when a
 * single URL trips several correlated notes at once.
 *
 * Evidence is grouped by hostname per finding-type (see
 * docs/audit/PHASE1-AUDIT.md, Finding 1) rather than emitted once per
 * URL instance. A legitimate bulk/marketing email routinely contains
 * dozens of unique tracking-parameter URLs to the SAME host — those
 * survive iocExtractor's exact-string dedupe as "distinct" URLs, and
 * emitting one weighted evidence item per instance let the risk
 * engine's noisy-OR combination saturate the urlDomain category to
 * 100 from nothing but repeated instances of one weak structural
 * observation. One evidence item per (finding-type, hostname) keeps
 * the same weight regardless of how many near-duplicate links to that
 * host exist, while still treating genuinely distinct hosts as
 * distinct evidence.
 */
export function analyzeUrls(emailId: string, urls: string[]): UrlAnalysisResult {
  const analyzed = urls.map(analyzeOneUrl).filter((u): u is UrlFeatures => u !== null);
  const evidence: RiskEvidenceItem[] = [];

  const byHost = new Map<string, UrlFeatures[]>();
  for (const u of analyzed) {
    const bucket = byHost.get(u.hostname);
    if (bucket) bucket.push(u);
    else byHost.set(u.hostname, [u]);
  }

  for (const [hostname, group] of byHost) {
    const ipHosts = group.filter((u) => u.hasIpHost);
    if (ipHosts.length > 0) {
      evidence.push({
        type: "raw_ip_host",
        severity: "high",
        weight: 30,
        message: `${ipHosts.length} link(s) use a raw IP address as their host (${hostname}) instead of a domain name.`,
        evidence: { hostname, count: ipHosts.length, urls: ipHosts.slice(0, 5).map((u) => u.url) },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
        strength: "strong",
      });
    }

    const structural = group.filter((u) => u.hasAtSymbol || u.hasEncodedCharacters || u.hasMultipleSubdomains);
    if (structural.length > 0) {
      evidence.push({
        type: "suspicious_structure",
        severity: "medium",
        weight: 15,
        message: `${structural.length} link(s) to ${hostname} have a suspicious structure (${[
          structural.some((u) => u.hasAtSymbol) && "embedded @ symbol",
          structural.some((u) => u.hasEncodedCharacters) && "percent-encoded characters",
          structural.some((u) => u.hasMultipleSubdomains) && "multiple subdomains",
        ]
          .filter(Boolean)
          .join(", ")}).`,
        evidence: {
          hostname,
          count: structural.length,
          urls: structural.slice(0, 5).map((u) => u.url),
          hasAtSymbol: structural.some((u) => u.hasAtSymbol),
          hasEncodedCharacters: structural.some((u) => u.hasEncodedCharacters),
          hasMultipleSubdomains: structural.some((u) => u.hasMultipleSubdomains),
        },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
        strength: "weak",
      });
    }

    const shortened = group.filter((u) => u.isShortened);
    if (shortened.length > 0) {
      evidence.push({
        type: "shortened_url",
        severity: "low",
        weight: 10,
        message: `${shortened.length} link(s) use a URL-shortening service (${hostname}), which hides the real destination.`,
        evidence: { hostname, count: shortened.length, urls: shortened.slice(0, 5).map((u) => u.url) },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
        strength: "weak",
      });
    }
  }

  return {
    urlAnalysis: {
      emailId,
      urls: analyzed,
    },
    evidence,
  };
}
