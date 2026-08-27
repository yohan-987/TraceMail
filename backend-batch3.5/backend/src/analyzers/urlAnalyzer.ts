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
 */
export function analyzeUrls(emailId: string, urls: string[]): UrlAnalysisResult {
  const analyzed = urls.map(analyzeOneUrl).filter((u): u is UrlFeatures => u !== null);
  const evidence: RiskEvidenceItem[] = [];

  for (const u of analyzed) {
    if (u.hasIpHost) {
      evidence.push({
        type: "raw_ip_host",
        severity: "high",
        weight: 30,
        message: `A link uses a raw IP address as its host (${u.hostname}) instead of a domain name.`,
        evidence: { url: u.url },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
      });
    }
    if (u.hasAtSymbol || u.hasEncodedCharacters || u.hasMultipleSubdomains) {
      evidence.push({
        type: "suspicious_structure",
        severity: "medium",
        weight: 15,
        message: `A link has a suspicious structure (${[
          u.hasAtSymbol && "embedded @ symbol",
          u.hasEncodedCharacters && "percent-encoded characters",
          u.hasMultipleSubdomains && "multiple subdomains",
        ]
          .filter(Boolean)
          .join(", ")}).`,
        evidence: {
          url: u.url,
          hasAtSymbol: u.hasAtSymbol,
          hasEncodedCharacters: u.hasEncodedCharacters,
          hasMultipleSubdomains: u.hasMultipleSubdomains,
        },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
      });
    }
    if (u.isShortened) {
      evidence.push({
        type: "shortened_url",
        severity: "low",
        weight: 10,
        message: `A link uses a URL-shortening service (${u.hostname}), which hides the real destination.`,
        evidence: { url: u.url, hostname: u.hostname },
        category: "urlDomain",
        provenance: "DETERMINISTIC_ANALYSIS",
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
