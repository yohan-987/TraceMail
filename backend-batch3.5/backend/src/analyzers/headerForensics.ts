import type {
  ParsedEmail,
  HeaderAnalysis,
  HeaderAnomaly,
  ReceivedHop,
  AuthenticationAnalysis,
  AuthResult,
  EvidenceStatus,
} from "../schemas/types";
import { classifyIp, findFirstIp } from "../utils/ip";
import { TRUSTED_BRANDS, AUTHORITY_KEYWORDS, FREE_WEBMAIL_DOMAINS } from "../config/trustedIdentities";

const KNOWN_AUTH_RESULTS: readonly string[] = [
  "pass",
  "fail",
  "softfail",
  "neutral",
  "none",
  "temperror",
  "permerror",
];

function normalizeAuthResult(token: string | null | undefined): AuthResult | "unknown" {
  if (!token) return "unknown";
  const t = token.toLowerCase();
  return KNOWN_AUTH_RESULTS.includes(t) ? (t as AuthResult) : "unknown";
}

function firstIfArray(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) ? value[0] ?? null : value;
}

// --- From vs Reply-To / Return-Path -----------------------------------

function checkAddressMismatches(parsed: ParsedEmail): HeaderAnomaly[] {
  const anomalies: HeaderAnomaly[] = [];
  const fromDomain = parsed.from[0]?.domain ?? null;
  const replyToDomain = parsed.replyTo[0]?.domain ?? null;
  const returnPathDomain = parsed.returnPath[0]?.domain ?? null;

  if (fromDomain && replyToDomain && replyToDomain !== fromDomain) {
    anomalies.push({
      type: "reply_to_mismatch",
      severity: "medium",
      weight: 40,
      message: `Reply-To domain (${replyToDomain}) differs from the sender domain (${fromDomain}).`,
      evidence: { fromDomain, replyToDomain },
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  // Legitimate mailing systems (newsletters, ticketing, bulk senders)
  // commonly use a different Return-Path — this is evidence, not proof,
  // hence the lower weight than reply_to_mismatch.
  if (fromDomain && returnPathDomain && returnPathDomain !== fromDomain) {
    anomalies.push({
      type: "return_path_mismatch",
      severity: "low",
      weight: 20,
      message: `Return-Path domain (${returnPathDomain}) differs from the sender domain (${fromDomain}).`,
      evidence: { fromDomain, returnPathDomain },
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  return anomalies;
}

// --- Display name impersonation ----------------------------------------

function checkDisplayNameImpersonation(parsed: ParsedEmail): HeaderAnomaly[] {
  const anomalies: HeaderAnomaly[] = [];
  const from = parsed.from[0];
  if (!from?.displayName || !from.domain) return anomalies;

  const nameLower = from.displayName.toLowerCase();
  const fromDomain = from.domain.toLowerCase();

  const matchedBrand = TRUSTED_BRANDS.find((brand) => nameLower.includes(brand.name.toLowerCase()));
  if (matchedBrand) {
    const domainIsBrandOwned = matchedBrand.domains.some(
      (d) => fromDomain === d || fromDomain.endsWith(`.${d}`)
    );
    if (!domainIsBrandOwned) {
      anomalies.push({
        type: "display_name_brand_impersonation",
        severity: "high",
        weight: 30,
        message: `Display name references "${matchedBrand.name}" but the sender domain (${fromDomain}) does not belong to that organization.`,
        evidence: { displayName: from.displayName, fromDomain, brand: matchedBrand.name },
        category: "identity",
        provenance: "DETERMINISTIC_ANALYSIS",
      });
      return anomalies; // don't double-flag with the generic authority check below
    }
  }

  const matchedKeyword = AUTHORITY_KEYWORDS.find((kw) => nameLower.includes(kw));
  if (matchedKeyword && FREE_WEBMAIL_DOMAINS.includes(fromDomain)) {
    anomalies.push({
      type: "display_name_authority_impersonation",
      severity: "medium",
      weight: 20,
      message: `Display name implies an authority role ("${matchedKeyword}") but is sent from a free/generic webmail domain (${fromDomain}).`,
      evidence: { displayName: from.displayName, fromDomain, matchedKeyword },
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  return anomalies;
}

// --- Received chain ------------------------------------------------------

function parseReceivedChain(parsed: ParsedEmail): ReceivedHop[] {
  const receivedLines = parsed.headers.raw.filter((h) => h.name.toLowerCase() === "received");

  return receivedLines.map((h, index) => {
    const line = h.value;
    const fromMatch = line.match(/\bfrom\s+([^\s(;,]+)/i);
    const byMatch = line.match(/\bby\s+([^\s(;,]+)/i);
    const fromIp = findFirstIp(line);

    // Timestamp is conventionally everything after the last ';'.
    const semiIndex = line.lastIndexOf(";");
    const timestampRaw = semiIndex >= 0 ? line.slice(semiIndex + 1).trim() : null;
    let timestampIso: string | null = null;
    if (timestampRaw) {
      const parsedDate = new Date(timestampRaw);
      if (!Number.isNaN(parsedDate.getTime())) timestampIso = parsedDate.toISOString();
    }

    return {
      hop: index + 1,
      fromHostname: fromMatch?.[1] ?? null,
      fromIp,
      fromIpClassification: fromIp ? classifyIp(fromIp) : null,
      byHostname: byMatch?.[1] ?? null,
      timestampRaw,
      timestampIso,
      rawHeader: line,
    };
  });
}

// --- Message-ID ------------------------------------------------------------

function checkMessageId(parsed: ParsedEmail): HeaderAnomaly[] {
  const anomalies: HeaderAnomaly[] = [];
  const messageId = parsed.messageId;
  const fromDomain = parsed.from[0]?.domain ?? null;

  if (!messageId) {
    anomalies.push({
      type: "message_id_missing",
      severity: "low",
      weight: 5,
      message: "No Message-ID header was present.",
      evidence: {},
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
    return anomalies;
  }

  const wellFormed = /^<[^<>@\s]+@[^<>@\s]+>$/.test(messageId);
  if (!wellFormed) {
    anomalies.push({
      type: "message_id_malformed",
      severity: "low",
      weight: 5,
      message: "Message-ID does not follow standard <local@domain> syntax.",
      evidence: { messageId },
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  const domainMatch = messageId.match(/@([^<>@\s]+)>?$/);
  const messageIdDomain = domainMatch?.[1]?.toLowerCase() ?? null;

  if (messageIdDomain && fromDomain && messageIdDomain !== fromDomain.toLowerCase()) {
    anomalies.push({
      type: "message_id_domain_mismatch",
      severity: "low",
      weight: 10,
      message: `Message-ID domain (${messageIdDomain}) differs from the sender domain (${fromDomain}).`,
      evidence: { messageIdDomain, fromDomain },
      category: "identity",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  return anomalies;
}

// --- SPF / DKIM / DMARC ----------------------------------------------------

function parseAuthentication(parsed: ParsedEmail): AuthenticationAnalysis {
  const authResultsRaw = firstIfArray(parsed.headers.normalized["authentication-results"]);
  const spfHeaderRaw = firstIfArray(parsed.headers.normalized["received-spf"]);

  let spfToken: string | null = null;
  let dkimToken: string | null = null;
  let dmarcToken: string | null = null;
  let dmarcPolicy: string | null = null;

  if (authResultsRaw) {
    spfToken = authResultsRaw.match(/\bspf=([a-z]+)/i)?.[1] ?? null;
    dkimToken = authResultsRaw.match(/\bdkim=([a-z]+)/i)?.[1] ?? null;
    dmarcToken = authResultsRaw.match(/\bdmarc=([a-z]+)/i)?.[1] ?? null;
    // Best-effort policy extraction (e.g. "dmarc=fail (p=REJECT ...)").
    // Not a full DMARC record parser — just what's echoed in this header.
    dmarcPolicy = authResultsRaw.match(/\bp=([a-z]+)/i)?.[1]?.toLowerCase() ?? null;
  }

  // Fall back to Received-SPF when Authentication-Results didn't have SPF.
  if (!spfToken && spfHeaderRaw) {
    spfToken = spfHeaderRaw.match(/^([a-z]+)/i)?.[1] ?? null;
  }

  return {
    emailId: parsed.emailId,
    spf: { result: normalizeAuthResult(spfToken), raw: authResultsRaw ?? spfHeaderRaw ?? null },
    dkim: { result: normalizeAuthResult(dkimToken), raw: authResultsRaw ?? null },
    dmarc: {
      result: normalizeAuthResult(dmarcToken),
      policy: dmarcPolicy,
      raw: authResultsRaw ?? null,
    },
  };
}

function authenticationAnomalies(auth: AuthenticationAnalysis): HeaderAnomaly[] {
  const anomalies: HeaderAnomaly[] = [];

  if (auth.spf.result === "fail") {
    anomalies.push({
      type: "spf_fail",
      severity: "high",
      weight: 25,
      message: "SPF authentication failed.",
      evidence: { spf: auth.spf.raw },
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  } else if (auth.spf.result === "softfail") {
    anomalies.push({
      type: "spf_softfail",
      severity: "medium",
      weight: 10,
      message: "SPF authentication soft-failed.",
      evidence: { spf: auth.spf.raw },
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  if (auth.dkim.result === "fail") {
    anomalies.push({
      type: "dkim_fail",
      severity: "high",
      weight: 25,
      message: "DKIM signature verification failed.",
      evidence: { dkim: auth.dkim.raw },
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  if (auth.dmarc.result === "fail") {
    anomalies.push({
      type: "dmarc_fail",
      severity: "high",
      weight: 30,
      message: "DMARC alignment failed.",
      evidence: { dmarc: auth.dmarc.raw, policy: auth.dmarc.policy },
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    });
  }

  // Deliberately no anomaly for "none"/"unknown"/"pass" — an absent or
  // unavailable authentication result is NOT itself evidence of malice
  // (INCONCLUSIVE ≠ MALICIOUS, per project-wide principle).
  return anomalies;
}

// --- Public entry point ----------------------------------------------------

export interface HeaderForensicsResult {
  headerAnalysis: HeaderAnalysis;
  authentication: AuthenticationAnalysis;
}

export function analyzeHeaders(parsed: ParsedEmail): HeaderForensicsResult {
  const authentication = parseAuthentication(parsed);

  const anomalies: HeaderAnomaly[] = [
    ...checkAddressMismatches(parsed),
    ...checkDisplayNameImpersonation(parsed),
    ...checkMessageId(parsed),
    ...authenticationAnomalies(authentication),
  ];

  const receivedChain = parseReceivedChain(parsed);

  let status: EvidenceStatus;
  if (parsed.headers.raw.length === 0) {
    status = "UNAVAILABLE";
  } else if (anomalies.length === 0) {
    status = "VERIFIED";
  } else {
    status = "SUSPICIOUS";
  }

  const headerAnalysis: HeaderAnalysis = {
    emailId: parsed.emailId,
    anomalies,
    receivedChain,
    status,
  };

  return { headerAnalysis, authentication };
}
