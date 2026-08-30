import type {
  EmailAddress,
  EmailRecord,
  Recommendation,
  RelatedEmailsResponse,
} from "../schemas/types";
import { generateRecommendations } from "./recommendations";

// Batch 6 — print-friendly, structured forensic report for one stored
// email. Pure projection: reuses stored EmailRecord data (plus a fresh,
// cheap Batch 5B correlation check and Batch 5C recommendations) — never
// re-runs parsing, ML, LLM, GeoIP, or DNS, and is not itself persisted
// as a second dataset. The frontend renders this and uses the browser's
// Print → Save as PDF; no PDF generation happens here.

export const GEOLOCATION_LIMITATION =
  "Geolocation represents probable network infrastructure and does not establish attacker identity or physical location.";
export const THREAT_SCORE_LIMITATION =
  "Threat scores are analytical risk assessments and are not legal conclusions.";

export interface ReportCaseInformation {
  emailId: string;
  caseId: string | null;
  filename: string;
  generatedAt: string;
}

export interface ReportEvidenceIntegrity {
  sha256: string;
  fileSizeBytes: number;
  collectedAt: string;
  storagePath: string;
  note: string;
}

export interface ReportEmailMetadata {
  subject: string | null;
  from: EmailAddress[];
  to: EmailAddress[];
  date: string | null;
  messageId: string | null;
  attachmentCount: number;
  status: "AVAILABLE" | "UNAVAILABLE";
}

export interface ReportAuthentication {
  spf: { result: string; raw: string | null } | null;
  dkim: { result: string; raw: string | null } | null;
  dmarc: { result: string; policy: string | null; raw: string | null } | null;
  status: "AVAILABLE" | "UNAVAILABLE";
}

export interface ReportReceivedHop {
  hop: number;
  fromHostname: string | null;
  fromIp: string | null;
  byHostname: string | null;
  timestampIso: string | null;
}

export interface ReportHeaderForensics {
  status: string;
  anomalyCount: number;
  anomalies: { type: string; severity: string; message: string; provenance: string }[];
  receivedHopCount: number;
  // Batch 7: the "Received Relay Chain" report section needs the actual
  // per-hop chain, not just a count — reusing the same data the
  // header-forensics analyzer already computed (OBSERVED provenance),
  // never re-derived or re-parsed here.
  receivedChain: ReportReceivedHop[];
}

export interface ReportThreatAssessment {
  score: number | null;
  level: string | null;
  classification: string | null;
  confidence: number | null;
  evidenceCoverage: number | null;
  categoryScores: Record<string, { score: number | null; status: string }> | null;
  status: "AVAILABLE" | "INSUFFICIENT_EVIDENCE";
}

export interface ReportIocs {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
  emails: string[];
  status: "AVAILABLE" | "UNAVAILABLE";
}

export interface ReportUrlDomainAnalysis {
  urls: { url: string; hostname: string; riskNotes: string[] }[];
  domains: { domain: string; lookalikeOf: string | null; similarityScore: number | null }[];
  status: "AVAILABLE" | "NOT_APPLICABLE" | "UNAVAILABLE";
}

export interface ReportInfrastructure {
  candidateIp: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  confidence: number | null;
  status: string;
  interpretation: string | null;
}

export interface ReportMlAiAssessment {
  ml: {
    model: string | null;
    modelVersion: string | null;
    classification: string | null;
    probability: number | null;
    status: string;
  } | null;
  ai: {
    status: string;
    attackType: string | null;
    summary: string | null;
    phishingIntent: number | null;
    credentialHarvesting: number | null;
    financialFraud: number | null;
    impersonation: number | null;
    socialEngineering: number | null;
    malwareDelivery: number | null;
    aiContentScore: number | null;
    provenance: string;
  } | null;
}

export interface ReportWhyFlaggedItem {
  type: string;
  severity: string;
  category: string;
  message: string;
  provenance: string;
  weight: number;
}

export interface ReportRelatedCampaign {
  campaignId: string | null;
  confidence: number;
  relatedEmailIds: string[];
  sharedIndicators: string[];
  sharedInfrastructure: string[];
  reasons: string[];
  available: boolean;
}

export interface ForensicReportContent {
  emailId: string;
  generatedAt: string;
  caseInformation: ReportCaseInformation;
  evidenceIntegrity: ReportEvidenceIntegrity;
  emailMetadata: ReportEmailMetadata;
  authentication: ReportAuthentication;
  headerForensics: ReportHeaderForensics;
  threatAssessment: ReportThreatAssessment;
  iocs: ReportIocs;
  urlDomainAnalysis: ReportUrlDomainAnalysis;
  infrastructure: ReportInfrastructure | null;
  mlAiAssessment: ReportMlAiAssessment;
  whyFlagged: ReportWhyFlaggedItem[];
  recommendedActions: Recommendation[];
  relatedCampaign: ReportRelatedCampaign;
  limitations: string[];
}

/**
 * Builds the full structured report for one already-scanned EmailRecord.
 * `relatedEmails` is an optional pre-computed Batch 5B correlation
 * result — supplying it keeps this a pure function of data the caller
 * already has (mirrors recommendations.ts) and keeps it independently
 * testable without a full stored-email corpus. When omitted, the
 * related-campaign section is reported as unavailable rather than
 * silently empty, so the report never implies "checked, found nothing"
 * when it simply wasn't checked.
 */
export function buildForensicReport(
  record: EmailRecord,
  relatedEmails: RelatedEmailsResponse | null = null
): ForensicReportContent {
  const generatedAt = new Date().toISOString();
  const risk = record.risk;
  const parsed = record.parsedEmail;
  const infra = record.infrastructure;
  const ml = record.mlAssessment ?? null;
  const ai = record.aiAssessment;

  const recommendedActions = generateRecommendations(record, relatedEmails);

  return {
    emailId: record.emailId,
    generatedAt,

    caseInformation: {
      emailId: record.emailId,
      caseId: record.caseId,
      filename: record.evidence.filename,
      generatedAt,
    },

    evidenceIntegrity: {
      sha256: record.evidence.sha256,
      fileSizeBytes: record.evidence.fileSizeBytes,
      collectedAt: record.evidence.createdAt,
      storagePath: record.evidence.storagePath,
      note: "SHA-256 computed over the exact raw bytes as uploaded, before any parsing — preserved untouched as evidence.",
    },

    emailMetadata: parsed
      ? {
          subject: parsed.subject,
          from: parsed.from,
          to: parsed.to,
          date: parsed.date,
          messageId: parsed.messageId,
          attachmentCount: parsed.attachments.length,
          status: "AVAILABLE",
        }
      : {
          subject: null,
          from: [],
          to: [],
          date: null,
          messageId: null,
          attachmentCount: 0,
          status: "UNAVAILABLE",
        },

    authentication: record.authentication
      ? {
          spf: record.authentication.spf,
          dkim: record.authentication.dkim,
          dmarc: record.authentication.dmarc,
          status: "AVAILABLE",
        }
      : { spf: null, dkim: null, dmarc: null, status: "UNAVAILABLE" },

    headerForensics: record.headerAnalysis
      ? {
          status: record.headerAnalysis.status,
          anomalyCount: record.headerAnalysis.anomalies.length,
          anomalies: record.headerAnalysis.anomalies.map((a) => ({
            type: a.type,
            severity: a.severity,
            message: a.message,
            provenance: a.provenance,
          })),
          receivedHopCount: record.headerAnalysis.receivedChain.length,
          receivedChain: record.headerAnalysis.receivedChain.map((hop) => ({
            hop: hop.hop,
            fromHostname: hop.fromHostname,
            fromIp: hop.fromIp,
            byHostname: hop.byHostname,
            timestampIso: hop.timestampIso,
          })),
        }
      : { status: "UNAVAILABLE", anomalyCount: 0, anomalies: [], receivedHopCount: 0, receivedChain: [] },

    threatAssessment: risk
      ? {
          score: risk.score,
          level: risk.level,
          classification: risk.classification,
          confidence: risk.confidence,
          evidenceCoverage: risk.evidenceCoverage,
          categoryScores: risk.categoryScores
            ? Object.fromEntries(
                Object.entries(risk.categoryScores).map(([cat, result]) => [
                  cat,
                  { score: result.score, status: result.status },
                ])
              )
            : null,
          status: risk.score === null ? "INSUFFICIENT_EVIDENCE" : "AVAILABLE",
        }
      : {
          score: null,
          level: null,
          classification: null,
          confidence: null,
          evidenceCoverage: null,
          categoryScores: null,
          status: "INSUFFICIENT_EVIDENCE",
        },

    iocs: record.iocs
      ? {
          ips: record.iocs.ips,
          domains: record.iocs.domains,
          urls: record.iocs.urls,
          hashes: record.iocs.hashes,
          emails: record.iocs.emails,
          status: "AVAILABLE",
        }
      : { ips: [], domains: [], urls: [], hashes: [], emails: [], status: "UNAVAILABLE" },

    urlDomainAnalysis: {
      urls: (record.urlAnalysis?.urls ?? []).map((u) => ({
        url: u.url,
        hostname: u.hostname,
        riskNotes: u.riskNotes,
      })),
      domains: (record.domainAnalysis?.domains ?? []).map((d) => ({
        domain: d.domain,
        lookalikeOf: d.lookalikeOf,
        similarityScore: d.similarityScore,
      })),
      status:
        record.urlAnalysis || record.domainAnalysis
          ? (record.iocs?.urls.length ?? 0) > 0 || (record.iocs?.domains.length ?? 0) > 0
            ? "AVAILABLE"
            : "NOT_APPLICABLE"
          : "UNAVAILABLE",
    },

    infrastructure: infra
      ? {
          candidateIp: infra.candidateIp,
          country: infra.country,
          region: infra.region,
          city: infra.city,
          isp: infra.isp,
          asn: infra.asn,
          confidence: infra.confidence,
          status: infra.status,
          interpretation: infra.interpretation,
        }
      : null,

    mlAiAssessment: {
      ml: ml
        ? {
            model: ml.model,
            modelVersion: ml.modelVersion,
            classification: ml.classification,
            probability: ml.probability,
            status: ml.status,
          }
        : null,
      ai: ai
        ? {
            status: ai.status,
            attackType: ai.attackType,
            summary: ai.summary,
            phishingIntent: ai.phishingIntent,
            credentialHarvesting: ai.credentialHarvesting,
            financialFraud: ai.financialFraud,
            impersonation: ai.impersonation,
            socialEngineering: ai.socialEngineering,
            malwareDelivery: ai.malwareDelivery,
            aiContentScore: ai.aiContentScore,
            provenance: ai.provenance,
          }
        : null,
    },

    // "Why flagged" is the same flat evidence list the risk score itself
    // was computed from — never a re-derivation, so it can't drift from
    // the score above it.
    whyFlagged: (record.explanations ?? []).map((e) => ({
      type: e.type,
      severity: e.severity,
      category: e.category,
      message: e.message,
      provenance: e.provenance,
      weight: e.weight,
    })),

    recommendedActions,

    relatedCampaign: relatedEmails
      ? {
          campaignId: relatedEmails.campaignId,
          confidence: relatedEmails.confidence,
          relatedEmailIds: relatedEmails.relatedEmailIds,
          sharedIndicators: relatedEmails.sharedIndicators,
          sharedInfrastructure: relatedEmails.sharedInfrastructure,
          reasons: relatedEmails.reasons,
          available: true,
        }
      : {
          campaignId: null,
          confidence: 0,
          relatedEmailIds: [],
          sharedIndicators: [],
          sharedInfrastructure: [],
          reasons: [],
          available: false,
        },

    limitations: [GEOLOCATION_LIMITATION, THREAT_SCORE_LIMITATION],
  };
}
