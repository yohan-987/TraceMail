import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildForensicReport,
  GEOLOCATION_LIMITATION,
  THREAT_SCORE_LIMITATION,
} from "../src/analyzers/reportBuilder";
import type {
  AuthenticationAnalysis,
  DomainAnalysis,
  EmailRecord,
  HeaderAnalysis,
  InfrastructureAssessment,
  IOCSet,
  MLAssessment,
  ParsedEmail,
  RelatedEmailsResponse,
  RiskAssessment,
  RiskEvidenceItem,
} from "../src/schemas/types";

function parsedEmail(emailId: string, extras?: Partial<ParsedEmail>): ParsedEmail {
  return {
    emailId,
    subject: "Test subject",
    from: [{ displayName: null, email: "a@example.com", localPart: "a", domain: "example.com" }],
    to: [{ displayName: null, email: "victim@example.org", localPart: "victim", domain: "example.org" }],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: "2026-08-28T00:00:00.000Z",
    messageId: "<abc@example.com>",
    headers: { normalized: {}, raw: [] },
    body: { text: "hello", html: null },
    attachments: [],
    ...extras,
  };
}

function categoryResult(status: "AVAILABLE" | "NOT_APPLICABLE" | "UNAVAILABLE", score: number | null, evidence: RiskEvidenceItem[] = []) {
  return { score: status === "AVAILABLE" ? score : null, status, evidence };
}

function risk(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    emailId: "EMAIL-A",
    categoryScores: {
      technical: categoryResult("AVAILABLE", 0),
      identity: categoryResult("AVAILABLE", 0),
      urlDomain: categoryResult("AVAILABLE", 0),
      content: categoryResult("AVAILABLE", 0),
      infrastructure: categoryResult("AVAILABLE", 0),
    },
    score: 10,
    level: "low",
    classification: "legitimate",
    confidence: 0.4,
    evidenceCoverage: 1,
    ...overrides,
  };
}

function auth(overrides: Partial<AuthenticationAnalysis> = {}): AuthenticationAnalysis {
  return {
    emailId: "EMAIL-A",
    spf: { result: "pass", raw: "v=spf1 pass" },
    dkim: { result: "pass", raw: "d=example.com" },
    dmarc: { result: "pass", policy: "reject", raw: "p=reject" },
    ...overrides,
  };
}

function headerAnalysis(overrides: Partial<HeaderAnalysis> = {}): HeaderAnalysis {
  return { emailId: "EMAIL-A", anomalies: [], receivedChain: [], status: "VERIFIED", ...overrides };
}

function iocs(overrides: Partial<IOCSet> = {}): IOCSet {
  return { emailId: "EMAIL-A", ips: [], domains: [], urls: [], hashes: [], emails: [], ...overrides };
}

function domainAnalysis(domains: DomainAnalysis["domains"]): DomainAnalysis {
  return { emailId: "EMAIL-A", domains };
}

function infra(overrides: Partial<InfrastructureAssessment> = {}): InfrastructureAssessment {
  return {
    emailId: "EMAIL-A",
    candidateIp: null,
    country: null,
    region: null,
    city: null,
    isp: null,
    asn: null,
    confidence: null,
    status: "AVAILABLE",
    ipIntelligence: [],
    domainIntelligence: [],
    interpretation: "probable_infrastructure",
    ...overrides,
  };
}

function mlAssessment(overrides: Partial<MLAssessment> = {}): MLAssessment {
  return {
    emailId: "EMAIL-A",
    model: "tfidf-logistic-v1",
    modelVersion: "1.0.0",
    classification: "legitimate",
    probability: 0.1,
    status: "AVAILABLE",
    ...overrides,
  };
}

function related(overrides: Partial<RelatedEmailsResponse> = {}): RelatedEmailsResponse {
  return {
    emailId: "EMAIL-A",
    campaignId: "CMP-ABCD1234",
    confidence: 0.6,
    relatedEmailIds: ["EMAIL-B"],
    sharedIndicators: ["SHARED_DOMAIN:evil.example"],
    sharedInfrastructure: [],
    reasons: ["Likely Related Campaign CMP-ABCD1234: 1 potentially related email(s)."],
    ...overrides,
  };
}

function record(overrides: Partial<EmailRecord> = {}): EmailRecord {
  return {
    emailId: "EMAIL-A",
    caseId: "CASE-1",
    evidence: {
      filename: "a.eml",
      sha256: "a".repeat(64),
      fileSizeBytes: 1234,
      createdAt: "2026-08-28T00:00:00.000Z",
      storagePath: "data/emails/EMAIL-A/original.eml",
    },
    parsedEmail: parsedEmail("EMAIL-A"),
    headerAnalysis: headerAnalysis(),
    authentication: auth(),
    iocs: iocs(),
    urlAnalysis: null,
    domainAnalysis: null,
    risk: risk(),
    aiAssessment: null,
    infrastructure: null,
    report: null,
    explanations: [],
    warnings: [],
    mlAssessment: mlAssessment(),
    intelligenceAssessment: null,
    ...overrides,
  };
}

describe("buildForensicReport — case info, evidence integrity, limitations", () => {
  it("always includes emailId, caseId, SHA-256, timestamps, and the two required limitation strings verbatim", () => {
    const r = record();
    const report = buildForensicReport(r, null);

    assert.equal(report.emailId, "EMAIL-A");
    assert.equal(report.caseInformation.caseId, "CASE-1");
    assert.equal(report.evidenceIntegrity.sha256, "a".repeat(64));
    assert.equal(report.evidenceIntegrity.collectedAt, "2026-08-28T00:00:00.000Z");
    assert.ok(report.generatedAt);
    assert.ok(report.limitations.includes(GEOLOCATION_LIMITATION));
    assert.ok(report.limitations.includes(THREAT_SCORE_LIMITATION));
  });

  it("reports caseId as null when the email has no case, without inventing one", () => {
    const r = record({ caseId: null });
    const report = buildForensicReport(r, null);
    assert.equal(report.caseInformation.caseId, null);
  });
});

describe("buildForensicReport — high-risk phishing", () => {
  it("surfaces threat assessment, why-flagged evidence, and QUARANTINE_EMAIL recommendation", () => {
    const ev: RiskEvidenceItem = {
      type: "possible_lookalike_domain",
      severity: "high",
      weight: 35,
      message: 'Domain "paypa1.com" closely resembles the trusted domain "paypal.com".',
      evidence: {},
      category: "urlDomain",
      provenance: "DETERMINISTIC_ANALYSIS",
    };
    const r = record({
      risk: risk({ score: 92, level: "critical", classification: "phishing" }),
      explanations: [ev],
    });

    const report = buildForensicReport(r, null);
    assert.equal(report.threatAssessment.score, 92);
    assert.equal(report.threatAssessment.level, "critical");
    assert.equal(report.threatAssessment.status, "AVAILABLE");
    assert.equal(report.whyFlagged.length, 1);
    assert.equal(report.whyFlagged[0].type, "possible_lookalike_domain");
    assert.ok(report.recommendedActions.some((a) => a.action === "QUARANTINE_EMAIL"));
  });
});

describe("buildForensicReport — suspicious domain", () => {
  it("includes flagged lookalike domains in the URL/domain analysis section", () => {
    const r = record({
      iocs: iocs({ domains: ["paypa1.com"] }),
      domainAnalysis: domainAnalysis([
        {
          domain: "paypa1.com",
          tld: "com",
          subdomain: null,
          hostnameLength: 10,
          hyphenCount: 0,
          digitCount: 1,
          isPunycode: false,
          lookalikeOf: "paypal.com",
          similarityScore: 0.9,
        },
      ]),
    });

    const report = buildForensicReport(r, null);
    assert.equal(report.urlDomainAnalysis.status, "AVAILABLE");
    assert.equal(report.urlDomainAnalysis.domains[0].lookalikeOf, "paypal.com");
  });

  it("marks URL/domain analysis NOT_APPLICABLE when there were no URLs or domains", () => {
    const r = record({ iocs: iocs({ domains: [], urls: [] }), urlAnalysis: { emailId: "EMAIL-A", urls: [] }, domainAnalysis: domainAnalysis([]) });
    const report = buildForensicReport(r, null);
    assert.equal(report.urlDomainAnalysis.status, "NOT_APPLICABLE");
  });
});

describe("buildForensicReport — related emails / campaign", () => {
  it("includes related-campaign section when a correlation result is supplied", () => {
    const r = record();
    const report = buildForensicReport(r, related());
    assert.equal(report.relatedCampaign.available, true);
    assert.equal(report.relatedCampaign.campaignId, "CMP-ABCD1234");
    assert.deepEqual(report.relatedCampaign.relatedEmailIds, ["EMAIL-B"]);
  });

  it("marks related-campaign section unavailable (not fabricated as empty-and-checked) when no correlation was supplied", () => {
    const r = record();
    const report = buildForensicReport(r, null);
    assert.equal(report.relatedCampaign.available, false);
    assert.equal(report.relatedCampaign.campaignId, null);
    assert.deepEqual(report.relatedCampaign.relatedEmailIds, []);
  });
});

describe("buildForensicReport — infrastructure anomalies", () => {
  it("includes infrastructure/geolocation fields and the geolocation limitation", () => {
    const r = record({
      infrastructure: infra({
        candidateIp: "198.51.100.1",
        country: "US",
        asn: "AS999",
        status: "AVAILABLE",
      }),
    });
    const report = buildForensicReport(r, null);
    assert.ok(report.infrastructure);
    assert.equal(report.infrastructure!.candidateIp, "198.51.100.1");
    assert.equal(report.infrastructure!.asn, "AS999");
    assert.ok(report.limitations.includes(GEOLOCATION_LIMITATION));
  });

  it("reports infrastructure as null (not fabricated) when infrastructure enrichment never ran", () => {
    const r = record({ infrastructure: null });
    const report = buildForensicReport(r, null);
    assert.equal(report.infrastructure, null);
  });
});

describe("buildForensicReport — low-risk emails", () => {
  it("reports a clean low-risk email with an empty recommendations list", () => {
    const r = record({ risk: risk({ score: 5, level: "low", classification: "legitimate" }) });
    const report = buildForensicReport(r, null);
    assert.equal(report.threatAssessment.level, "low");
    assert.deepEqual(report.recommendedActions, []);
    assert.deepEqual(report.whyFlagged, []);
  });
});

describe("buildForensicReport — missing evidence", () => {
  it("marks threat assessment INSUFFICIENT_EVIDENCE when risk.score is null, without fabricating a score", () => {
    const r = record({
      risk: risk({
        score: null,
        level: null,
        classification: "insufficient_evidence",
        confidence: 0,
        evidenceCoverage: 0.2,
      }),
    });
    const report = buildForensicReport(r, null);
    assert.equal(report.threatAssessment.status, "INSUFFICIENT_EVIDENCE");
    assert.equal(report.threatAssessment.score, null);
  });

  it("marks each section UNAVAILABLE rather than fabricating content when its source data is null", () => {
    const r = record({
      parsedEmail: null,
      headerAnalysis: null,
      authentication: null,
      iocs: null,
      risk: null,
    });
    const report = buildForensicReport(r, null);
    assert.equal(report.emailMetadata.status, "UNAVAILABLE");
    assert.equal(report.authentication.status, "UNAVAILABLE");
    assert.equal(report.headerForensics.status, "UNAVAILABLE");
    assert.equal(report.iocs.status, "UNAVAILABLE");
    assert.equal(report.threatAssessment.status, "INSUFFICIENT_EVIDENCE");
  });
});

describe("buildForensicReport — data integrity", () => {
  it("why-flagged is exactly the stored explanations list, never re-derived", () => {
    const ev1: RiskEvidenceItem = {
      type: "spf_fail",
      severity: "medium",
      weight: 25,
      message: "SPF failed.",
      evidence: {},
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    };
    const ev2: RiskEvidenceItem = {
      type: "urgency_language",
      severity: "low",
      weight: 10,
      message: "Urgency language detected.",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    };
    const r = record({ explanations: [ev1, ev2] });
    const report = buildForensicReport(r, null);
    assert.deepEqual(
      report.whyFlagged.map((w) => w.type),
      ["spf_fail", "urgency_language"]
    );
  });

  it("does not generate a PDF or binary payload — response is plain structured JSON", () => {
    const r = record();
    const report = buildForensicReport(r, null);
    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes("%PDF"));
    assert.equal(typeof report, "object");
  });
});
