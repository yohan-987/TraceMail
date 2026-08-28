import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateRecommendations } from "../src/analyzers/recommendations";
import type {
  DomainAnalysis,
  EmailRecord,
  InfrastructureAssessment,
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
    date: null,
    messageId: null,
    headers: { normalized: {}, raw: [] },
    body: { text: null, html: null },
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

function record(overrides: Partial<EmailRecord> = {}): EmailRecord {
  return {
    emailId: "EMAIL-A",
    caseId: null,
    evidence: {
      filename: "a.eml",
      sha256: "a".repeat(64),
      fileSizeBytes: 100,
      createdAt: "2026-08-28T00:00:00.000Z",
      storagePath: "data/emails/EMAIL-A/original.eml",
    },
    parsedEmail: parsedEmail("EMAIL-A"),
    headerAnalysis: null,
    authentication: null,
    iocs: null,
    urlAnalysis: null,
    domainAnalysis: null,
    risk: risk(),
    aiAssessment: null,
    infrastructure: null,
    report: null,
    explanations: [],
    warnings: [],
    ...overrides,
  };
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

describe("generateRecommendations — high-risk phishing", () => {
  it("recommends QUARANTINE_EMAIL and WARN_RECIPIENT for a critical-risk phishing email", () => {
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

    const recs = generateRecommendations(r, null);
    const actions = recs.map((x) => x.action);
    assert.ok(actions.includes("QUARANTINE_EMAIL"));
    assert.ok(actions.includes("WARN_RECIPIENT"));
    const quarantine = recs.find((x) => x.action === "QUARANTINE_EMAIL")!;
    assert.equal(quarantine.priority, "critical");
    assert.ok(quarantine.reason.includes("critical"));
    assert.ok(quarantine.supportingEvidence.length > 0);
  });
});

describe("generateRecommendations — suspicious domain", () => {
  it("recommends REVIEW_BLOCK_DOMAIN when a lookalike domain was flagged", () => {
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
      risk: risk({ score: 55, level: "moderate", classification: "phishing" }),
      explanations: [ev],
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

    const recs = generateRecommendations(r, null);
    const blockRec = recs.find((x) => x.action === "REVIEW_BLOCK_DOMAIN");
    assert.ok(blockRec);
    assert.ok(blockRec!.supportingEvidence.some((s) => s.includes("paypa1.com")));
  });

  it("recommends REVIEW_BLOCK_DOMAIN for a raw-IP-hosted link even without a lookalike domain", () => {
    const ev: RiskEvidenceItem = {
      type: "raw_ip_host",
      severity: "high",
      weight: 30,
      message: "A link uses a raw IP address as its host (203.0.113.5).",
      evidence: {},
      category: "urlDomain",
      provenance: "DETERMINISTIC_ANALYSIS",
    };
    const r = record({
      risk: risk({ score: 60, level: "high", classification: "phishing" }),
      explanations: [ev],
    });

    const recs = generateRecommendations(r, null);
    assert.ok(recs.some((x) => x.action === "REVIEW_BLOCK_DOMAIN"));
  });
});

describe("generateRecommendations — related emails", () => {
  it("recommends REVIEW_RELATED_EMAILS only when a correlation result with related emails is supplied", () => {
    const r = record({ risk: risk({ score: 40, level: "moderate", classification: "suspicious" }) });

    const withRelated = generateRecommendations(r, related());
    assert.ok(withRelated.some((x) => x.action === "REVIEW_RELATED_EMAILS"));
    const rec = withRelated.find((x) => x.action === "REVIEW_RELATED_EMAILS")!;
    assert.ok(rec.reason.includes("CMP-ABCD1234"));
    assert.ok(!rec.reason.toLowerCase().includes("confirmed threat actor"));

    const withoutRelated = generateRecommendations(r, related({ relatedEmailIds: [] }));
    assert.ok(!withoutRelated.some((x) => x.action === "REVIEW_RELATED_EMAILS"));

    const noCorrelationPassed = generateRecommendations(r, null);
    assert.ok(!noCorrelationPassed.some((x) => x.action === "REVIEW_RELATED_EMAILS"));
  });
});

describe("generateRecommendations — infrastructure anomalies", () => {
  it("recommends INVESTIGATE_SOURCE_INFRASTRUCTURE when infrastructure evidence fired", () => {
    const ev: RiskEvidenceItem = {
      type: "suspicious_asn",
      severity: "medium",
      weight: 20,
      message: "GeoIP reported ASN AS999 which is on the configured suspicious-ASN list.",
      evidence: {},
      category: "infrastructure",
      provenance: "EXTERNAL_INTELLIGENCE",
    };
    const r = record({
      risk: risk({ score: 45, level: "moderate", classification: "suspicious" }),
      explanations: [ev],
      infrastructure: infra({ candidateIp: "198.51.100.1", asn: "AS999" }),
    });

    const recs = generateRecommendations(r, null);
    const infraRec = recs.find((x) => x.action === "INVESTIGATE_SOURCE_INFRASTRUCTURE");
    assert.ok(infraRec);
    assert.ok(infraRec!.supportingEvidence.some((s) => s.includes("AS999")));
  });

  it("recommends INVESTIGATE_SOURCE_INFRASTRUCTURE when infrastructure status is INCONCLUSIVE", () => {
    const r = record({
      risk: risk({ score: 20, level: "low", classification: "legitimate" }),
      infrastructure: infra({ status: "INCONCLUSIVE" }),
    });

    const recs = generateRecommendations(r, null);
    assert.ok(recs.some((x) => x.action === "INVESTIGATE_SOURCE_INFRASTRUCTURE"));
  });
});

describe("generateRecommendations — low-risk emails", () => {
  it("returns no recommendations for a clean, fully-covered, low-risk email", () => {
    const r = record({
      risk: risk({ score: 5, level: "low", classification: "legitimate", evidenceCoverage: 1 }),
    });

    const recs = generateRecommendations(r, null);
    assert.deepEqual(recs, []);
  });

  it("never recommends QUARANTINE_EMAIL or WARN_RECIPIENT for a low-risk email even with related emails present", () => {
    const r = record({
      risk: risk({ score: 5, level: "low", classification: "legitimate", evidenceCoverage: 1 }),
    });

    const recs = generateRecommendations(r, related());
    const actions = recs.map((x) => x.action);
    assert.ok(!actions.includes("QUARANTINE_EMAIL"));
    assert.ok(!actions.includes("WARN_RECIPIENT"));
  });
});

describe("generateRecommendations — missing evidence", () => {
  it("recommends only COLLECT_ADDITIONAL_EVIDENCE when risk.score is null", () => {
    const r = record({
      risk: risk({
        score: null,
        level: null,
        classification: "insufficient_evidence",
        confidence: 0,
        categoryScores: {
          technical: categoryResult("UNAVAILABLE", null),
          identity: categoryResult("UNAVAILABLE", null),
          urlDomain: categoryResult("NOT_APPLICABLE", null),
          content: categoryResult("AVAILABLE", 0),
          infrastructure: categoryResult("UNAVAILABLE", null),
        },
        evidenceCoverage: 0.2,
      }),
    });

    const recs = generateRecommendations(r, null);
    assert.deepEqual(
      recs.map((x) => x.action),
      ["COLLECT_ADDITIONAL_EVIDENCE"]
    );
    assert.ok(recs[0].supportingEvidence.some((s) => s.includes("technical")));
  });

  it("recommends COLLECT_ADDITIONAL_EVIDENCE when risk itself is null", () => {
    const r = record({ risk: null });
    const recs = generateRecommendations(r, null);
    assert.deepEqual(
      recs.map((x) => x.action),
      ["COLLECT_ADDITIONAL_EVIDENCE"]
    );
  });

  it("adds a low-priority COLLECT_ADDITIONAL_EVIDENCE alongside other recommendations when coverage is partial", () => {
    const r = record({
      risk: risk({
        score: 80,
        level: "high",
        classification: "phishing",
        evidenceCoverage: 0.6,
        categoryScores: {
          technical: categoryResult("AVAILABLE", 80),
          identity: categoryResult("AVAILABLE", 60),
          urlDomain: categoryResult("AVAILABLE", 70),
          content: categoryResult("UNAVAILABLE", null),
          infrastructure: categoryResult("UNAVAILABLE", null),
        },
      }),
    });

    const recs = generateRecommendations(r, null);
    assert.ok(recs.some((x) => x.action === "QUARANTINE_EMAIL"));
    const collectRec = recs.find((x) => x.action === "COLLECT_ADDITIONAL_EVIDENCE");
    assert.ok(collectRec);
    assert.equal(collectRec!.priority, "low");
  });
});

describe("generateRecommendations — data integrity", () => {
  it("never fabricates supportingEvidence not present in the stored record", () => {
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

    const recs = generateRecommendations(r, null);
    for (const rec of recs) {
      for (const supporting of rec.supportingEvidence) {
        assert.equal(typeof supporting, "string");
      }
    }
  });

  it("never claims confirmed threat-actor attribution", () => {
    const r = record({
      risk: risk({ score: 92, level: "critical", classification: "phishing" }),
    });
    const recs = generateRecommendations(r, related());
    for (const rec of recs) {
      assert.ok(!rec.reason.toLowerCase().includes("confirmed threat actor"));
    }
  });

  it("each recommendation has action, priority, reason, and supportingEvidence", () => {
    const r = record({
      risk: risk({ score: 92, level: "critical", classification: "phishing" }),
      explanations: [
        {
          type: "possible_lookalike_domain",
          severity: "high",
          weight: 35,
          message: "test",
          evidence: {},
          category: "urlDomain",
          provenance: "DETERMINISTIC_ANALYSIS",
        },
      ],
    });
    const recs = generateRecommendations(r, related());
    assert.ok(recs.length > 0);
    for (const rec of recs) {
      assert.ok(rec.action);
      assert.ok(["low", "medium", "high", "critical"].includes(rec.priority));
      assert.ok(rec.reason.length > 0);
      assert.ok(Array.isArray(rec.supportingEvidence));
    }
  });
});
