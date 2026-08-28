import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { correlateEmail } from "../src/analyzers/correlation";
import type {
  DomainAnalysis,
  EmailRecord,
  InfrastructureAssessment,
  IOCSet,
  ParsedEmail,
} from "../src/schemas/types";

function parsedEmail(emailId: string, extras?: Partial<ParsedEmail>): ParsedEmail {
  return {
    emailId,
    subject: "Verify your account immediately",
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

function iocs(emailId: string, extras?: Partial<IOCSet>): IOCSet {
  return { emailId, ips: [], domains: [], urls: [], hashes: [], emails: [], ...extras };
}

function record(emailId: string, overrides: Partial<EmailRecord> = {}): EmailRecord {
  return {
    emailId,
    caseId: null,
    evidence: {
      filename: `${emailId}.eml`,
      sha256: "a".repeat(64),
      fileSizeBytes: 100,
      createdAt: "2026-08-28T00:00:00.000Z",
      storagePath: `data/emails/${emailId}/original.eml`,
    },
    parsedEmail: parsedEmail(emailId),
    headerAnalysis: null,
    authentication: null,
    iocs: iocs(emailId),
    urlAnalysis: null,
    domainAnalysis: null,
    risk: null,
    aiAssessment: null,
    infrastructure: null,
    report: null,
    explanations: [],
    warnings: [],
    ...overrides,
    emailId,
  };
}

function domainAnalysis(emailId: string, domains: DomainAnalysis["domains"]): DomainAnalysis {
  return { emailId, domains };
}

function infra(overrides: Partial<InfrastructureAssessment> = {}): InfrastructureAssessment {
  return {
    emailId: "unused",
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

describe("correlateEmail — positive correlations", () => {
  it("relates emails sharing a domain AND a URL (multi-signal, not domain alone)", () => {
    const selected = record("EMAIL-A", {
      iocs: iocs("EMAIL-A", { domains: ["evil.example"], urls: ["http://evil.example/login"] }),
    });
    const other = record("EMAIL-B", {
      iocs: iocs("EMAIL-B", { domains: ["evil.example"], urls: ["http://evil.example/login"] }),
    });
    const unrelated = record("EMAIL-C");

    const result = correlateEmail(selected, [selected, other, unrelated]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
    assert.ok(result.confidence >= 0.3);
    assert.ok(result.sharedIndicators.some((s) => s.startsWith("SHARED_DOMAIN:")));
    assert.ok(result.sharedIndicators.some((s) => s.startsWith("SHARED_URL:")));
    assert.ok(result.campaignId);
    assert.ok(result.reasons.some((r) => r.includes("Likely Related Campaign")));
    assert.ok(result.reasons.some((r) => r.includes("EMAIL-B")));
  });

  it("relates emails sharing a public IP alone", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { ips: ["198.51.100.23"] }) });
    const other = record("EMAIL-B", { iocs: iocs("EMAIL-B", { ips: ["198.51.100.23"] }) });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
    assert.ok(result.sharedInfrastructure.some((s) => s.startsWith("SHARED_IP:")));
  });

  it("relates emails sharing an attachment hash alone", () => {
    const selected = record("EMAIL-A", {
      parsedEmail: parsedEmail("EMAIL-A", { subject: "Q3 report" }),
      iocs: iocs("EMAIL-A", { hashes: ["deadbeef".repeat(8)] }),
    });
    const other = record("EMAIL-B", {
      parsedEmail: parsedEmail("EMAIL-B", { subject: "Team offsite photos" }),
      iocs: iocs("EMAIL-B", { hashes: ["deadbeef".repeat(8)] }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
    assert.equal(result.confidence, 0.5);
  });

  it("relates emails whose sender domains look alike the same brand, when combined with another signal", () => {
    const selected = record("EMAIL-A", {
      parsedEmail: parsedEmail("EMAIL-A", {
        from: [{ displayName: null, email: "x@paypa1-login.com", localPart: "x", domain: "paypa1-login.com" }],
      }),
      iocs: iocs("EMAIL-A", { domains: ["paypa1-login.com"], urls: ["http://shared.example/x"] }),
      domainAnalysis: domainAnalysis("EMAIL-A", [
        {
          domain: "paypa1-login.com",
          tld: "com",
          subdomain: null,
          hostnameLength: 16,
          hyphenCount: 1,
          digitCount: 1,
          isPunycode: false,
          lookalikeOf: "paypal.com",
          similarityScore: 0.9,
        },
      ]),
    });
    const other = record("EMAIL-B", {
      parsedEmail: parsedEmail("EMAIL-B", {
        from: [{ displayName: null, email: "y@paypa1-secure.net", localPart: "y", domain: "paypa1-secure.net" }],
      }),
      iocs: iocs("EMAIL-B", { domains: ["paypa1-secure.net"], urls: ["http://shared.example/x"] }),
      domainAnalysis: domainAnalysis("EMAIL-B", [
        {
          domain: "paypa1-secure.net",
          tld: "net",
          subdomain: null,
          hostnameLength: 17,
          hyphenCount: 1,
          digitCount: 1,
          isPunycode: false,
          lookalikeOf: "paypal.com",
          similarityScore: 0.85,
        },
      ]),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
    assert.ok(
      result.reasons.some((r) => r.includes("sender domain similarity") || r.includes("shared url"))
    );
  });

  it("relates emails with near-identical subjects combined with a shared domain", () => {
    const selected = record("EMAIL-A", {
      parsedEmail: parsedEmail("EMAIL-A", { subject: "Your invoice #4471 is overdue please pay now" }),
      iocs: iocs("EMAIL-A", { domains: ["billing-example.com"] }),
    });
    const other = record("EMAIL-B", {
      parsedEmail: parsedEmail("EMAIL-B", { subject: "Your invoice #4482 is overdue please pay now" }),
      iocs: iocs("EMAIL-B", { domains: ["billing-example.com"] }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
    assert.ok(result.reasons.some((r) => r.includes("subject similarity")));
  });
});

describe("correlateEmail — negative cases and data integrity", () => {
  it("does not relate emails with no shared indicators", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { domains: ["a.example"] }) });
    const other = record("EMAIL-B", { iocs: iocs("EMAIL-B", { domains: ["b.example"] }) });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, []);
    assert.equal(result.confidence, 0);
    assert.equal(result.campaignId, null);
    assert.deepEqual(result.sharedIndicators, []);
    assert.deepEqual(result.reasons, []);
  });

  it("does not treat a single shared domain alone as a related email (weak single-signal overlap)", () => {
    const selected = record("EMAIL-A", {
      parsedEmail: parsedEmail("EMAIL-A", { subject: "Q3 report" }),
      iocs: iocs("EMAIL-A", { domains: ["shared.example"] }),
    });
    const other = record("EMAIL-B", {
      parsedEmail: parsedEmail("EMAIL-B", { subject: "Team offsite photos" }),
      iocs: iocs("EMAIL-B", { domains: ["shared.example"] }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, []);
    assert.equal(result.campaignId, null);
  });

  it("does not treat similar subject wording alone as a related email", () => {
    const selected = record("EMAIL-A", {
      parsedEmail: parsedEmail("EMAIL-A", { subject: "Your invoice #4471 is overdue please pay now" }),
    });
    const other = record("EMAIL-B", {
      parsedEmail: parsedEmail("EMAIL-B", { subject: "Your invoice #4482 is overdue please pay now" }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, []);
  });

  it("handles missing/malformed analysis (null iocs, domainAnalysis, infrastructure) without crashing", () => {
    const selected = record("EMAIL-A", { iocs: null, domainAnalysis: null, infrastructure: null });
    const other = record("EMAIL-B", { iocs: null, domainAnalysis: null, infrastructure: null });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, []);
    assert.equal(result.confidence, 0);
  });

  it("does not treat shared private/loopback IPs as correlation evidence", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { ips: ["10.0.0.1"] }) });
    const other = record("EMAIL-B", { iocs: iocs("EMAIL-B", { ips: ["10.0.0.1"] }) });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, []);
  });

  it("is correlatable even without a caseId", () => {
    const selected = record("EMAIL-A", {
      caseId: null,
      iocs: iocs("EMAIL-A", { ips: ["198.51.100.1"] }),
    });
    const other = record("EMAIL-B", { caseId: null, iocs: iocs("EMAIL-B", { ips: ["198.51.100.1"] }) });

    const result = correlateEmail(selected, [selected, other]);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
  });
});

describe("correlateEmail — validation", () => {
  it("keeps confidence bounded between 0 and 1 even with many stacked signals", () => {
    const shared = {
      ips: ["198.51.100.1"],
      domains: ["evil.example"],
      urls: ["http://evil.example/a"],
      hashes: ["deadbeef".repeat(8)],
    };
    const selected = record("EMAIL-A", {
      iocs: iocs("EMAIL-A", shared),
      infrastructure: infra({ asn: "AS999", candidateIp: "198.51.100.1", ipIntelligence: [
        { ip: "198.51.100.1", country: null, region: null, city: null, isp: null, asn: "AS999", organization: "Evil Hosting", hosting: null, status: "AVAILABLE" },
      ] }),
    });
    const other = record("EMAIL-B", {
      iocs: iocs("EMAIL-B", shared),
      infrastructure: infra({ asn: "AS999", candidateIp: "198.51.100.1", ipIntelligence: [
        { ip: "198.51.100.1", country: null, region: null, city: null, isp: null, asn: "AS999", organization: "Evil Hosting", hosting: null, status: "AVAILABLE" },
      ] }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.ok(result.confidence <= 1);
    assert.ok(result.confidence > 0);
  });

  it("never returns the selected email as its own related email", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { ips: ["198.51.100.1"] }) });
    const result = correlateEmail(selected, [selected]);
    assert.deepEqual(result.relatedEmailIds, []);
    assert.ok(!result.relatedEmailIds.includes("EMAIL-A"));
  });

  it("never duplicates a related email even when it matches via multiple signal types", () => {
    const selected = record("EMAIL-A", {
      iocs: iocs("EMAIL-A", { domains: ["evil.example"], urls: ["http://evil.example/a"], ips: ["198.51.100.1"] }),
    });
    const other = record("EMAIL-B", {
      iocs: iocs("EMAIL-B", { domains: ["evil.example"], urls: ["http://evil.example/a"], ips: ["198.51.100.1"] }),
    });

    const result = correlateEmail(selected, [selected, other]);
    assert.equal(result.relatedEmailIds.length, 1);
    assert.deepEqual(result.relatedEmailIds, ["EMAIL-B"]);
  });

  it("keeps reasons tied to actually shared evidence values", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { ips: ["198.51.100.1"] }) });
    const other = record("EMAIL-B", { iocs: iocs("EMAIL-B", { ips: ["198.51.100.1"] }) });

    const result = correlateEmail(selected, [selected, other]);
    assert.ok(result.reasons.some((r) => r.includes("198.51.100.1")));
  });

  it("never claims confirmed threat-actor attribution in generated wording", () => {
    const selected = record("EMAIL-A", { iocs: iocs("EMAIL-A", { ips: ["198.51.100.1"] }) });
    const other = record("EMAIL-B", { iocs: iocs("EMAIL-B", { ips: ["198.51.100.1"] }) });

    const result = correlateEmail(selected, [selected, other]);
    for (const reason of result.reasons) {
      assert.ok(!reason.toLowerCase().includes("confirmed threat actor"));
    }
  });
});

describe("correlateEmail — candidate generation avoids full pairwise comparison", () => {
  it("only surfaces genuinely overlapping emails out of a large unrelated pool", () => {
    const selected = record("EMAIL-SEL", {
      iocs: iocs("EMAIL-SEL", { ips: ["198.51.100.1"], domains: ["evil.example"] }),
    });
    const relatedOne = record("EMAIL-REL-1", {
      iocs: iocs("EMAIL-REL-1", { ips: ["198.51.100.1"], domains: ["evil.example"] }),
    });

    const noise: EmailRecord[] = [];
    for (let i = 0; i < 500; i++) {
      noise.push(
        record(`EMAIL-NOISE-${i}`, {
          iocs: iocs(`EMAIL-NOISE-${i}`, { domains: [`noise-${i}.example`], ips: [`203.0.113.${i % 250}`] }),
        })
      );
    }

    const start = Date.now();
    const result = correlateEmail(selected, [selected, relatedOne, ...noise]);
    const elapsedMs = Date.now() - start;

    assert.deepEqual(result.relatedEmailIds, ["EMAIL-REL-1"]);
    assert.ok(elapsedMs < 2000, `correlation took too long: ${elapsedMs}ms`);
  });
});
