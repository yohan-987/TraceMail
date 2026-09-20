import { test } from "node:test";
import assert from "node:assert/strict";
import { buildInfrastructureGraph } from "../src/analyzers/infrastructureGraph";
import type { EmailRecord } from "../src/schemas/types";

// Prompt 10 — graph "suspicious-only filtering". Confirms the
// `suspicious` flag on graph nodes is derived from ALREADY-COMPUTED
// analysis (domainAnalyzer.ts's lookalikeOf, urlAnalyzer.ts's
// hasIpHost) rather than any new scoring, and — deliberately — that
// weak structural URL features (percent-encoding, multiple
// subdomains) do NOT set it, consistent with Findings 1-3's weak/strong
// evidence model elsewhere in this project.

function baseRecord(overrides: Partial<EmailRecord> = {}): EmailRecord {
  return {
    emailId: "graph-test",
    parsedEmail: {
      emailId: "graph-test",
      subject: "s",
      from: [],
      to: [],
      cc: [],
      bcc: [],
      replyTo: [],
      returnPath: [],
      date: null,
      messageId: null,
      headers: { normalized: {}, raw: [] },
      body: { text: null, html: null },
      attachments: [],
    },
    headerAnalysis: null,
    authentication: null,
    forwarding: null,
    iocs: null,
    urlAnalysis: null,
    domainAnalysis: null,
    mlAssessment: null,
    aiAssessment: null,
    infrastructure: null,
    relationshipGraph: null,
    correlation: null,
    risk: null,
    ...overrides,
  } as unknown as EmailRecord;
}

test("a domain flagged lookalikeOf by domainAnalyzer.ts is marked suspicious on its graph node", () => {
  const record = baseRecord({
    iocs: { emailId: "t", ips: [], domains: ["paypa1.com"], urls: [], canonicalUrlIndicators: [], hashes: [], emails: [] } as any,
    domainAnalysis: {
      emailId: "t",
      domains: [{ domain: "paypa1.com", lookalikeOf: "paypal.com", similarityScore: 0.9 }],
    } as any,
  });

  const graph = buildInfrastructureGraph(record);
  const domainNode = graph.nodes.find((n) => n.type === "DOMAIN" && n.label === "paypa1.com");
  assert.ok(domainNode);
  assert.equal(domainNode!.suspicious, true);
});

test("an ordinary domain with no lookalike flag is NOT marked suspicious", () => {
  const record = baseRecord({
    iocs: { emailId: "t", ips: [], domains: ["brand-example.com"], urls: [], canonicalUrlIndicators: [], hashes: [], emails: [] } as any,
    domainAnalysis: { emailId: "t", domains: [{ domain: "brand-example.com", lookalikeOf: null, similarityScore: null }] } as any,
  });

  const graph = buildInfrastructureGraph(record);
  const domainNode = graph.nodes.find((n) => n.type === "DOMAIN" && n.label === "brand-example.com");
  assert.ok(domainNode);
  assert.equal(domainNode!.suspicious, undefined);
});

test("a URL with a raw IP host (STRONG signal) is marked suspicious, and so is the resulting IP node", () => {
  const record = baseRecord({
    iocs: { emailId: "t", ips: [], domains: [], urls: ["http://192.0.2.10/login"], canonicalUrlIndicators: [], hashes: [], emails: [] } as any,
    urlAnalysis: {
      emailId: "t",
      urls: [
        {
          url: "http://192.0.2.10/login",
          hostname: "192.0.2.10",
          domain: "192.0.2.10",
          hasIpHost: true,
          hasAtSymbol: false,
          hasEncodedCharacters: false,
          hasMultipleSubdomains: false,
          isShortened: false,
        },
      ],
    } as any,
  });

  const graph = buildInfrastructureGraph(record);
  const urlNode = graph.nodes.find((n) => n.type === "URL");
  const ipNode = graph.nodes.find((n) => n.type === "IP");
  assert.equal(urlNode?.suspicious, true);
  assert.equal(ipNode?.suspicious, true);
});

test("a URL with only WEAK structural features (percent-encoding + multiple subdomains, no IP host) is NOT marked suspicious", () => {
  const record = baseRecord({
    iocs: {
      emailId: "t",
      ips: [],
      domains: [],
      urls: ["https://click.mail.brand.example/redirect?x=abc%20123"],
      canonicalUrlIndicators: [],
      hashes: [],
      emails: [],
    } as any,
    urlAnalysis: {
      emailId: "t",
      urls: [
        {
          url: "https://click.mail.brand.example/redirect?x=abc%20123",
          hostname: "click.mail.brand.example",
          domain: "brand.example",
          hasIpHost: false,
          hasAtSymbol: false,
          hasEncodedCharacters: true,
          hasMultipleSubdomains: true,
          isShortened: false,
        },
      ],
    } as any,
  });

  const graph = buildInfrastructureGraph(record);
  const urlNode = graph.nodes.find((n) => n.type === "URL");
  assert.equal(
    urlNode?.suspicious,
    undefined,
    "percent-encoding + multiple subdomains are WEAK signals and must not light up the graph filter, consistent with Findings 1-3"
  );
});
