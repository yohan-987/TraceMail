import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { buildInfrastructureGraph } from "../src/analyzers/infrastructureGraph";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";
import type {
  EmailRecord,
  GeoIpRecord,
  HeaderAnalysis,
  InfrastructureAssessment,
  InfrastructureGraph,
  IOCSet,
  ParsedEmail,
} from "../src/schemas/types";

function hop(fromIp: string, classification: HeaderAnalysis["receivedChain"][0]["fromIpClassification"]): HeaderAnalysis["receivedChain"][0] {
  return {
    hop: 1,
    fromHostname: null,
    fromIp,
    fromIpClassification: classification,
    byHostname: null,
    timestampRaw: null,
    timestampIso: null,
    rawHeader: `Received: from x ([${fromIp}])`,
  };
}

function parsedEmail(emailId: string, extras?: Partial<ParsedEmail>): ParsedEmail {
  return {
    emailId,
    subject: "Verify your account",
    from: [{ displayName: "PayPal", email: "alert@paypa1-secure-login.com", localPart: "alert", domain: "paypa1-secure-login.com" }],
    to: [{ displayName: null, email: "victim@example.org", localPart: "victim", domain: "example.org" }],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: null,
    headers: { normalized: {}, raw: [] },
    body: { text: "click", html: null },
    attachments: [],
    ...extras,
  };
}

function record(overrides: Partial<EmailRecord> & { emailId?: string } = {}): EmailRecord {
  const emailId = overrides.emailId ?? "EMAIL-GRAPH-001";
  const headerAnalysis: HeaderAnalysis = overrides.headerAnalysis ?? {
    emailId,
    anomalies: [],
    receivedChain: [hop("198.51.100.23", "PUBLIC")],
    status: "SUSPICIOUS",
  };
  const iocs: IOCSet = overrides.iocs ?? {
    emailId,
    ips: ["198.51.100.23"],
    domains: ["paypa1-secure-login.com", "evil.example"],
    urls: ["http://evil.example/login"],
    hashes: [],
    emails: ["alert@paypa1-secure-login.com"],
  };
  const geo: GeoIpRecord = {
    ip: "198.51.100.23",
    country: "US",
    region: "VA",
    city: "Ashburn",
    isp: "DigitalOcean",
    asn: "AS14061",
    organization: "DigitalOcean, LLC",
    hosting: "hosting",
    status: "AVAILABLE",
  };
  const infrastructure: InfrastructureAssessment = overrides.infrastructure ?? {
    emailId,
    candidateIp: "198.51.100.23",
    country: "US",
    region: "VA",
    city: "Ashburn",
    isp: "DigitalOcean",
    asn: "AS14061",
    confidence: 0.5,
    status: "AVAILABLE",
    ipIntelligence: [geo],
    domainIntelligence: [
      {
        domain: "evil.example",
        resolvedIps: ["203.0.113.10"],
        mxHosts: null,
        registrar: null,
        domainAgeDays: null,
        hostingOrganization: null,
        status: "AVAILABLE",
      },
    ],
    interpretation: "probable_infrastructure",
  };

  return {
    emailId,
    caseId: null,
    evidence: {
      filename: "phish.eml",
      sha256: "a".repeat(64),
      fileSizeBytes: 100,
      createdAt: "2026-08-28T00:00:00.000Z",
      storagePath: "data/emails/EMAIL-GRAPH-001/original.eml",
    },
    parsedEmail: overrides.parsedEmail === undefined ? parsedEmail(emailId) : overrides.parsedEmail,
    headerAnalysis,
    authentication: null,
    iocs,
    urlAnalysis: overrides.urlAnalysis === undefined
      ? {
          emailId,
          urls: [
            {
              url: "http://evil.example/login",
              hostname: "evil.example",
              domain: "evil.example",
              isHttps: false,
              urlLength: 24,
              subdomainLength: 0,
              pathLength: 6,
              queryLength: 0,
              hasIpHost: false,
              hasAtSymbol: false,
              hasEncodedCharacters: false,
              hasMultipleSubdomains: false,
              isShortened: false,
              riskNotes: [],
            },
          ],
        }
      : overrides.urlAnalysis,
    domainAnalysis: null,
    risk: null,
    aiAssessment: null,
    infrastructure,
    report: null,
    explanations: [],
    warnings: [],
    ...overrides,
    emailId,
  };
}

function nodesOf(graph: InfrastructureGraph, type: string) {
  return graph.nodes.filter((n) => n.type === type);
}

function edgesOf(graph: InfrastructureGraph, relationship: string) {
  return graph.edges.filter((e) => e.relationship === relationship);
}

describe("infrastructure graph builder", () => {
  it("creates evidence-backed nodes for email, addresses, domain, URL, public IP, ASN, org, geo", () => {
    const graph = buildInfrastructureGraph(record());
    assert.equal(nodesOf(graph, "EMAIL").length, 1);
    assert.ok(nodesOf(graph, "EMAIL_ADDRESS").some((n) => n.label === "alert@paypa1-secure-login.com"));
    assert.ok(nodesOf(graph, "EMAIL_ADDRESS").some((n) => n.label === "victim@example.org"));
    assert.ok(nodesOf(graph, "DOMAIN").some((n) => n.label === "evil.example"));
    assert.ok(nodesOf(graph, "URL").some((n) => n.label === "http://evil.example/login"));
    assert.ok(nodesOf(graph, "IP").some((n) => n.label === "198.51.100.23"));
    assert.ok(nodesOf(graph, "ASN").some((n) => n.label === "AS14061"));
    assert.ok(nodesOf(graph, "ORGANIZATION").length >= 1);
    assert.equal(nodesOf(graph, "GEOLOCATION").length, 1);
    const geo = nodesOf(graph, "GEOLOCATION")[0];
    assert.equal(geo.metadata?.country, "US");
    assert.equal(geo.metadata?.region, "VA");
    assert.equal(geo.metadata?.city, "Ashburn");
    assert.equal(geo.metadata?.confidence, 0.5);
    assert.equal(geo.metadata?.interpretation, "Infrastructure location ≠ attacker identity");
    assert.equal(geo.metadata?.latitude, undefined);
  });

  it("creates observed and intelligence-backed relationships", () => {
    const graph = buildInfrastructureGraph(record());
    const emailId = graph.nodes.find((n) => n.type === "EMAIL")!.id;
    const ipId = graph.nodes.find((n) => n.type === "IP" && n.label === "198.51.100.23")!.id;
    const urlId = graph.nodes.find((n) => n.type === "URL")!.id;
    const urlDomainId = graph.nodes.find((n) => n.type === "DOMAIN" && n.label === "evil.example")!.id;
    const asnId = graph.nodes.find((n) => n.type === "ASN")!.id;
    const geoId = graph.nodes.find((n) => n.type === "GEOLOCATION")!.id;
    const dnsIpId = graph.nodes.find((n) => n.type === "IP" && n.label === "203.0.113.10")!.id;

    const received = edgesOf(graph, "contains_received_ip");
    assert.equal(received.length, 1);
    assert.equal(received[0].source, emailId);
    assert.equal(received[0].target, ipId);
    assert.equal(received[0].provenance, "OBSERVED");
    assert.deepEqual(received[0].evidence, ["Received header"]);

    const containsUrl = edgesOf(graph, "contains_url");
    assert.equal(containsUrl[0].source, emailId);
    assert.equal(containsUrl[0].target, urlId);
    assert.equal(containsUrl[0].provenance, "OBSERVED");

    const usesDomain = edgesOf(graph, "uses_domain");
    assert.equal(usesDomain[0].source, urlId);
    assert.equal(usesDomain[0].target, urlDomainId);
    assert.equal(usesDomain[0].provenance, "DETERMINISTIC_ANALYSIS");

    assert.ok(edgesOf(graph, "has_asn").some((e) => e.source === ipId && e.target === asnId && e.provenance === "EXTERNAL_INTELLIGENCE"));
    assert.ok(edgesOf(graph, "hosted_by").some((e) => e.source === ipId && e.provenance === "EXTERNAL_INTELLIGENCE"));
    assert.ok(edgesOf(graph, "located_in").some((e) => e.source === ipId && e.target === geoId && e.provenance === "EXTERNAL_INTELLIGENCE"));

    const resolves = edgesOf(graph, "resolves_to");
    assert.equal(resolves.length, 1);
    assert.equal(resolves[0].source, urlDomainId);
    assert.equal(resolves[0].target, dnsIpId);
    assert.equal(resolves[0].provenance, "EXTERNAL_INTELLIGENCE");
    assert.deepEqual(resolves[0].evidence, ["DNS A-record"]);
  });

  it("does not attach GeoIP to private IPs", () => {
    const graph = buildInfrastructureGraph(
      record({
        headerAnalysis: {
          emailId: "EMAIL-GRAPH-001",
          anomalies: [],
          receivedChain: [hop("10.0.0.1", "PRIVATE")],
          status: "VERIFIED",
        },
        iocs: { emailId: "EMAIL-GRAPH-001", ips: ["10.0.0.1"], domains: [], urls: [], hashes: [], emails: [] },
        urlAnalysis: { emailId: "EMAIL-GRAPH-001", urls: [] },
        infrastructure: {
          emailId: "EMAIL-GRAPH-001",
          candidateIp: null,
          country: null,
          region: null,
          city: null,
          isp: null,
          asn: null,
          confidence: null,
          status: "NOT_APPLICABLE",
          ipIntelligence: [
            {
              ip: "10.0.0.1",
              country: "US",
              region: null,
              city: null,
              isp: null,
              asn: "AS1",
              organization: "Fake",
              hosting: null,
              status: "AVAILABLE",
            },
          ],
          domainIntelligence: [],
          interpretation: "probable_infrastructure",
        },
      })
    );
    const privateIp = graph.nodes.find((n) => n.label === "10.0.0.1");
    assert.ok(privateIp);
    assert.equal(nodesOf(graph, "GEOLOCATION").length, 0);
    assert.equal(nodesOf(graph, "ASN").length, 0);
    assert.equal(edgesOf(graph, "located_in").length, 0);
  });

  it("does not create an infrastructure IP node for invalid addresses", () => {
    const graph = buildInfrastructureGraph(
      record({
        headerAnalysis: {
          emailId: "EMAIL-GRAPH-001",
          anomalies: [],
          receivedChain: [hop("999.999.999.999", "INVALID")],
          status: "VERIFIED",
        },
        iocs: { emailId: "EMAIL-GRAPH-001", ips: ["not-an-ip", "999.999.999.999"], domains: [], urls: [], hashes: [], emails: [] },
        urlAnalysis: { emailId: "EMAIL-GRAPH-001", urls: [] },
        infrastructure: {
          emailId: "EMAIL-GRAPH-001",
          candidateIp: null,
          country: null,
          region: null,
          city: null,
          isp: null,
          asn: null,
          confidence: null,
          status: "NOT_APPLICABLE",
          ipIntelligence: [],
          domainIntelligence: [],
          interpretation: "probable_infrastructure",
        },
      })
    );
    assert.equal(nodesOf(graph, "IP").length, 0);
  });

  it("does not fabricate geolocation, ASN, or organization nodes", () => {
    const graph = buildInfrastructureGraph(
      record({
        infrastructure: {
          emailId: "EMAIL-GRAPH-001",
          candidateIp: "198.51.100.23",
          country: null,
          region: null,
          city: null,
          isp: null,
          asn: null,
          confidence: null,
          status: "UNAVAILABLE",
          ipIntelligence: [
            {
              ip: "198.51.100.23",
              country: null,
              region: null,
              city: null,
              isp: "UNKNOWN",
              asn: "N/A",
              organization: "UNAVAILABLE",
              hosting: null,
              status: "UNAVAILABLE",
            },
          ],
          domainIntelligence: [],
          interpretation: "probable_infrastructure",
        },
      })
    );
    assert.equal(nodesOf(graph, "GEOLOCATION").length, 0);
    assert.equal(nodesOf(graph, "ASN").length, 0);
    assert.equal(nodesOf(graph, "ORGANIZATION").length, 0);
  });

  it("does not fabricate DOMAIN → IP from co-located sender domain and received IP", () => {
    const graph = buildInfrastructureGraph(
      record({
        iocs: {
          emailId: "EMAIL-GRAPH-001",
          ips: ["198.51.100.23"],
          domains: ["paypa1-secure-login.com"],
          urls: [],
          hashes: [],
          emails: [],
        },
        urlAnalysis: { emailId: "EMAIL-GRAPH-001", urls: [] },
        infrastructure: {
          emailId: "EMAIL-GRAPH-001",
          candidateIp: "198.51.100.23",
          country: "US",
          region: null,
          city: null,
          isp: null,
          asn: "AS14061",
          confidence: 0.5,
          status: "AVAILABLE",
          ipIntelligence: [
            {
              ip: "198.51.100.23",
              country: "US",
              region: null,
              city: null,
              isp: null,
              asn: "AS14061",
              organization: null,
              hosting: null,
              status: "AVAILABLE",
            },
          ],
          domainIntelligence: [
            {
              domain: "paypa1-secure-login.com",
              resolvedIps: null,
              mxHosts: null,
              registrar: null,
              domainAgeDays: null,
              hostingOrganization: null,
              status: "UNAVAILABLE",
            },
          ],
          interpretation: "probable_infrastructure",
        },
      })
    );
    const domain = graph.nodes.find((n) => n.type === "DOMAIN" && n.label === "paypa1-secure-login.com");
    const ip = graph.nodes.find((n) => n.type === "IP" && n.label === "198.51.100.23");
    assert.ok(domain);
    assert.ok(ip);
    assert.equal(edgesOf(graph, "resolves_to").length, 0);
    assert.ok(!graph.edges.some((e) => e.source === domain.id && e.target === ip.id));
  });

  it("marks inferred relationships INFERRED and does not disguise them as OBSERVED", () => {
    const graph = buildInfrastructureGraph(record());
    for (const edge of graph.edges) {
      if (edge.relationship === "resolves_to") {
        assert.equal(edge.provenance, "EXTERNAL_INTELLIGENCE");
        assert.notEqual(edge.provenance, "OBSERVED");
        assert.notEqual(edge.provenance, "INFERRED");
      }
      if (edge.provenance === "INFERRED") {
        assert.equal(edge.provenance, "INFERRED");
      }
      if (edge.provenance === "OBSERVED") {
        assert.ok(
          ["contains_received_ip", "contains_ip", "contains_url", "contains_domain", "has_from_address", "has_to_address", "has_cc_address", "has_bcc_address", "has_reply_to_address", "has_return_path_address"].includes(
            edge.relationship
          )
        );
      }
    }
  });

  it("returns only the email node (and observed addresses) when infrastructure data is missing", () => {
    const graph = buildInfrastructureGraph(
      record({
        parsedEmail: parsedEmail("EMAIL-GRAPH-001", {
          from: [{ displayName: null, email: "a@example.com", localPart: "a", domain: "example.com" }],
          to: [],
        }),
        headerAnalysis: { emailId: "EMAIL-GRAPH-001", anomalies: [], receivedChain: [], status: "VERIFIED" },
        iocs: { emailId: "EMAIL-GRAPH-001", ips: [], domains: [], urls: [], hashes: [], emails: [] },
        urlAnalysis: { emailId: "EMAIL-GRAPH-001", urls: [] },
        infrastructure: {
          emailId: "EMAIL-GRAPH-001",
          candidateIp: null,
          country: null,
          region: null,
          city: null,
          isp: null,
          asn: null,
          confidence: null,
          status: "NOT_APPLICABLE",
          ipIntelligence: [],
          domainIntelligence: [],
          interpretation: "probable_infrastructure",
        },
      })
    );
    assert.equal(nodesOf(graph, "EMAIL").length, 1);
    assert.equal(nodesOf(graph, "EMAIL_ADDRESS").length, 1);
    assert.equal(nodesOf(graph, "IP").length, 0);
    assert.equal(nodesOf(graph, "URL").length, 0);
    assert.equal(nodesOf(graph, "GEOLOCATION").length, 0);
    assert.equal(nodesOf(graph, "ASN").length, 0);
  });
});

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-graph-"));
process.env.EMAIL_DATA_DIR = dataDir;
process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();
const app = createApp();

describe("GET /emails/:emailId/graph", { concurrency: false }, () => {
  it("returns 404 EMAIL_NOT_FOUND for a missing email", async () => {
    const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST/graph");
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
  });

  it("returns a derived graph for a scanned email without rewriting detail", async () => {
    const eml = Buffer.from(
      [
        'From: "PayPal Security" <alert@paypa1-secure-login.com>',
        "To: victim@example.org",
        "Subject: Urgent: verify your account immediately",
        "Received: from mail.paypa1-secure-login.com (mail.paypa1-secure-login.com [198.51.100.23]) by mx.example.org; Mon, 24 Aug 2026 10:00:00 +0000",
        "",
        '<p><a href="http://203.0.113.44/verify">Click here</a></p>',
        "",
      ].join("\r\n"),
      "utf-8"
    );
    const scan = await request(app).post("/api/v1/emails/scan").attach("file", eml, "graph.eml");
    assert.equal(scan.status, 201);
    const emailId = scan.body.emailId as string;

    const graphRes = await request(app).get(`/api/v1/emails/${emailId}/graph`);
    assert.equal(graphRes.status, 200);
    assert.equal(graphRes.body.emailId, emailId);
    assert.ok(Array.isArray(graphRes.body.graph.nodes));
    assert.ok(Array.isArray(graphRes.body.graph.edges));
    assert.ok(graphRes.body.graph.nodes.some((n: { type: string }) => n.type === "EMAIL"));
    assert.ok(graphRes.body.graph.nodes.some((n: { type: string }) => n.type === "URL"));
    assert.ok(graphRes.body.graph.nodes.some((n: { type: string }) => n.type === "DOMAIN"));
    assert.ok(graphRes.body.graph.nodes.some((n: { type: string; label: string }) => n.type === "IP" && n.label === "198.51.100.23"));
    assert.ok(graphRes.body.graph.edges.some((e: { relationship: string; provenance: string }) => e.relationship === "contains_received_ip" && e.provenance === "OBSERVED"));
    assert.ok(graphRes.body.graph.edges.some((e: { relationship: string }) => e.relationship === "contains_url"));
    assert.ok(graphRes.body.graph.edges.some((e: { relationship: string }) => e.relationship === "uses_domain" || e.relationship === "uses_ip_host"));
    assert.ok(!graphRes.body.graph.edges.some((e: { relationship: string }) => e.relationship === "resolves_to"));

    const detail = await request(app).get(`/api/v1/emails/${emailId}`);
    assert.equal(detail.status, 200);
    assert.equal(detail.body.emailId, emailId);
    assert.ok(detail.body.parsedEmail);
    assert.ok(detail.body.headerAnalysis);
    assert.ok(detail.body.iocs);
    assert.equal(detail.body.graph, undefined);
  });

  it("returns a valid sparse graph when the email has little infrastructure", async () => {
    const eml = Buffer.from(
      ["From: newsletter@example.com", "To: subscriber@example.org", "Subject: Weekly digest", "", "Hello.", ""].join("\r\n"),
      "utf-8"
    );
    const scan = await request(app).post("/api/v1/emails/scan").attach("file", eml, "sparse.eml");
    const res = await request(app).get(`/api/v1/emails/${scan.body.emailId}/graph`);
    assert.equal(res.status, 200);
    assert.ok(res.body.graph.nodes.some((n: { type: string }) => n.type === "EMAIL"));
    assert.equal(res.body.graph.nodes.filter((n: { type: string }) => n.type === "IP").length, 0);
    assert.equal(res.body.graph.nodes.filter((n: { type: string }) => n.type === "GEOLOCATION").length, 0);
    assert.equal(res.body.graph.nodes.filter((n: { type: string }) => n.type === "URL").length, 0);
  });
});
