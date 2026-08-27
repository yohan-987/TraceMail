import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import type { GeoIpProvider } from "../src/services/geoipClient";
import type { DnsProvider } from "../src/services/dnsClient";
import type { LlmProvider } from "../src/services/llmClient";
import { assessMl, resetMlModelCache } from "../src/analyzers/mlClassifier";
import { assessAi } from "../src/analyzers/aiAssessment";
import { analyzeInfrastructure } from "../src/analyzers/infrastructure";
import { analyzeHeaders } from "../src/analyzers/headerForensics";
import { extractIOCs } from "../src/analyzers/iocExtractor";
import { analyzeUrls } from "../src/analyzers/urlAnalyzer";
import { parseEmlBuffer } from "../src/analyzers/emailParser";
import { computeRisk } from "../src/analyzers/riskEngine";

process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();

const app = createApp();

test("GET /emails/:emailId returns stored Batch 4 slots without requiring a second scan", async () => {
  const eml = Buffer.from(
    ["From: a@example.com", "To: b@example.com", "Subject: stored", "", "hello", ""].join("\r\n"),
    "utf-8"
  );
  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "stored.eml");
  const emailId = scanRes.body.emailId;
  const first = await request(app).get(`/api/v1/emails/${emailId}`);
  const second = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(first.status, 200);
  assert.equal(second.body.mlAssessment.status, first.body.mlAssessment.status);
  assert.equal(second.body.aiAssessment.status, first.body.aiAssessment.status);
  assert.equal(second.body.infrastructure.status, first.body.infrastructure.status);
  assert.equal(second.body.infrastructure.interpretation, "probable_infrastructure");
});

test("mocked GeoIP + DNS + ML + LLM fuse into stored analysis for an emailId", async () => {
  const raw = Buffer.from(
    [
      'From: "PayPal Security" <alert@paypa1-secure-login.com>',
      "To: victim@example.org",
      "Subject: Urgent: verify your account immediately",
      "Received: from mail.example.net (mail.example.net [198.51.100.23]) by mx.example.org; Mon, 24 Aug 2026 10:00:00 +0000",
      "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail",
      "",
      "Verify your account at http://203.0.113.44/login",
      "",
    ].join("\r\n"),
    "utf-8"
  );
  const { parsed } = await parseEmlBuffer("EMAIL-BATCH4", raw);
  const { headerAnalysis, authentication } = analyzeHeaders(parsed);
  const iocs = extractIOCs(parsed, headerAnalysis);
  const { urlAnalysis, evidence: urlEvidence } = analyzeUrls(parsed.emailId, iocs.urls);

  const { mlAssessment, evidence: mlEvidence } = assessMl({
    emailId: parsed.emailId,
    input: {
      subject: parsed.subject ?? "",
      body: parsed.body.text ?? "",
      urlCount: iocs.urls.length,
      urgency: 1,
      credentialRequest: 1,
      financialRequest: 0,
    },
    predictor: { predict: () => ({ probability: 0.94 }) },
  });

  const geoIp: GeoIpProvider = {
    async lookup(ip) {
      return {
        ip,
        country: "US",
        region: "VA",
        city: null,
        isp: "DigitalOcean",
        asn: "AS14061",
        organization: "DigitalOcean",
        hosting: null,
        status: "AVAILABLE",
      };
    },
  };
  const dns: DnsProvider = {
    async lookup(domain) {
      return { domain, resolvedIps: ["198.51.100.10"], mxHosts: ["mx.example.net"], status: "AVAILABLE" };
    },
  };
  const llm: LlmProvider = {
    async complete() {
      return JSON.stringify({
        phishingIntent: 0.9,
        credentialHarvesting: 0.8,
        financialFraud: 0.1,
        impersonation: 0.85,
        socialEngineering: 0.7,
        attackType: "phishing",
        summary: "Credential phishing using a look-alike brand.",
        recommendedActions: ["Do not open the link"],
      });
    },
  };

  const infra = await analyzeInfrastructure({
    emailId: parsed.emailId,
    headerAnalysis,
    iocs,
    geoIp,
    dns,
  });
  const ai = await assessAi({
    emailId: parsed.emailId,
    parsed,
    headerAnalysis,
    authentication,
    urlAnalysis,
    mlAssessment,
    provider: llm,
  });

  const explanations = [...headerAnalysis.anomalies, ...urlEvidence, ...mlEvidence, ...ai.evidence, ...infra.evidence];
  const risk = computeRisk(parsed.emailId, explanations, {
    headerDataAvailable: true,
    urlDomainApplicable: true,
    infrastructureAvailable: true,
    infrastructureStatus: infra.infrastructure.status,
  });

  assert.equal(mlAssessment.status, "AVAILABLE");
  assert.equal(ai.aiAssessment.status, "AVAILABLE");
  assert.equal(infra.infrastructure.status, "AVAILABLE");
  assert.equal(infra.infrastructure.ipIntelligence[0].isp, "DigitalOcean");
  assert.ok(infra.evidence.some((e) => e.type === "cloud_vps_indicator"));
  assert.ok(infra.evidence.some((e) => e.provenance === "INFERRED" || e.provenance === "OBSERVED"));
  assert.equal(risk.categoryScores?.infrastructure.status, "AVAILABLE");
  assert.ok((risk.score ?? 0) > 0);
  assert.equal(risk.evidenceCoverage, 1);
  assert.ok(risk.score !== null && risk.score <= 100);
});
