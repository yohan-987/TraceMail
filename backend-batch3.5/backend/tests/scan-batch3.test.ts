import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();

const app = createApp();

test("full pipeline: a realistic phishing email produces IOCs, URL/domain analysis, risk score, and explanations via the real API", async () => {
  const eml = Buffer.from(
    [
      'From: "PayPal Security" <alert@paypa1-secure-login.com>',
      "Reply-To: support-team@gmail.com",
      "To: victim@example.org",
      "Subject: Urgent: verify your account immediately",
      "Message-ID: <weird@totally-unrelated.net>",
      "Received: from mail.paypa1-secure-login.com (mail.paypa1-secure-login.com [198.51.100.23]) by mx.example.org; Mon, 24 Aug 2026 10:00:00 +0000",
      "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail (p=QUARANTINE)",
      "Content-Type: text/html",
      "",
      '<p>Your account has been suspended. <a href="http://203.0.113.44/verify">Click here</a> to verify your account immediately, or wire the funds to avoid suspension.</p>',
      "",
    ].join("\r\n"),
    "utf-8"
  );

  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "phish.eml");
  assert.equal(scanRes.status, 201);
  const emailId = scanRes.body.emailId;

  const getRes = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(getRes.status, 200);
  const record = getRes.body;

  // IOCs extracted.
  assert.ok(record.iocs.urls.includes("http://203.0.113.44/verify"));
  assert.ok(record.iocs.ips.includes("203.0.113.44") || record.iocs.ips.includes("198.51.100.23"));
  assert.ok(record.iocs.domains.includes("paypa1-secure-login.com"));

  // URL analysis: raw IP host flagged.
  const urlEntry = record.urlAnalysis.urls.find((u: { url: string }) => u.url === "http://203.0.113.44/verify");
  assert.ok(urlEntry);
  assert.equal(urlEntry.hasIpHost, true);

  // Domain analysis: look-alike of paypal.com flagged.
  const domainEntry = record.domainAnalysis.domains.find(
    (d: { domain: string }) => d.domain === "paypa1-secure-login.com"
  );
  assert.ok(domainEntry);
  assert.equal(domainEntry.lookalikeOf, "paypal.com");

  // Risk assessment present and complete.
  assert.equal(typeof record.risk.score, "number");
  assert.ok(["low", "moderate", "high", "critical"].includes(record.risk.level));
  assert.equal(typeof record.risk.classification, "string");
  assert.equal(typeof record.risk.confidence, "number");
  assert.ok(record.risk.score > 50); // this sample should read as clearly risky

  // Category results present for all five categories, each with a
  // status and an evidence array; infrastructure is UNAVAILABLE (score
  // null) since Batch 4 hasn't landed, all others are AVAILABLE here.
  for (const cat of ["technical", "identity", "urlDomain", "content", "infrastructure"] as const) {
    const result = record.risk.categoryScores[cat];
    assert.ok(["AVAILABLE", "NOT_APPLICABLE", "UNAVAILABLE", "ERROR", "INCONCLUSIVE"].includes(result.status));
    assert.ok(Array.isArray(result.evidence));
    if (result.status === "AVAILABLE") {
      assert.equal(typeof result.score, "number");
    } else {
      assert.equal(result.score, null);
    }
  }
  assert.equal(record.risk.categoryScores.infrastructure.status, "UNAVAILABLE");
  assert.equal(typeof record.risk.evidenceCoverage, "number");

  // Explanations: every evidence item has the required contract fields.
  assert.ok(Array.isArray(record.explanations));
  assert.ok(record.explanations.length > 0);
  for (const item of record.explanations) {
    assert.equal(typeof item.type, "string");
    assert.ok(["low", "medium", "high"].includes(item.severity));
    assert.equal(typeof item.weight, "number");
    assert.equal(typeof item.message, "string");
    assert.equal(typeof item.evidence, "object");
    assert.ok(["technical", "identity", "urlDomain", "content", "infrastructure"].includes(item.category));
  }

  // Specific expected evidence types present.
  const types = record.explanations.map((e: { type: string }) => e.type);
  assert.ok(types.includes("spf_fail"));
  assert.ok(types.includes("dmarc_fail"));
  assert.ok(types.includes("possible_lookalike_domain"));
  assert.ok(types.includes("raw_ip_host"));
});

test("full pipeline: a clean legitimate email produces a low risk score with no explanations", async () => {
  const eml = Buffer.from(
    [
      "From: newsletter@example.com",
      "To: subscriber@example.org",
      "Subject: Weekly digest",
      "Message-ID: <digest-2026-08-24@example.com>",
      "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass",
      "",
      "Here is your weekly digest of company news and updates.",
      "",
    ].join("\r\n"),
    "utf-8"
  );

  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "clean.eml");
  const emailId = scanRes.body.emailId;
  const getRes = await request(app).get(`/api/v1/emails/${emailId}`);

  assert.equal(getRes.body.risk.level, "low");
  assert.equal(getRes.body.risk.classification, "legitimate");
  assert.equal(getRes.body.explanations.length, 0);
});

test("emailId is sufficient to retrieve the complete analysis — no caseId required", async () => {
  const eml = Buffer.from(
    ["From: a@example.com", "To: b@example.com", "Subject: hi", "", "hello", ""].join("\r\n"),
    "utf-8"
  );
  // Explicitly no caseId field sent.
  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "no-case.eml");
  assert.equal(scanRes.body.caseId, null);

  const getRes = await request(app).get(`/api/v1/emails/${scanRes.body.emailId}`);
  assert.equal(getRes.status, 200);
  assert.notEqual(getRes.body.risk, null);
});
