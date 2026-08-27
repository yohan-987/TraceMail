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

test("scan endpoint returns complete header/authentication evidence for a realistic impersonation email", async () => {
  const eml = Buffer.from(
    [
      'From: "CEO" <ceo@company-example.com>',
      "Reply-To: finance-request@gmail.com",
      "To: victim@company-example.com",
      "Subject: Urgent wire transfer",
      "Message-ID: <weird-id@totally-unrelated.net>",
      "Received: from mail.company-example.com (mail.company-example.com [203.0.113.9]) by mx.company-example.com; Mon, 24 Aug 2026 09:00:00 +0000",
      "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=company-example.com; dkim=fail header.i=@company-example.com; dmarc=fail (p=REJECT) header.from=company-example.com",
      "",
      "Please wire the funds immediately, this is time sensitive.",
      "",
    ].join("\r\n"),
    "utf-8"
  );

  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "urgent.eml");
  assert.equal(scanRes.status, 201);
  const emailId = scanRes.body.emailId;

  const getRes = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(getRes.status, 200);

  const { headerAnalysis, authentication } = getRes.body;

  // Authentication evidence present and correctly parsed.
  assert.equal(authentication.spf.result, "fail");
  assert.equal(authentication.dkim.result, "fail");
  assert.equal(authentication.dmarc.result, "fail");
  assert.equal(authentication.dmarc.policy, "reject");

  // Header anomalies present: reply-to mismatch, message-id mismatch, auth failures.
  const types = headerAnalysis.anomalies.map((a: { type: string }) => a.type);
  assert.ok(types.includes("reply_to_mismatch"));
  assert.ok(types.includes("message_id_domain_mismatch"));
  assert.ok(types.includes("spf_fail"));
  assert.ok(types.includes("dkim_fail"));
  assert.ok(types.includes("dmarc_fail"));

  // Every anomaly has the required fields per the Batch 2 contract.
  for (const anomaly of headerAnalysis.anomalies) {
    assert.equal(typeof anomaly.type, "string");
    assert.ok(["low", "medium", "high"].includes(anomaly.severity));
    assert.equal(typeof anomaly.weight, "number");
    assert.equal(typeof anomaly.evidence, "object");
  }

  // Received chain reconstructed with candidate source infrastructure.
  assert.equal(headerAnalysis.receivedChain.length, 1);
  assert.equal(headerAnalysis.receivedChain[0].fromIp, "203.0.113.9");
  assert.equal(headerAnalysis.receivedChain[0].fromIpClassification, "PUBLIC");

  assert.equal(headerAnalysis.status, "SUSPICIOUS");
});

test("scan endpoint returns VERIFIED status for a clean, consistent legitimate email", async () => {
  const eml = Buffer.from(
    [
      "From: newsletter@example.com",
      "To: subscriber@example.org",
      "Subject: Weekly newsletter",
      "Message-ID: <news-2026-08-24@example.com>",
      "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass",
      "",
      "Here is this week's newsletter.",
      "",
    ].join("\r\n"),
    "utf-8"
  );

  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", eml, "newsletter.eml");
  const emailId = scanRes.body.emailId;

  const getRes = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(getRes.body.headerAnalysis.anomalies.length, 0);
  assert.equal(getRes.body.headerAnalysis.status, "VERIFIED");
  assert.equal(getRes.body.authentication.spf.result, "pass");
});
