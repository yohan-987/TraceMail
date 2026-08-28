import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-related-"));
process.env.EMAIL_DATA_DIR = dataDir;
process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();
const app = createApp();

function eml(fields: { from: string; to: string; subject: string; body: string }): Buffer {
  return Buffer.from(
    [
      `From: ${fields.from}`,
      `To: ${fields.to}`,
      `Subject: ${fields.subject}`,
      "",
      fields.body,
      "",
    ].join("\r\n"),
    "utf-8"
  );
}

async function scan(fields: { from: string; to: string; subject: string; body: string }, filename: string) {
  const res = await request(app).post("/api/v1/emails/scan").attach("file", eml(fields), filename);
  assert.equal(res.status, 201);
  return res.body.emailId as string;
}

describe("GET /emails/:emailId/related", { concurrency: false }, () => {
  it("returns 404 EMAIL_NOT_FOUND for a nonexistent emailId", async () => {
    const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST/related");
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
  });

  it("finds a related email sharing a phishing URL and domain, without requiring a caseId", async () => {
    const idA = await scan(
      {
        from: '"PayPal" <alert@paypa1-secure.com>',
        to: "victim1@example.org",
        subject: "Verify your account now",
        body: '<a href="http://paypa1-secure.com/verify">click</a>',
      },
      "a.eml"
    );
    const idB = await scan(
      {
        from: '"PayPal" <alert@paypa1-secure.com>',
        to: "victim2@example.org",
        subject: "Verify your account now",
        body: '<a href="http://paypa1-secure.com/verify">click</a>',
      },
      "b.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${idA}/related`);
    assert.equal(res.status, 200);
    assert.equal(res.body.emailId, idA);
    assert.ok(res.body.relatedEmailIds.includes(idB));
    assert.ok(!res.body.relatedEmailIds.includes(idA));
    assert.ok(res.body.confidence > 0 && res.body.confidence <= 1);
    assert.ok(res.body.campaignId);
    assert.ok(Array.isArray(res.body.sharedIndicators));
    assert.ok(Array.isArray(res.body.reasons));
    assert.ok(res.body.reasons.some((r: string) => r.includes("Likely Related Campaign")));

    // Symmetric: querying B should surface A too, with the same campaignId.
    const resB = await request(app).get(`/api/v1/emails/${idB}/related`);
    assert.ok(resB.body.relatedEmailIds.includes(idA));
    assert.equal(resB.body.campaignId, res.body.campaignId);
  });

  it("returns no related emails and a null campaignId for an isolated email", async () => {
    const idIsolated = await scan(
      {
        from: "newsletter@distinct-example.com",
        to: "subscriber@example.org",
        subject: "This week's totally unique digest",
        body: "Hello, nothing shared with anyone else here.",
      },
      "isolated.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${idIsolated}/related`);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.relatedEmailIds, []);
    assert.equal(res.body.confidence, 0);
    assert.equal(res.body.campaignId, null);
    assert.deepEqual(res.body.reasons, []);
  });

  it("never uses confirmed-attribution wording", async () => {
    const idA = await scan(
      {
        from: "x@shared-infra-example.com",
        to: "v1@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-infra-example.com/pay">pay</a>',
      },
      "c.eml"
    );
    await scan(
      {
        from: "y@shared-infra-example.com",
        to: "v2@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-infra-example.com/pay">pay</a>',
      },
      "d.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${idA}/related`);
    const joined = (res.body.reasons as string[]).join(" ").toLowerCase();
    assert.ok(!joined.includes("confirmed threat actor"));
  });
});
