import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-recommendations-"));
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

describe("GET /emails/:emailId — recommendations (Batch 5C)", { concurrency: false }, () => {
  it("attaches an array of recommendations to the stored-email response", async () => {
    const id = await scan(
      {
        from: '"PayPal" <alert@paypa1-secure-login.com>',
        to: "victim@example.org",
        subject: "Urgent: verify your account or it will be suspended",
        body: '<a href="http://paypa1-secure-login.com/verify">click here now</a>',
      },
      "phish.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${id}`);
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.recommendations));
    for (const rec of res.body.recommendations) {
      assert.ok(rec.action);
      assert.ok(rec.priority);
      assert.ok(rec.reason);
      assert.ok(Array.isArray(rec.supportingEvidence));
    }
  });

  it("finds REVIEW_RELATED_EMAILS once a second, evidence-sharing email is scanned", async () => {
    const idA = await scan(
      {
        from: "x@shared-campaign-example.com",
        to: "v1@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-campaign-example.com/pay">pay</a>',
      },
      "e1.eml"
    );
    await scan(
      {
        from: "x@shared-campaign-example.com",
        to: "v2@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-campaign-example.com/pay">pay</a>',
      },
      "e2.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${idA}`);
    assert.equal(res.status, 200);
    const actions = (res.body.recommendations as { action: string }[]).map((r) => r.action);
    assert.ok(actions.includes("REVIEW_RELATED_EMAILS"));
  });

  it("returns 404 for a nonexistent emailId without crashing on recommendation generation", async () => {
    const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST");
    assert.equal(res.status, 404);
  });
});
