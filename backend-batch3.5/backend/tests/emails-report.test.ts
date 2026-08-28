import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-report-"));
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

async function scan(fields: { from: string; to: string; subject: string; body: string }, filename: string, caseId?: string) {
  const req = request(app).post("/api/v1/emails/scan").attach("file", eml(fields), filename);
  const res = caseId ? await req.field("caseId", caseId) : await req;
  assert.equal(res.status, 201);
  return res.body.emailId as string;
}

describe("GET /emails/:emailId/report", { concurrency: false }, () => {
  it("returns 404 EMAIL_NOT_FOUND (preserving the existing error format) for a nonexistent emailId", async () => {
    const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST/report");
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
    assert.ok(res.body.error.message);
  });

  it("returns a full structured report for a scanned phishing email, including caseId, SHA-256, and limitations", async () => {
    const id = await scan(
      {
        from: '"PayPal" <alert@paypa1-secure-login.com>',
        to: "victim@example.org",
        subject: "Urgent: verify your account or it will be suspended",
        body: '<a href="http://paypa1-secure-login.com/verify">click here now</a>',
      },
      "phish.eml",
      "CASE-42"
    );

    const res = await request(app).get(`/api/v1/emails/${id}/report`);
    assert.equal(res.status, 200);
    assert.equal(res.body.emailId, id);
    assert.equal(res.body.caseInformation.caseId, "CASE-42");
    assert.equal(res.body.evidenceIntegrity.sha256.length, 64);
    assert.ok(res.body.evidenceIntegrity.collectedAt);
    assert.ok(Array.isArray(res.body.limitations));
    assert.ok(
      res.body.limitations.includes(
        "Geolocation represents probable network infrastructure and does not establish attacker identity or physical location."
      )
    );
    assert.ok(
      res.body.limitations.includes(
        "Threat scores are analytical risk assessments and are not legal conclusions."
      )
    );
    assert.ok(Array.isArray(res.body.whyFlagged));
    assert.ok(Array.isArray(res.body.recommendedActions));
    assert.ok(res.body.threatAssessment);
    assert.ok(res.body.relatedCampaign);
  });

  it("includes related-campaign evidence in the report once a second, evidence-sharing email is scanned", async () => {
    const idA = await scan(
      {
        from: "x@shared-report-example.com",
        to: "v1@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-report-example.com/pay">pay</a>',
      },
      "r1.eml"
    );
    await scan(
      {
        from: "x@shared-report-example.com",
        to: "v2@example.org",
        subject: "Invoice attached",
        body: '<a href="http://shared-report-example.com/pay">pay</a>',
      },
      "r2.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${idA}/report`);
    assert.equal(res.status, 200);
    assert.equal(res.body.relatedCampaign.available, true);
    assert.ok(res.body.relatedCampaign.relatedEmailIds.length > 0);
  });

  it("returns a report with no caseId for an email scanned without one", async () => {
    const id = await scan(
      {
        from: "newsletter@distinct-report-example.com",
        to: "subscriber@example.org",
        subject: "Weekly digest",
        body: "Nothing shared with anyone else here.",
      },
      "no-case.eml"
    );

    const res = await request(app).get(`/api/v1/emails/${id}/report`);
    assert.equal(res.status, 200);
    assert.equal(res.body.caseInformation.caseId, null);
  });

  it("response is plain JSON, not a PDF binary", async () => {
    const id = await scan(
      {
        from: "sender@example.com",
        to: "recipient@example.com",
        subject: "Hello",
        body: "Just a normal email.",
      },
      "plain.eml"
    );
    const res = await request(app).get(`/api/v1/emails/${id}/report`);
    assert.equal(res.status, 200);
    assert.match(res.headers["content-type"] ?? "", /json/);
  });
});
