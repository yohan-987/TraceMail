import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { createHash } from "crypto";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();

const app = createApp();

function sampleEml(): Buffer {
  return Buffer.from(
    [
      "From: sender@example.com",
      "To: recipient@example.com",
      "Subject: Test scan",
      "",
      "This is a test body.",
      "",
    ].join("\r\n"),
    "utf-8"
  );
}

test("POST /emails/scan accepts a valid .eml and returns the expected shape", async () => {
  const res = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", sampleEml(), "sample.eml");

  assert.equal(res.status, 201);
  assert.match(res.body.emailId, /^EMAIL-/);
  assert.equal(res.body.caseId, null);
  assert.equal(res.body.filename, "sample.eml");
  assert.equal(res.body.status, "accepted");
  assert.equal(typeof res.body.sha256, "string");
  assert.equal(res.body.sha256.length, 64);
  assert.ok(Array.isArray(res.body.warnings));
});

test("sha256 in the response matches the exact uploaded bytes", async () => {
  const buf = sampleEml();
  const expected = createHash("sha256").update(buf).digest("hex");

  const res = await request(app).post("/api/v1/emails/scan").attach("file", buf, "sample.eml");

  assert.equal(res.body.sha256, expected);
});

test("POST /emails/scan rejects an empty file", async () => {
  const res = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", Buffer.alloc(0), "empty.eml");

  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "EMPTY_FILE");
});

test("POST /emails/scan rejects a missing file field", async () => {
  const res = await request(app).post("/api/v1/emails/scan");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "MISSING_FILE");
});

test("POST /emails/scan rejects a non-.eml extension", async () => {
  const res = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", Buffer.from("not an email"), "notes.txt");

  assert.equal(res.status, 400);
});

// NOTE: an endpoint-level test attaching a filename like "../../etc/passwd.eml"
// does NOT reliably exercise assertSafeFilename() here — supertest's
// underlying multipart client sanitizes to the basename ("passwd.eml")
// before the request ever reaches our server, the same way a browser
// file input would. That's a real, useful client-side safety property,
// but it means the traversal vector has to be tested at the unit level
// instead, against the validator directly. See tests/filename.test.ts.
test("POST /emails/scan rejects a filename with control characters", async () => {
  const res = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", sampleEml(), "bad\x00name.eml");

  assert.equal(res.status, 400);
});

test("two scans of the same content produce different, unique emailIds", async () => {
  const buf = sampleEml();
  const res1 = await request(app).post("/api/v1/emails/scan").attach("file", buf, "a.eml");
  const res2 = await request(app).post("/api/v1/emails/scan").attach("file", buf, "a.eml");

  assert.notEqual(res1.body.emailId, res2.body.emailId);
});

test("caseId is optional: omitted -> null, provided -> preserved", async () => {
  const withoutCase = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", sampleEml(), "no-case.eml");
  assert.equal(withoutCase.body.caseId, null);

  const withCase = await request(app)
    .post("/api/v1/emails/scan")
    .field("caseId", "CASE-20260824-ABC123")
    .attach("file", sampleEml(), "with-case.eml");
  assert.equal(withCase.body.caseId, "CASE-20260824-ABC123");
});

test("scanned email is independently retrievable by emailId via GET /emails/:emailId", async () => {
  const scanRes = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", sampleEml(), "retrievable.eml");
  const emailId = scanRes.body.emailId;

  const getRes = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(getRes.status, 200);
  assert.equal(getRes.body.emailId, emailId);
  assert.equal(getRes.body.parsedEmail.subject, "Test scan");
  assert.equal(getRes.body.parsedEmail.from[0].email, "sender@example.com");
  // Batch 2 populates header/auth analysis; Batch 3 populates
  // iocs/urlAnalysis/domainAnalysis/risk/explanations. Batch 4 slots
  // are present with explicit availability when providers are off.
  assert.notEqual(getRes.body.headerAnalysis, null);
  assert.notEqual(getRes.body.authentication, null);
  assert.notEqual(getRes.body.iocs, null);
  assert.notEqual(getRes.body.risk, null);
  assert.equal(getRes.body.aiAssessment.status, "UNAVAILABLE");
  assert.ok(["UNAVAILABLE", "NOT_APPLICABLE", "ERROR", "INCONCLUSIVE"].includes(getRes.body.infrastructure.status));
  assert.equal(getRes.body.mlAssessment.status, "UNAVAILABLE");
});

test("GET /emails/:emailId returns 404 with structured error for unknown id", async () => {
  const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST");
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
});

test("GET /emails lists scanned emails as lightweight summaries", async () => {
  await request(app).post("/api/v1/emails/scan").attach("file", sampleEml(), "for-list.eml");

  const res = await request(app).get("/api/v1/emails");
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.body.items));
  assert.ok(res.body.items.length > 0);
  assert.equal(typeof res.body.pagination.total, "number");
  assert.equal(res.body.pagination.limit, 50);
  assert.equal(res.body.pagination.offset, 0);
  const row = res.body.items[0];
  assert.ok("emailId" in row);
  assert.ok("subject" in row);
  // Must be a lightweight row — no full body/headers in the list response.
  assert.ok(!("headers" in row));
  assert.ok(!("body" in row));
});

test("GET /emails/:emailId/report is 404 before a report has been generated", async () => {
  const scanRes = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", sampleEml(), "no-report-yet.eml");

  const res = await request(app).get(`/api/v1/emails/${scanRes.body.emailId}/report`);
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, "REPORT_NOT_AVAILABLE");
});
