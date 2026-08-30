import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-security-"));
process.env.EMAIL_DATA_DIR = dataDir;
process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();
const app = createApp();

function sampleEml(): Buffer {
  return Buffer.from(
    ["From: sender@example.com", "To: recipient@example.com", "Subject: Test scan", "", "Body.", ""].join(
      "\r\n"
    ),
    "utf-8"
  );
}

// --- emailId route param validation ---------------------------------

test("GET /emails/:emailId rejects a traversal-style emailId with a clean 400, not a filesystem error", async () => {
  const res = await request(app).get("/api/v1/emails/..%2F..%2F..%2Fetc%2Fpasswd");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_EMAIL_ID");
});

test("GET /emails/:emailId rejects an emailId containing path separators", async () => {
  const res = await request(app).get("/api/v1/emails/EMAIL-123%2F..%2Fsecret");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_EMAIL_ID");
});

test("GET /emails/:emailId rejects a null-byte emailId", async () => {
  const res = await request(app).get("/api/v1/emails/EMAIL-123%00");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_EMAIL_ID");
});

test("GET /emails/:emailId/report also validates emailId format (shared router.param)", async () => {
  const res = await request(app).get("/api/v1/emails/..%2F..%2Fetc/report");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_EMAIL_ID");
});

test("GET /emails/:emailId/related also validates emailId format (shared router.param)", async () => {
  const res = await request(app).get("/api/v1/emails/%2e%2e%2f/related");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_EMAIL_ID");
});

test("a well-formed but nonexistent emailId still cleanly 404s (validation doesn't block real lookups)", async () => {
  const res = await request(app).get("/api/v1/emails/EMAIL-20260101-ABCDEF");
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
});

// --- malformed stored JSON --------------------------------------------

test("a corrupted stored record returns a controlled 500, not a raw JSON.parse error", async () => {
  const scanRes = await request(app).post("/api/v1/emails/scan").attach("file", sampleEml(), "corrupt.eml");
  assert.equal(scanRes.status, 201);
  const emailId = scanRes.body.emailId as string;

  const parsedJsonPath = path.join(dataDir, emailId, "parsed.json");
  fs.writeFileSync(parsedJsonPath, "{ this is not valid json ");

  const res = await request(app).get(`/api/v1/emails/${emailId}`);
  assert.equal(res.status, 500);
  assert.equal(res.body.error.code, "RECORD_UNREADABLE");
  // Must never leak the raw parser error or any filesystem path.
  const serialized = JSON.stringify(res.body);
  assert.ok(!serialized.includes(dataDir));
  assert.ok(!serialized.toLowerCase().includes("unexpected token"));
});

// --- upload security ---------------------------------------------------

test("non-.eml upload is rejected through the controlled ApiError path (INVALID_FILE_TYPE), not a raw Error", async () => {
  const res = await request(app).post("/api/v1/emails/scan").attach("file", Buffer.from("hi"), "notes.txt");
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "INVALID_FILE_TYPE");
});

// --- generic error handler hardening ------------------------------------

test("responses never include Express's X-Powered-By header", async () => {
  const res = await request(app).get("/api/v1/health");
  assert.equal(res.headers["x-powered-by"], undefined);
});

test("responses include baseline safe headers", async () => {
  const res = await request(app).get("/api/v1/health");
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["x-frame-options"], "DENY");
});

test("no response body ever contains a stack trace", async () => {
  const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST-000000");
  const serialized = JSON.stringify(res.body);
  assert.ok(!serialized.includes("at ")); // stack frames always contain " at "
  assert.ok(!serialized.toLowerCase().includes(".ts:"));
  assert.ok(!serialized.toLowerCase().includes(".js:"));
});
