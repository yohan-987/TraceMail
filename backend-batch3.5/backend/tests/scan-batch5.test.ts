import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { createApp } from "../src/app";
import { resetMlModelCache } from "../src/analyzers/mlClassifier";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sih-batch5-"));
process.env.EMAIL_DATA_DIR = dataDir;
process.env.DNS_INTEL_ENABLED = "0";
process.env.ML_MODEL_PATH = path.join(__dirname, "missing-ml-model.json");
delete process.env.LLM_API_KEY;
delete process.env.GEOIP_API_URL;
resetMlModelCache();

const app = createApp();

function eml(overrides: { from?: string; to?: string; subject?: string; body?: string }): Buffer {
  return Buffer.from(
    [
      `From: ${overrides.from ?? "sender@example.com"}`,
      `To: ${overrides.to ?? "recipient@example.com"}`,
      `Subject: ${overrides.subject ?? "Test scan"}`,
      "",
      overrides.body ?? "This is a test body.",
      "",
    ].join("\r\n"),
    "utf-8"
  );
}

function phishingEml(): Buffer {
  return Buffer.from(
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
}

function cleanEml(): Buffer {
  return Buffer.from(
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
}

describe("Batch 5 email-centric API", { concurrency: false }, () => {
  before(() => {
    process.env.EMAIL_DATA_DIR = dataDir;
  });

  after(() => {
    delete process.env.EMAIL_DATA_DIR;
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("GET /emails returns an empty dataset with pagination", async () => {
    const res = await request(app).get("/api/v1/emails?limit=50&offset=0");
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      items: [],
      pagination: { total: 0, limit: 50, offset: 0 },
    });
  });

  it("scan → list → detail workflow; scan contract unchanged", async () => {
    const scan = await request(app)
      .post("/api/v1/emails/scan")
      .field("caseId", "CASE-004")
      .attach("file", phishingEml(), "phish.eml");

    assert.equal(scan.status, 201);
    assert.match(scan.body.emailId, /^EMAIL-/);
    assert.equal(scan.body.caseId, "CASE-004");
    assert.equal(scan.body.filename, "phish.eml");
    assert.equal(scan.body.status, "accepted");
    assert.equal(typeof scan.body.sha256, "string");
    assert.equal(scan.body.sha256.length, 64);
    assert.equal(typeof scan.body.fileSize, "number");
    assert.ok(Array.isArray(scan.body.warnings));

    const emailId = scan.body.emailId as string;

    const list = await request(app).get("/api/v1/emails");
    assert.equal(list.status, 200);
    const row = list.body.items.find((r: { emailId: string }) => r.emailId === emailId);
    assert.ok(row, "scanned email must appear in GET /emails immediately");
    assert.equal(row.caseId, "CASE-004");
    assert.equal(row.sender, "alert@paypa1-secure-login.com");
    assert.equal(row.senderDomain, "paypa1-secure-login.com");
    assert.equal(row.recipient, "victim@example.org");
    assert.equal(typeof row.threatScore, "number");
    assert.equal(typeof row.classification, "string");
    assert.ok(["low", "moderate", "high", "critical"].includes(row.status));
    assert.equal(row.riskLevel, row.status);
    assert.ok("date" in row);
    assert.ok("analysisStatus" in row);

    const heavy = [
      "headers",
      "body",
      "attachments",
      "parsedEmail",
      "email",
      "explanations",
      "iocs",
      "urlAnalysis",
      "domainAnalysis",
      "urlDomainAnalysis",
      "mlAssessment",
      "aiAssessment",
      "infrastructure",
      "authentication",
      "headerAnalysis",
      "warnings",
      "storagePath",
    ];
    for (const key of heavy) {
      assert.ok(!(key in row), `list row must not include ${key}`);
    }

    const detail = await request(app).get(`/api/v1/emails/${emailId}`);
    assert.equal(detail.status, 200);
    assert.equal(detail.body.emailId, emailId);
    assert.equal(detail.body.caseId, "CASE-004");
    assert.ok(detail.body.parsedEmail);
    assert.deepEqual(detail.body.email, detail.body.parsedEmail);
    assert.ok(detail.body.headerAnalysis);
    assert.deepEqual(detail.body.headers, detail.body.headerAnalysis);
    assert.ok(detail.body.authentication);
    assert.ok(detail.body.iocs);
    assert.ok(detail.body.urlAnalysis);
    assert.ok(detail.body.domainAnalysis);
    assert.ok(detail.body.urlDomainAnalysis);
    assert.deepEqual(detail.body.urlDomainAnalysis.urlAnalysis, detail.body.urlAnalysis);
    assert.deepEqual(detail.body.urlDomainAnalysis.domainAnalysis, detail.body.domainAnalysis);
    assert.ok(detail.body.risk);
    assert.ok(detail.body.mlAssessment);
    assert.ok(detail.body.aiAssessment);
    assert.ok(detail.body.infrastructure);
    assert.ok(Array.isArray(detail.body.explanations));
    assert.ok(Array.isArray(detail.body.warnings));
    assert.equal(detail.body.evidence.storagePath, undefined);
  });

  it("GET /emails/:emailId returns 404 EMAIL_NOT_FOUND for a missing id", async () => {
    const res = await request(app).get("/api/v1/emails/EMAIL-DOES-NOT-EXIST");
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, "EMAIL_NOT_FOUND");
    assert.ok(!JSON.stringify(res.body).includes(dataDir));
  });

  it("GET /emails/:emailId returns stored analysis and does not rewrite parsed.json", async () => {
    const scan = await request(app).post("/api/v1/emails/scan").attach("file", cleanEml(), "clean.eml");
    const emailId = scan.body.emailId as string;
    const parsedPath = path.join(dataDir, emailId, "parsed.json");
    const before = fs.statSync(parsedPath);
    const stored = JSON.parse(fs.readFileSync(parsedPath, "utf-8"));

    const first = await request(app).get(`/api/v1/emails/${emailId}`);
    const second = await request(app).get(`/api/v1/emails/${emailId}`);
    const after = fs.statSync(parsedPath);

    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(first.body.mlAssessment.status, stored.mlAssessment.status);
    assert.equal(first.body.aiAssessment.status, stored.aiAssessment.status);
    assert.equal(first.body.infrastructure.status, stored.infrastructure.status);
    assert.equal(second.body.mlAssessment.status, first.body.mlAssessment.status);
    assert.equal(second.body.aiAssessment.status, first.body.aiAssessment.status);
    assert.equal(after.mtimeMs, before.mtimeMs);
  });

  it("pagination splits a populated dataset", async () => {
    const a = await request(app)
      .post("/api/v1/emails/scan")
      .attach("file", eml({ subject: "page-a" }), "a.eml");
    const b = await request(app)
      .post("/api/v1/emails/scan")
      .attach("file", eml({ subject: "page-b" }), "b.eml");
    const c = await request(app)
      .post("/api/v1/emails/scan")
      .attach("file", eml({ subject: "page-c" }), "c.eml");

    const page1 = await request(app).get("/api/v1/emails?limit=2&offset=0");
    assert.equal(page1.status, 200);
    assert.equal(page1.body.items.length, 2);
    assert.ok(page1.body.pagination.total >= 3);
    assert.equal(page1.body.pagination.limit, 2);
    assert.equal(page1.body.pagination.offset, 0);

    const page2 = await request(app).get("/api/v1/emails?limit=2&offset=2");
    assert.equal(page2.status, 200);
    assert.ok(page2.body.items.length >= 1);
    assert.equal(page2.body.pagination.offset, 2);

    const ids = new Set(
      [...page1.body.items, ...page2.body.items].map((r: { emailId: string }) => r.emailId)
    );
    assert.ok(ids.has(a.body.emailId));
    assert.ok(ids.has(b.body.emailId));
    assert.ok(ids.has(c.body.emailId));
  });

  it("search covers sender, domain, subject, recipient, emailId, and caseId", async () => {
    const scan = await request(app)
      .post("/api/v1/emails/scan")
      .field("caseId", "CASE-SEARCH-99")
      .attach(
        "file",
        eml({
          from: "billing@paypal-alerts.example.com",
          to: "finance@corp.example",
          subject: "Invoice 42",
        }),
        "search.eml"
      );
    const emailId = scan.body.emailId as string;

    const bySender = await request(app).get("/api/v1/emails?search=paypal");
    assert.ok(bySender.body.items.some((r: { emailId: string }) => r.emailId === emailId));

    const byDomain = await request(app).get("/api/v1/emails?search=paypal-alerts.example.com");
    assert.ok(byDomain.body.items.some((r: { emailId: string }) => r.emailId === emailId));

    const bySubject = await request(app).get("/api/v1/emails?search=Invoice");
    assert.ok(bySubject.body.items.some((r: { emailId: string }) => r.emailId === emailId));

    const byRecipient = await request(app).get("/api/v1/emails?search=finance@corp.example");
    assert.ok(byRecipient.body.items.some((r: { emailId: string }) => r.emailId === emailId));

    const byId = await request(app).get(`/api/v1/emails?search=${encodeURIComponent(emailId)}`);
    assert.ok(byId.body.items.some((r: { emailId: string }) => r.emailId === emailId));

    const byCase = await request(app).get("/api/v1/emails?search=CASE-SEARCH-99");
    assert.ok(byCase.body.items.some((r: { emailId: string }) => r.emailId === emailId));
  });

  it("status, classification, caseId, and no-case filters", async () => {
    const withCase = await request(app)
      .post("/api/v1/emails/scan")
      .field("caseId", "CASE-004")
      .attach("file", phishingEml(), "phish-filter.eml");
    const noCase = await request(app)
      .post("/api/v1/emails/scan")
      .attach("file", cleanEml(), "clean-filter.eml");

    const phishId = withCase.body.emailId as string;
    const cleanId = noCase.body.emailId as string;

    const detailPhish = await request(app).get(`/api/v1/emails/${phishId}`);
    const detailClean = await request(app).get(`/api/v1/emails/${cleanId}`);
    const phishStatus = detailPhish.body.risk.level as string;
    const phishClass = detailPhish.body.risk.classification as string;
    const cleanStatus = detailClean.body.risk.level as string;

    const byStatus = await request(app).get(`/api/v1/emails?status=${phishStatus}`);
    assert.ok(byStatus.body.items.every((r: { status: string }) => r.status === phishStatus));
    assert.ok(byStatus.body.items.some((r: { emailId: string }) => r.emailId === phishId));

    const byClass = await request(app).get(
      `/api/v1/emails?classification=${encodeURIComponent(phishClass)}`
    );
    assert.ok(
      byClass.body.items.every(
        (r: { classification: string }) => r.classification.toLowerCase() === phishClass.toLowerCase()
      )
    );
    assert.ok(byClass.body.items.some((r: { emailId: string }) => r.emailId === phishId));

    const byCase = await request(app).get("/api/v1/emails?caseId=CASE-004");
    assert.ok(byCase.body.items.every((r: { caseId: string | null }) => r.caseId === "CASE-004"));
    assert.ok(byCase.body.items.some((r: { emailId: string }) => r.emailId === phishId));
    assert.ok(!byCase.body.items.some((r: { emailId: string }) => r.emailId === cleanId));

    const uncased = await request(app).get("/api/v1/emails?caseId=none");
    assert.ok(uncased.body.items.every((r: { caseId: string | null }) => r.caseId == null));
    assert.ok(uncased.body.items.some((r: { emailId: string }) => r.emailId === cleanId));
    assert.ok(!uncased.body.items.some((r: { emailId: string }) => r.emailId === phishId));

    const uncasedAlt = await request(app).get("/api/v1/emails?hasCase=false");
    assert.ok(uncasedAlt.body.items.every((r: { caseId: string | null }) => r.caseId == null));

    const stillThere = await request(app).get(`/api/v1/emails/${cleanId}`);
    assert.equal(stillThere.status, 200);
    assert.equal(stillThere.body.caseId, null);

    assert.ok(["low", "moderate", "high", "critical"].includes(cleanStatus));
  });

  it("sorting by threatScore and date is deterministic", async () => {
    const byScore = await request(app).get("/api/v1/emails?sort=threatScore");
    assert.equal(byScore.status, 200);
    const scores = byScore.body.items.map((r: { threatScore: number | null }) => r.threatScore ?? -1);
    for (let i = 1; i < scores.length; i++) {
      assert.ok(scores[i - 1] >= scores[i]);
    }
    const scoreIds = byScore.body.items.map((r: { emailId: string }) => r.emailId);
    const byScoreAgain = await request(app).get("/api/v1/emails?sort=threatScore");
    assert.deepEqual(
      byScoreAgain.body.items.map((r: { emailId: string }) => r.emailId),
      scoreIds
    );

    const byDate = await request(app).get("/api/v1/emails?sort=date");
    assert.equal(byDate.status, 200);
    const dates = byDate.body.items.map((r: { date: string; createdAt: string }) => r.date ?? r.createdAt);
    for (let i = 1; i < dates.length; i++) {
      assert.ok(dates[i - 1].localeCompare(dates[i]) >= 0);
    }
  });

  it("invalid pagination and filters return structured errors without paths", async () => {
    const pag = await request(app).get("/api/v1/emails?limit=-1");
    assert.equal(pag.status, 400);
    assert.equal(pag.body.error.code, "INVALID_PAGINATION");

    const pag2 = await request(app).get("/api/v1/emails?offset=nope");
    assert.equal(pag2.status, 400);
    assert.equal(pag2.body.error.code, "INVALID_PAGINATION");

    const filt = await request(app).get("/api/v1/emails?status=banana");
    assert.equal(filt.status, 400);
    assert.equal(filt.body.error.code, "INVALID_FILTER");

    const sort = await request(app).get("/api/v1/emails?sort=sender");
    assert.equal(sort.status, 400);
    assert.equal(sort.body.error.code, "INVALID_FILTER");

    const blob = JSON.stringify(pag.body) + JSON.stringify(filt.body);
    assert.ok(!blob.includes(dataDir));
    assert.ok(!blob.toLowerCase().includes("stack"));
  });

  it("GET /emails/:emailId/report returns a structured report now that Batch 6 has run", async () => {
    const scan = await request(app).post("/api/v1/emails/scan").attach("file", eml({}), "report.eml");
    const res = await request(app).get(`/api/v1/emails/${scan.body.emailId}/report`);
    assert.equal(res.status, 200);
    assert.equal(res.body.emailId, scan.body.emailId);
    assert.ok(res.body.caseInformation);
    assert.ok(res.body.evidenceIntegrity);
    assert.ok(Array.isArray(res.body.limitations));
    assert.ok(res.body.limitations.length >= 2);
  });
});
