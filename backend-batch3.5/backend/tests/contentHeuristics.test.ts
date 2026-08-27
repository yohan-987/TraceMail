import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeContent } from "../src/analyzers/contentHeuristics";
import type { ParsedEmail } from "../src/schemas/types";

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "EMAIL-TEST-CONTENT",
    subject: "",
    from: [],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: null,
    headers: { normalized: {}, raw: [] },
    body: { text: "", html: null },
    attachments: [],
    ...overrides,
  };
}

test("detects urgency language", () => {
  const parsed = baseParsedEmail({ body: { text: "This is urgent, please act immediately.", html: null } });
  const { featureCounts, evidence } = analyzeContent(parsed);
  assert.ok(featureCounts.urgency > 0);
  assert.ok(evidence.find((e) => e.type === "urgency_language"));
});

test("detects credential-request language with high severity", () => {
  const parsed = baseParsedEmail({ body: { text: "Please verify your account by logging in.", html: null } });
  const { evidence } = analyzeContent(parsed);
  const anomaly = evidence.find((e) => e.type === "credential_request_language");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "high");
});

test("detects financial-request language", () => {
  const parsed = baseParsedEmail({ body: { text: "Please process this payment via wire transfer.", html: null } });
  const { evidence } = analyzeContent(parsed);
  assert.ok(evidence.find((e) => e.type === "financial_request_language"));
});

test("detects call-to-action language", () => {
  const parsed = baseParsedEmail({ body: { text: "Click here to continue.", html: null } });
  const { evidence } = analyzeContent(parsed);
  assert.ok(evidence.find((e) => e.type === "call_to_action_language"));
});

test("produces no evidence for neutral content", () => {
  const parsed = baseParsedEmail({ body: { text: "Here is the weekly team meeting summary.", html: null } });
  const { evidence } = analyzeContent(parsed);
  assert.equal(evidence.length, 0);
});

test("counts distinct matched keywords, not raw repetitions, per category", () => {
  const parsed = baseParsedEmail({
    body: { text: "urgent urgent urgent, act now, this is time sensitive", html: null },
  });
  const { featureCounts, evidence } = analyzeContent(parsed);
  // 3 distinct urgency keywords matched ("urgent", "act now", "time sensitive"),
  // not a raw occurrence count, and still exactly one evidence item.
  assert.equal(featureCounts.urgency, 3);
  assert.equal(evidence.filter((e) => e.type === "urgency_language").length, 1);
});

test("also scans the subject line and HTML body", () => {
  const subjectOnly = baseParsedEmail({ subject: "URGENT: verify your account now" });
  const { evidence: subjEvidence } = analyzeContent(subjectOnly);
  assert.ok(subjEvidence.length > 0);

  const htmlOnly = baseParsedEmail({ body: { text: null, html: "<p>wire transfer required</p>" } });
  const { evidence: htmlEvidence } = analyzeContent(htmlOnly);
  assert.ok(htmlEvidence.find((e) => e.type === "financial_request_language"));
});
