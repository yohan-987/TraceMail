import { test } from "node:test";
import assert from "node:assert/strict";
import { mapApiEmailToUiEmail } from "../src/api/emailMapper";

// Regression tests for docs/audit/PHASE1-AUDIT.md, Finding 7.
//
// Root cause: mapApiEmailToUiEmail() derived the UI's 4-value status
// (safe/suspicious/malicious/inconclusive) from a hand-matched set of
// level-like strings that never covered the backend's "moderate" band
// and never consulted the backend's actual `classification` field at
// all. Any level other than "critical"/"high" silently fell through to
// the hardcoded default of 'safe' — so the reported regression (score
// 32, level MODERATE, classification SUSPICIOUS) rendered as "Safe" on
// the Overview tab. No frontend test suite existed for this file
// before this fix; this file establishes one, mirroring the backend's
// `node:test` + tsx convention (backend-batch3.5/backend/tests/).
//
// NOTE ON SCOPE: emailMapper.ts has zero runtime dependencies of its
// own (its only imports are `import type`, fully erased by tsx), so
// these tests run it directly without a bundler, jsdom, or React.

test("the exact reported regression: score 32 / level MODERATE / classification SUSPICIOUS is NOT 'safe'", () => {
  const ui = mapApiEmailToUiEmail({
    emailId: "e1",
    sender: "promo@brand-example.com",
    subject: "Sale",
    recipient: "user@example.com",
    date: "2026-01-01",
    threatScore: 32,
    classification: "suspicious",
    riskLevel: "moderate",
    status: "moderate",
  } as any);

  assert.notEqual(ui.status, "safe", "the historical bug: MODERATE/SUSPICIOUS silently became 'safe'");
  assert.equal(ui.status, "suspicious");
});

test("moderate score + classification legitimate (Finding 2's weak-evidence case) maps to safe", () => {
  const ui = mapApiEmailToUiEmail({
    emailId: "e2",
    threatScore: 28,
    classification: "legitimate",
    riskLevel: "moderate",
  } as any);

  assert.equal(
    ui.status,
    "safe",
    "a moderate-scoring email that the backend correctly classifies as legitimate (Finding 2) must still show as safe"
  );
});

test("each malicious-tier classification maps to 'malicious'", () => {
  for (const classification of ["phishing", "impersonation", "financial_fraud", "suspicious_authentication"]) {
    const ui = mapApiEmailToUiEmail({
      emailId: "e3",
      threatScore: 80,
      classification,
      riskLevel: "critical",
    } as any);
    assert.equal(ui.status, "malicious", `expected 'malicious' for classification="${classification}"`);
  }
});

test("a genuinely missing risk assessment (no score, no classification) maps to 'inconclusive', not 'safe'", () => {
  const ui = mapApiEmailToUiEmail({
    emailId: "e4",
    risk: { score: null, level: null, classification: null },
  } as any);

  assert.equal(ui.status, "inconclusive");
});

test("low score + legitimate classification maps to safe (baseline sanity check)", () => {
  const ui = mapApiEmailToUiEmail({
    emailId: "e5",
    threatScore: 5,
    classification: "legitimate",
    riskLevel: "low",
  } as any);
  assert.equal(ui.status, "safe");
});

test("Prompt 2 requirement: list-summary shape and detail shape produce the IDENTICAL status for the same underlying risk", () => {
  // Flat ApiEmailSummary shape (GET /api/v1/emails list rows).
  const fromSummary = mapApiEmailToUiEmail({
    emailId: "e6",
    threatScore: 32,
    classification: "suspicious",
    riskLevel: "moderate",
  } as any);

  // Nested ApiEmailDetail shape (GET /api/v1/emails/:emailId).
  const fromDetail = mapApiEmailToUiEmail({
    emailId: "e6",
    risk: { score: 32, level: "moderate", classification: "suspicious" },
  } as any);

  assert.equal(fromSummary.status, fromDetail.status);
  assert.equal(fromSummary.status, "suspicious");
});
