import { test } from "node:test";
import assert from "node:assert/strict";
import { computeRisk, type RiskComputationContext } from "../src/analyzers/riskEngine";
import type { RiskEvidenceItem } from "../src/schemas/types";

// Regression test for docs/audit/PHASE1-AUDIT.md, Finding 2.
//
// Before the fix, classify() defaulted ANY non-"low" score straight to
// "suspicious" regardless of whether the contributing evidence was
// actually strong. This reproduces the real-world regression: a pile
// of purely weak/structural evidence (percent-encoded tracking links
// across several hosts, ordinary marketing urgency/CTA language, a
// Message-ID/From domain mismatch) that crosses into the "moderate"
// score band on volume alone, with no genuinely suspicious evidence
// type present anywhere.

function weakEvidenceOnly(): RiskEvidenceItem[] {
  const evidence: RiskEvidenceItem[] = [];
  // 10 distinct hosts each tripping the (weak) structural check —
  // urlDomain noisy-OR of ten weight-15 items ~= 80, but every item is
  // tagged strength: "weak" so computeCategoryResult's weak-only
  // ceiling (Finding 3) caps the category at 40, not 80.
  for (let i = 0; i < 10; i++) {
    evidence.push({
      type: "suspicious_structure",
      severity: "medium",
      weight: 15,
      message: `link ${i} has a suspicious structure`,
      evidence: {},
      category: "urlDomain",
      provenance: "DETERMINISTIC_ANALYSIS",
      strength: "weak",
    });
  }
  // Ordinary marketing language (weak) — content noisy-OR of 15,15 ~= 28
  // (below the 40 ceiling, so unaffected by it either way).
  evidence.push({
    type: "urgency_language",
    severity: "low",
    weight: 15,
    message: "urgency language",
    evidence: {},
    category: "content",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  evidence.push({
    type: "call_to_action_language",
    severity: "medium",
    weight: 15,
    message: "call to action language",
    evidence: {},
    category: "content",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  // Message-ID/From mismatch + Return-Path mismatch + missing Message-ID
  // (all weak) — identity noisy-OR of 10,20,5 ~= 32, under the ceiling.
  evidence.push({
    type: "message_id_domain_mismatch",
    severity: "low",
    weight: 10,
    message: "message id mismatch",
    evidence: {},
    category: "identity",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  evidence.push({
    type: "return_path_mismatch",
    severity: "low",
    weight: 20,
    message: "return path mismatch",
    evidence: {},
    category: "identity",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  evidence.push({
    type: "message_id_missing",
    severity: "low",
    weight: 5,
    message: "message id missing",
    evidence: {},
    category: "identity",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  // SPF soft-fail (weak) — technical = 10, under the ceiling.
  evidence.push({
    type: "spf_softfail",
    severity: "medium",
    weight: 10,
    message: "spf softfail",
    evidence: {},
    category: "technical",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "weak",
  });
  return evidence;
}

const context: RiskComputationContext = {
  headerDataAvailable: true,
  urlDomainApplicable: true,
  infrastructureAvailable: false,
};

test("a score in the moderate band composed ONLY of weak evidence classifies as legitimate, not suspicious", () => {
  const evidence = weakEvidenceOnly();
  const risk = computeRisk("email-weak", evidence, context);

  assert.equal(risk.level, "moderate", `test setup should land in the moderate band, got score=${risk.score}`);
  assert.equal(
    risk.classification,
    "legitimate",
    `expected "legitimate" for weak-only evidence at a moderate score, got "${risk.classification}"`
  );
});

test("Finding 3: a category composed only of weak evidence is capped at the weak-only ceiling (40), regardless of how much weak evidence piles up", () => {
  const evidence = weakEvidenceOnly();
  const risk = computeRisk("email-weak-ceiling", evidence, context);

  const urlDomainScore = risk.categoryScores?.urlDomain.score ?? null;
  assert.ok(urlDomainScore !== null);
  assert.ok(
    (urlDomainScore as number) <= 40,
    `urlDomain category (10 weak suspicious_structure items) should be capped at 40, got ${urlDomainScore}`
  );
});

test("a moderate score with at least one real (non-weak) signal still classifies as suspicious", () => {
  const evidence = weakEvidenceOnly();
  evidence.push({
    type: "reply_to_mismatch",
    severity: "medium",
    weight: 40,
    message: "Reply-To domain differs from sender domain",
    evidence: {},
    category: "identity",
    provenance: "DETERMINISTIC_ANALYSIS",
    strength: "strong",
  });

  const risk = computeRisk("email-real-signal", evidence, context);
  assert.equal(
    risk.classification,
    "suspicious",
    `expected "suspicious" once a real (non-weak) signal is present, got "${risk.classification}"`
  );

  // The identity category now contains a strong item, so its own
  // weak-only ceiling no longer applies -- it should combine well
  // above 40, unlike the weak-only test above.
  const identityScore = risk.categoryScores?.identity.score ?? null;
  assert.ok(identityScore !== null);
  assert.ok(
    (identityScore as number) > 40,
    `identity category with one strong signal should NOT be capped at 40, got ${identityScore}`
  );
});

test("no regression: a lookalike domain still classifies as phishing regardless of the weak-evidence fix", () => {
  const evidence: RiskEvidenceItem[] = [
    {
      type: "possible_lookalike_domain",
      severity: "high",
      weight: 35,
      message: "lookalike domain",
      evidence: {},
      category: "urlDomain",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
  const risk = computeRisk("email-lookalike", evidence, context);
  assert.equal(risk.classification, "phishing");
});
