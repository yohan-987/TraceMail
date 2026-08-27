import { test } from "node:test";
import assert from "node:assert/strict";
import { computeRisk } from "../src/analyzers/riskEngine";
import type { RiskComputationContext } from "../src/analyzers/riskEngine";
import type { RiskEvidenceItem } from "../src/schemas/types";

function evidence(overrides: Partial<RiskEvidenceItem>): RiskEvidenceItem {
  return {
    type: "test_type",
    severity: "medium",
    weight: 20,
    message: "test",
    evidence: {},
    category: "technical",
    provenance: "DETERMINISTIC_ANALYSIS",
    ...overrides,
  };
}

// Default context: every category available — matches the common case
// (a normal email with headers and at least one URL/domain).
const FULLY_AVAILABLE: RiskComputationContext = {
  headerDataAvailable: true,
  urlDomainApplicable: true,
  infrastructureAvailable: false, // still false — Batch 4 hasn't landed
};

// --- Basic scoring behavior (carried over from Batch 3, adapted to the new shape) ---

test("no evidence at all -> all available category scores 0, final score 0, level low, classification legitimate", () => {
  const risk = computeRisk("EMAIL-1", [], FULLY_AVAILABLE);
  assert.equal(risk.categoryScores?.technical.score, 0);
  assert.equal(risk.categoryScores?.identity.score, 0);
  assert.equal(risk.categoryScores?.urlDomain.score, 0);
  assert.equal(risk.categoryScores?.content.score, 0);
  assert.equal(risk.score, 0);
  assert.equal(risk.level, "low");
  assert.equal(risk.classification, "legitimate");
});

test("a single piece of evidence contributes exactly its own weight to its category", () => {
  const risk = computeRisk(
    "EMAIL-2",
    [evidence({ type: "spf_fail", category: "technical", weight: 25 })],
    FULLY_AVAILABLE
  );
  assert.equal(risk.categoryScores?.technical.score, 25);
  assert.equal(risk.categoryScores?.technical.status, "AVAILABLE");
});

test("CRITICAL: correlated SPF/DKIM/DMARC failures do NOT sum linearly (double-counting avoided)", () => {
  const risk = computeRisk(
    "EMAIL-3",
    [
      evidence({ type: "spf_fail", category: "technical", weight: 25 }),
      evidence({ type: "dkim_fail", category: "technical", weight: 25 }),
      evidence({ type: "dmarc_fail", category: "technical", weight: 30 }),
    ],
    FULLY_AVAILABLE
  );
  const naiveSum = 25 + 25 + 30; // = 80
  const technicalScore = risk.categoryScores?.technical.score ?? 0;
  assert.ok(
    technicalScore < naiveSum,
    `expected combined technical score below the naive sum of ${naiveSum}, got ${technicalScore}`
  );
  assert.ok(technicalScore > 50); // still strong evidence, just not inflated
});

test("combination is monotonic: adding more evidence never lowers the category score", () => {
  const oneSignal = computeRisk("EMAIL-4a", [evidence({ category: "technical", weight: 25 })], FULLY_AVAILABLE);
  const twoSignals = computeRisk(
    "EMAIL-4b",
    [evidence({ category: "technical", weight: 25 }), evidence({ category: "technical", weight: 10 })],
    FULLY_AVAILABLE
  );
  assert.ok((twoSignals.categoryScores?.technical.score ?? 0) >= (oneSignal.categoryScores?.technical.score ?? 0));
});

test("category score is always capped at 100 regardless of how much evidence piles up", () => {
  const manyStrongSignals = Array.from({ length: 6 }, () => evidence({ category: "identity", weight: 90 }));
  const risk = computeRisk("EMAIL-5", manyStrongSignals, FULLY_AVAILABLE);
  assert.ok((risk.categoryScores?.identity.score ?? 0) <= 100);
});

test("evidence in one category does not leak into another category's score", () => {
  const risk = computeRisk("EMAIL-6", [evidence({ category: "content", weight: 50 })], FULLY_AVAILABLE);
  assert.equal(risk.categoryScores?.technical.score, 0);
  assert.equal(risk.categoryScores?.identity.score, 0);
  assert.equal(risk.categoryScores?.urlDomain.score, 0);
  assert.equal(risk.categoryScores?.content.score, 50);
});

test("infrastructure category is UNAVAILABLE (not 0) since Batch 4 hasn't landed", () => {
  const risk = computeRisk(
    "EMAIL-7",
    [evidence({ category: "technical", weight: 25 }), evidence({ category: "identity", weight: 40 })],
    FULLY_AVAILABLE
  );
  assert.equal(risk.categoryScores?.infrastructure.status, "UNAVAILABLE");
  assert.equal(risk.categoryScores?.infrastructure.score, null);
});

test("every RiskAssessment carries its own emailId", () => {
  const risk = computeRisk("EMAIL-SPECIFIC", [], FULLY_AVAILABLE);
  assert.equal(risk.emailId, "EMAIL-SPECIFIC");
});

// --- Classification (unchanged logic, still reads the flat evidence list) ---

test("classification: impersonation when brand/authority impersonation evidence present", () => {
  const risk = computeRisk(
    "EMAIL-9",
    [
      evidence({ type: "display_name_brand_impersonation", category: "identity", weight: 30 }),
      evidence({ category: "technical", weight: 25 }),
    ],
    FULLY_AVAILABLE
  );
  assert.equal(risk.classification, "impersonation");
});

test("classification: phishing when look-alike domain or raw IP host present", () => {
  const risk = computeRisk(
    "EMAIL-10",
    [evidence({ type: "possible_lookalike_domain", category: "urlDomain", weight: 35 })],
    FULLY_AVAILABLE
  );
  assert.equal(risk.classification, "phishing");
});

test("classification: financial_fraud when financial + urgency language co-occur", () => {
  const risk = computeRisk(
    "EMAIL-11",
    [
      evidence({ type: "financial_request_language", category: "content", weight: 25 }),
      evidence({ type: "urgency_language", category: "content", weight: 15 }),
    ],
    FULLY_AVAILABLE
  );
  assert.equal(risk.classification, "financial_fraud");
});

test("confidence increases as more independent AVAILABLE categories corroborate the assessment", () => {
  const oneCategory = computeRisk("EMAIL-12a", [evidence({ category: "technical", weight: 50 })], FULLY_AVAILABLE);
  const threeCategories = computeRisk(
    "EMAIL-12b",
    [
      evidence({ category: "technical", weight: 50 }),
      evidence({ category: "identity", weight: 50 }),
      evidence({ category: "urlDomain", weight: 50 }),
    ],
    FULLY_AVAILABLE
  );
  assert.ok((threeCategories.confidence ?? 0) > (oneCategory.confidence ?? 0));
});

// --- Batch 3.5: NOT_APPLICABLE vs AVAILABLE ---------------------------

test("urlDomain is NOT_APPLICABLE (not AVAILABLE with score 0) when there are no URLs/domains to analyze", () => {
  const risk = computeRisk("EMAIL-13", [], { ...FULLY_AVAILABLE, urlDomainApplicable: false });
  assert.equal(risk.categoryScores?.urlDomain.status, "NOT_APPLICABLE");
  assert.equal(risk.categoryScores?.urlDomain.score, null);
});

test("NOT_APPLICABLE is distinct from AVAILABLE-with-zero-evidence: both score null vs 0 respectively", () => {
  const notApplicable = computeRisk("EMAIL-14a", [], { ...FULLY_AVAILABLE, urlDomainApplicable: false });
  const availableButClean = computeRisk("EMAIL-14b", [], { ...FULLY_AVAILABLE, urlDomainApplicable: true });
  assert.equal(notApplicable.categoryScores?.urlDomain.score, null);
  assert.equal(availableButClean.categoryScores?.urlDomain.score, 0);
  assert.notEqual(notApplicable.categoryScores?.urlDomain.status, availableButClean.categoryScores?.urlDomain.status);
});

// --- Batch 3.5: UNAVAILABLE vs low risk --------------------------------

test("UNAVAILABLE technical/identity (no headers at all) is distinct from AVAILABLE-and-clean", () => {
  const noHeaders = computeRisk("EMAIL-15", [], { ...FULLY_AVAILABLE, headerDataAvailable: false });
  assert.equal(noHeaders.categoryScores?.technical.status, "UNAVAILABLE");
  assert.equal(noHeaders.categoryScores?.technical.score, null);
  assert.equal(noHeaders.categoryScores?.identity.status, "UNAVAILABLE");
});

test("missing evidence is never silently treated as proof of safety: score stays null per-category, not 0", () => {
  const risk = computeRisk("EMAIL-16", [], {
    headerDataAvailable: false,
    urlDomainApplicable: false,
    infrastructureAvailable: false,
  });
  assert.equal(risk.categoryScores?.technical.score, null);
  assert.equal(risk.categoryScores?.identity.score, null);
  assert.equal(risk.categoryScores?.urlDomain.score, null);
  assert.equal(risk.categoryScores?.infrastructure.score, null);
  assert.equal(risk.categoryScores?.content.status, "AVAILABLE");
  assert.notEqual(risk.score, null);
});

test("score/level stay well-defined (not fabricated 0/low) even with only one category available", () => {
  const risk = computeRisk("EMAIL-17", [], {
    headerDataAvailable: false,
    urlDomainApplicable: false,
    infrastructureAvailable: false,
  });
  assert.equal(typeof risk.score, "number");
  assert.notEqual(risk.classification, "insufficient_evidence");
});

// --- Batch 3.5: score normalization across available categories -------

test("score normalizes across available categories: weight is redistributed, not zero-padded", () => {
  const risk = computeRisk(
    "EMAIL-18",
    [evidence({ category: "technical", weight: 100 }), evidence({ category: "identity", weight: 100 })],
    { headerDataAvailable: true, urlDomainApplicable: false, infrastructureAvailable: false }
  );
  // technical(100) + identity(100) + content(0, available) normalized
  // across weights .25+.20+.20=.65: (25+20+0)/0.65 = 69.2 -> 69
  assert.equal(risk.score, 69);
  // Confirm this is HIGHER than what a naive zero-padded average across
  // all 5 categories would give: (25+20+0+0+0)/1.0 = 45.
  assert.ok((risk.score ?? 0) > 45);
});

test("full coverage of the four already-implemented categories uses the standard fixed weights, redistributed since infrastructure isn't available yet", () => {
  const risk = computeRisk("EMAIL-19", [evidence({ category: "technical", weight: 100 })], FULLY_AVAILABLE);
  // technical=100, identity/urlDomain/content AVAILABLE-and-0,
  // infrastructure UNAVAILABLE (excluded). Weighted sum = 0.25*100 = 25,
  // total available weight = .25+.20+.20+.20 = .85 -> 25/0.85 = 29.4 -> 29.
  // (Batch 3's old behavior — dividing by a fixed 1.0 that silently
  // included an always-zero infrastructure slot — is exactly the
  // dilution this batch fixes.)
  assert.equal(risk.score, 29);
});

// --- Batch 3.5: evidenceCoverage ---------------------------------------

test("evidenceCoverage reflects infrastructure always being unavailable pre-Batch-4: 4 of 5", () => {
  const risk = computeRisk("EMAIL-20", [], FULLY_AVAILABLE);
  assert.equal(risk.evidenceCoverage, 0.8);
});

test("evidenceCoverage decreases as fewer categories are available", () => {
  const full = computeRisk("EMAIL-21a", [], FULLY_AVAILABLE);
  const partial = computeRisk("EMAIL-21b", [], { ...FULLY_AVAILABLE, urlDomainApplicable: false });
  assert.ok((partial.evidenceCoverage ?? 0) < (full.evidenceCoverage ?? 0));
});

test("evidenceCoverage reflects exactly the fraction of AVAILABLE categories out of five", () => {
  // technical+identity unavailable, urlDomain not applicable, content
  // available, infrastructure unavailable -> only 1 of 5 available.
  const risk = computeRisk("EMAIL-22", [], {
    headerDataAvailable: false,
    urlDomainApplicable: false,
    infrastructureAvailable: false,
  });
  assert.equal(risk.evidenceCoverage, 0.2);
});

// --- Batch 3.5: provenance ----------------------------------------------

test("evidence items retain their provenance through category results", () => {
  const risk = computeRisk(
    "EMAIL-23",
    [evidence({ category: "technical", weight: 25, provenance: "DETERMINISTIC_ANALYSIS" })],
    FULLY_AVAILABLE
  );
  const technicalEvidence = risk.categoryScores?.technical.evidence ?? [];
  assert.equal(technicalEvidence.length, 1);
  assert.equal(technicalEvidence[0].provenance, "DETERMINISTIC_ANALYSIS");
});

test("category evidence array is preserved even when the category is unavailable", () => {
  const risk = computeRisk("EMAIL-24", [evidence({ category: "technical", weight: 25 })], {
    ...FULLY_AVAILABLE,
    headerDataAvailable: false,
  });
  assert.equal(risk.categoryScores?.technical.status, "UNAVAILABLE");
  assert.equal(risk.categoryScores?.technical.evidence.length, 1);
  assert.equal(risk.categoryScores?.technical.score, null);
});
