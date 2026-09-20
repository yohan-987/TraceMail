import { test } from "node:test";
import assert from "node:assert/strict";
import { assessArchetype } from "../src/analyzers/archetypeAssessment";
import type { AuthenticationAnalysis, CategoryResult, RiskEvidenceItem } from "../src/schemas/types";

// Regression test for docs/audit/PHASE1-AUDIT.md, Finding 4.
//
// Before the fix, COMPROMISED_ACCOUNT fired off ANY content score above
// the moderate threshold, including one composed only of ordinary
// urgency/call-to-action marketing language — exactly what a legitimate
// promotional/anniversary email contains. It now additionally requires
// a high-severity content signal (credential- or financial-request
// language).

const cleanAuth: AuthenticationAnalysis = {
  emailId: "e",
  spf: { result: "pass", raw: null },
  dkim: { result: "pass", raw: null },
  dmarc: { result: "pass", policy: null, raw: null },
};

function categoryResult(score: number, evidence: RiskEvidenceItem[]): CategoryResult {
  return { score, status: "AVAILABLE", evidence };
}

function marketingEvidence(): RiskEvidenceItem[] {
  return [
    {
      type: "urgency_language",
      severity: "low",
      weight: 15,
      message: "urgency",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
    {
      type: "call_to_action_language",
      severity: "medium",
      weight: 15,
      message: "call to action",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
}

test("clean auth + ordinary marketing content (urgency/CTA only) does NOT classify as COMPROMISED_ACCOUNT", () => {
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(28, marketingEvidence()),
    infrastructureCategory: null,
    earliestOrigin: null,
  });

  assert.notEqual(result.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(result.archetype, "INCONCLUSIVE");
});

test("clean auth + credential-request language still classifies as COMPROMISED_ACCOUNT (no regression on real signal)", () => {
  const evidence: RiskEvidenceItem[] = [
    ...marketingEvidence(),
    {
      type: "credential_request_language",
      severity: "high",
      weight: 25,
      message: "credential request",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(45, evidence),
    infrastructureCategory: null,
    earliestOrigin: null,
  });

  assert.equal(result.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(result.compromiseTier, "POSSIBLE", "a single uncorroborated strong signal must stay at POSSIBLE, not LIKELY");
});

// --- Prompt 7: graduated confidence hierarchy regression tests ---

test("benign legitimate promotional sender (Genshin-style): no credential/financial-request language at all -> INCONCLUSIVE, no compromiseTier", () => {
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(28, marketingEvidence()),
    infrastructureCategory: categoryResult(0, []),
    earliestOrigin: null,
  });

  assert.equal(result.archetype, "INCONCLUSIVE");
  assert.equal(result.compromiseTier, undefined);
});

test("legitimate forwarding: forwarding is not an input to this function at all, so a forwarded legitimate email resolves identically to a non-forwarded one (INCONCLUSIVE)", () => {
  // assessArchetype's input type has no forwarding field by design —
  // this test documents that forwarding structurally cannot influence
  // this archetype, rather than merely asserting today's output.
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(28, marketingEvidence()),
    infrastructureCategory: null,
    earliestOrigin: null,
  });
  assert.equal(result.archetype, "INCONCLUSIVE");
});

test("suspicious content but clean infrastructure: one strong signal + explicitly clean infra -> POSSIBLE, not LIKELY", () => {
  const evidence: RiskEvidenceItem[] = [
    {
      type: "credential_request_language",
      severity: "high",
      weight: 25,
      message: "Message asks the recipient to confirm login credentials",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(30, evidence),
    infrastructureCategory: categoryResult(0, []), // clean/available, not just absent
    earliestOrigin: null,
  });

  assert.equal(result.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(result.compromiseTier, "POSSIBLE");
  assert.equal(result.confidence, "low");
});

test("strong compromise indicators (credential-request AND financial-request both present) -> LIKELY, corroborated", () => {
  const evidence: RiskEvidenceItem[] = [
    {
      type: "credential_request_language",
      severity: "high",
      weight: 25,
      message: "credential request",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
    {
      type: "financial_request_language",
      severity: "high",
      weight: 25,
      message: "financial request",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(50, evidence),
    infrastructureCategory: categoryResult(0, []),
    earliestOrigin: null,
  });

  assert.equal(result.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(result.compromiseTier, "LIKELY");
  assert.equal(result.confidence, "medium");
});

test("a grounded (strong) ML/AI content classification corroborates a single content-heuristic signal -> LIKELY", () => {
  const evidence: RiskEvidenceItem[] = [
    {
      type: "credential_request_language",
      severity: "high",
      weight: 25,
      message: "credential request",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
    {
      type: "ml_phishing_classification",
      severity: "high",
      weight: 30,
      message: "ML model classified as phishing with high confidence",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(50, evidence),
    infrastructureCategory: null,
    earliestOrigin: null,
  });

  assert.equal(result.compromiseTier, "LIKELY");
});

test("an UNGROUNDED (weak) AI semantic read does NOT corroborate -> stays POSSIBLE", () => {
  const evidence: RiskEvidenceItem[] = [
    {
      type: "credential_request_language",
      severity: "high",
      weight: 25,
      message: "credential request",
      evidence: {},
      category: "content",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
    {
      type: "ai_semantic_phishing",
      severity: "medium",
      weight: 15,
      message: "Semantic Content Assessment: stylistic concern only",
      evidence: {},
      category: "content",
      provenance: "AI_INTERPRETATION",
      strength: "weak",
    },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(40, evidence),
    infrastructureCategory: null,
    earliestOrigin: null,
  });

  assert.equal(result.compromiseTier, "POSSIBLE", "a weak/ungrounded AI read must not count as corroboration");
});

test("insufficient evidence (fewer than 2 categories available) -> INCONCLUSIVE with the insufficient-coverage basis", () => {
  const result = assessArchetype({
    authentication: null,
    urlDomainCategory: null,
    contentCategory: null,
    infrastructureCategory: null,
    earliestOrigin: null,
  });

  assert.equal(result.archetype, "INCONCLUSIVE");
  assert.equal(result.compromiseTier, undefined);
  assert.match(result.basis[0], /insufficient evidence coverage/i);
});

test("CONFIRMED compromise tier is never emitted, no matter how strong the input evidence is (no evidence source exists to support it)", () => {
  const evidence: RiskEvidenceItem[] = [
    { type: "credential_request_language", severity: "high", weight: 25, message: "x", evidence: {}, category: "content", provenance: "DETERMINISTIC_ANALYSIS" },
    { type: "financial_request_language", severity: "high", weight: 25, message: "x", evidence: {}, category: "content", provenance: "DETERMINISTIC_ANALYSIS" },
    { type: "ml_phishing_classification", severity: "high", weight: 30, message: "x", evidence: {}, category: "content", provenance: "DETERMINISTIC_ANALYSIS" },
  ];
  const result = assessArchetype({
    authentication: cleanAuth,
    urlDomainCategory: categoryResult(0, []),
    contentCategory: categoryResult(80, evidence),
    infrastructureCategory: categoryResult(0, []),
    earliestOrigin: null,
  });

  assert.notEqual(result.compromiseTier, "CONFIRMED");
  assert.equal(result.compromiseTier, "LIKELY", "the ceiling for this analyzer's evidence sources is LIKELY, never CONFIRMED");
});
