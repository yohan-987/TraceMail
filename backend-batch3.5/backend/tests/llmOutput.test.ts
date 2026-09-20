import { test } from "node:test";
import assert from "node:assert/strict";
import { llmSemanticSchema, aiContentScore, isGroundedConcern, parseLlmSemanticJson } from "../src/schemas/llmOutput";

function validOutput(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    phishingIntent: 0.1,
    credentialHarvesting: 0,
    financialFraud: 0,
    impersonation: 0.1,
    socialEngineering: 0.1,
    concernLevel: "low",
    topReasons: ["Marketing link structure — common in legitimate bulk email."],
    benignExplanation: "Promotional email with routine tracking links.",
    confidence: "medium",
    attackType: "None",
    summary: "Appears to be routine marketing email.",
    recommendedActions: [],
    ...overrides,
  };
}

test("schema accepts a well-formed Prompt 6 output (concernLevel/topReasons/benignExplanation/confidence present)", () => {
  const result = llmSemanticSchema.safeParse(validOutput());
  assert.equal(result.success, true);
});

test("schema rejects an invalid concernLevel", () => {
  const result = llmSemanticSchema.safeParse(validOutput({ concernLevel: "extreme" }));
  assert.equal(result.success, false);
});

test("schema rejects an invalid confidence value", () => {
  const result = llmSemanticSchema.safeParse(validOutput({ confidence: "certain" }));
  assert.equal(result.success, false);
});

test("schema accepts a null benignExplanation (no benign explanation applies)", () => {
  const result = llmSemanticSchema.safeParse(validOutput({ benignExplanation: null }));
  assert.equal(result.success, true);
});

test("schema rejects more than 5 topReasons (must be consolidated, not one per finding)", () => {
  const result = llmSemanticSchema.safeParse(validOutput({ topReasons: Array(6).fill("reason") }));
  assert.equal(result.success, false);
});

test("parseLlmSemanticJson handles a fenced ```json code block", () => {
  const raw = "```json\n" + JSON.stringify(validOutput()) + "\n```";
  const parsed = parseLlmSemanticJson(raw);
  assert.equal(parsed.concernLevel, "low");
});

// --- isGroundedConcern: the core Finding 8 / Prompt 6 fix ---

test("high phishingIntent/impersonation ALONE (no credential/financial claim) is NOT grounded — the exact false-positive pattern from the regression", () => {
  const output = llmSemanticSchema.parse(
    validOutput({
      phishingIntent: 0.8,
      impersonation: 0.7,
      socialEngineering: 0.6,
      credentialHarvesting: 0,
      financialFraud: 0,
      concernLevel: "high",
    })
  );
  assert.equal(
    isGroundedConcern(output),
    false,
    "stylistic suspicion (percent-encoding/subdomains/Message-ID mismatch inflating phishingIntent/impersonation) must not count as grounded"
  );
});

test("a real credential-harvesting claim IS grounded, even with modest other scores", () => {
  const output = llmSemanticSchema.parse(validOutput({ credentialHarvesting: 0.9, phishingIntent: 0.3 }));
  assert.equal(isGroundedConcern(output), true);
});

test("a real financial-fraud claim IS grounded", () => {
  const output = llmSemanticSchema.parse(validOutput({ financialFraud: 0.75 }));
  assert.equal(isGroundedConcern(output), true);
});

test("Prompt 11 fix: schema accepts a pre-Prompt-6-style output missing concernLevel/topReasons/benignExplanation/confidence entirely", () => {
  const preExisting = {
    phishingIntent: 0.1,
    credentialHarvesting: 0,
    financialFraud: 0,
    impersonation: 0.1,
    socialEngineering: 0.1,
    attackType: "None",
    summary: "Appears to be routine marketing email.",
    recommendedActions: [],
  };
  const result = llmSemanticSchema.safeParse(preExisting);
  assert.equal(
    result.success,
    true,
    "an older/partial LLM response missing the Prompt 6 qualitative fields must still validate -- discovered via a pre-existing test's mocked LLM response that predates Prompt 6"
  );
});

test("aiContentScore formula is unchanged by the Prompt 6 additions (0.3/0.2/0.2/0.2/0.1 weighted blend)", () => {
  const output = llmSemanticSchema.parse(
    validOutput({ phishingIntent: 1, credentialHarvesting: 1, financialFraud: 0, impersonation: 0, socialEngineering: 0 })
  );
  assert.equal(aiContentScore(output), 50); // 100 * (0.3*1 + 0.2*1) = 50
});
